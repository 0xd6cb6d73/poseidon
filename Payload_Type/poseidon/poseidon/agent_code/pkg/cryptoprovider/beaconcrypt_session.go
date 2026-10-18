//go:build beaconcrypt && (linux || darwin) && (amd64 || arm64)

package cryptoprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

type beaconcryptClient interface {
	GenerateRegistration() ([]byte, error)
	ProcessInitialMessage([]byte) ([]byte, error)
	EncryptToServer([]byte) ([]byte, error)
	DecryptServerMessage([]byte) ([]byte, error)
	Close()
}

type beaconcryptPendingExchange struct {
	plaintext, frame []byte
	route            string
	push             bool
	announcement     bool
}

// beaconcryptSession owns a native client and serializes complete exchanges,
// including transport retries, rather than just individual FFI calls.
// Native failures are terminal: the agent cannot safely guess ratchet state.
type beaconcryptSession struct {
	mu                         sync.Mutex
	client                     beaconcryptClient
	payload, sessionID, stage  string
	callback                   string
	registration, checkinReply []byte
	pending                    *beaconcryptPendingExchange
	failed                     error
}

var _ Session = (*beaconcryptSession)(nil)

func newBeaconcryptSession(native beaconcryptClient, payloadUUID string) (*beaconcryptSession, error) {
	registration, err := native.GenerateRegistration()
	if err != nil {
		native.Close()
		return nil, fmt.Errorf("generate registration: %w", err)
	}
	sessionID := uuid.NewString()
	body, err := json.Marshal(struct {
		Action    string `json:"action"`
		SessionID string `json:"session_id"`
		Data      []byte `json:"data"`
	}{"staging", sessionID, registration})
	if err != nil {
		native.Close()
		return nil, err
	}
	return &beaconcryptSession{client: native, payload: payloadUUID, sessionID: sessionID, registration: encodeFrame(payloadUUID, body)}, nil
}

// Register authenticates Mythic's proposed staging UUID and session identity
// using the library's authenticated initial message before accepting either.
func (s *beaconcryptSession) Register(send RoundTrip) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return s.failed
	}
	if s.stage != "" {
		return nil
	}
	reply, err := send(s.registration)
	if err != nil {
		return err
	}
	body, err := decodeFrame(reply, s.payload)
	if err != nil {
		return err
	}
	var outer struct {
		Action    string `json:"action"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
		Data      []byte `json:"data"`
	}
	if err = json.Unmarshal(body, &outer); err != nil || outer.Action != "staging" || outer.SessionID != s.sessionID || !canonicalUUID(outer.UUID) || len(outer.Data) == 0 {
		return errors.New("invalid staging response")
	}
	authenticated, err := s.client.ProcessInitialMessage(outer.Data)
	if err != nil {
		return s.fail(fmt.Errorf("authenticate staging response: %w", err))
	}
	var claims struct {
		Action    string `json:"action"`
		Status    string `json:"status"`
		UUID      string `json:"uuid"`
		SessionID string `json:"session_id"`
	}
	if err = json.Unmarshal(authenticated, &claims); err != nil || claims.Action != "staging" || claims.Status != "success" || claims.UUID != outer.UUID || claims.SessionID != s.sessionID {
		return s.fail(errors.New("authenticated staging claims differ from response"))
	}
	s.stage = claims.UUID
	s.registration = nil
	return nil
}

// CheckIn caches the first authenticated check-in result. Transport failures
// retain the original ciphertext and original check-in rather than encrypting
// a new host snapshot with an advanced client ratchet.
func (s *beaconcryptSession) CheckIn(plaintext []byte, send RoundTrip) ([]byte, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, "", s.failed
	}
	if s.callback != "" {
		return append([]byte(nil), s.checkinReply...), s.callback, nil
	}
	if s.stage == "" {
		return nil, "", errors.New("registration is incomplete")
	}
	if s.pending != nil {
		plaintext = s.pending.plaintext
	}
	reply, err := s.exchange(plaintext, s.stage, send)
	if err != nil {
		return nil, "", err
	}
	var claims struct {
		Action string `json:"action"`
		Status string `json:"status"`
		ID     string `json:"id"`
	}
	if err = json.Unmarshal(reply, &claims); err != nil || claims.Action != "checkin" || claims.Status != "success" || !canonicalUUID(claims.ID) {
		return nil, "", s.fail(errors.New("invalid authenticated check-in response"))
	}
	s.callback, s.checkinReply = claims.ID, append([]byte(nil), reply...)
	return reply, s.callback, nil
}

// Exchange encrypts an application message once and authenticates its reply.
// If transport returns an error, retry with the same plaintext. A different
// message cannot replace an outstanding request whose server outcome is unknown.
func (s *beaconcryptSession) Exchange(plaintext []byte, send RoundTrip) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, s.failed
	}
	if s.callback == "" {
		return nil, errors.New("check-in is incomplete")
	}
	return s.exchange(plaintext, s.callback, send)
}

func (s *beaconcryptSession) exchange(plaintext []byte, route string, send RoundTrip) ([]byte, error) {
	if s.pending == nil {
		ciphertext, err := s.client.EncryptToServer(plaintext)
		if err != nil {
			return nil, s.fail(fmt.Errorf("encrypt request: %w", err))
		}
		s.pending = &beaconcryptPendingExchange{plaintext: append([]byte(nil), plaintext...), frame: encodeFrame(route, ciphertext), route: route}
	} else if s.pending.push || s.pending.route != route || !bytes.Equal(s.pending.plaintext, plaintext) {
		return nil, errors.New("a different message is still awaiting its authenticated response")
	}
	reply, err := send(s.pending.frame)
	if err != nil {
		return nil, err
	}
	ciphertext, err := decodeFrame(reply, route)
	if err != nil {
		return nil, err
	}
	body, err := s.client.DecryptServerMessage(ciphertext)
	if err != nil {
		return nil, s.fail(fmt.Errorf("authenticate response: %w", err))
	}
	s.pending = nil
	return body, nil
}

// SendPush sends an application message on an ordered push transport. The
// transport must finish writing this frame before sending another and close the
// connection on a partial write. A failed write retains the exact ciphertext for
// retry after reconnection; a successful write does not wait for an application
// reply, because Mythic can also deliver unsolicited task messages.
func (s *beaconcryptSession) SendPush(plaintext []byte, send func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sendPush(plaintext, send, false)
}

// StartPush announces the callback on a newly connected push stream when no
// earlier write is awaiting delivery. The caller must resume that earlier write
// instead when one exists, so the relay learns the route from its exact frame.
func (s *beaconcryptSession) StartPush(plaintext []byte, send func([]byte) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && s.pending.push && !s.pending.announcement {
		return s.failed
	}
	return s.sendPush(plaintext, send, true)
}

func (s *beaconcryptSession) sendPush(plaintext []byte, send func([]byte) error, announcement bool) error {
	if s.failed != nil {
		return s.failed
	}
	if s.callback == "" {
		return errors.New("check-in is incomplete")
	}
	if s.pending == nil {
		ciphertext, err := s.client.EncryptToServer(plaintext)
		if err != nil {
			return s.fail(fmt.Errorf("encrypt push message: %w", err))
		}
		s.pending = &beaconcryptPendingExchange{plaintext: append([]byte(nil), plaintext...), frame: encodeFrame(s.callback, ciphertext), route: s.callback, push: true, announcement: announcement}
	} else if !s.pending.push || s.pending.announcement != announcement || s.pending.route != s.callback || !bytes.Equal(s.pending.plaintext, plaintext) {
		return errors.New("a different message is still awaiting transport delivery")
	}
	if err := send(s.pending.frame); err != nil {
		return err
	}
	s.pending = nil
	return nil
}

// ReceivePush authenticates one ordered server message, including unsolicited
// task messages. The frame's route is checked before native state is touched.
func (s *beaconcryptSession) ReceivePush(frame []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, s.failed
	}
	if s.callback == "" {
		return nil, errors.New("check-in is incomplete")
	}
	ciphertext, err := decodeFrame(frame, s.callback)
	if err != nil {
		return nil, err
	}
	body, err := s.client.DecryptServerMessage(ciphertext)
	if err != nil {
		return nil, s.fail(fmt.Errorf("authenticate push message: %w", err))
	}
	return body, nil
}

// Resume finishes an outstanding application exchange before the caller removes
// another message from its outbound queue. It returns nil when none is pending.
// This permits an explicitly stopped profile to restart without replacing an
// ambiguously delivered request or dropping newly collected task responses.
func (s *beaconcryptSession) Resume(send RoundTrip) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed != nil {
		return nil, s.failed
	}
	if s.pending == nil {
		return nil, nil
	}
	if s.callback == "" || s.pending.route != s.callback || s.pending.push {
		return nil, errors.New("check-in is incomplete")
	}
	return s.exchange(s.pending.plaintext, s.pending.route, send)
}

// Failed reports a terminal cryptographic/protocol failure.
func (s *beaconcryptSession) Failed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed != nil
}

func (s *beaconcryptSession) fail(err error) error {
	s.failed = err
	s.client.Close()
	return err
}

func (s *beaconcryptSession) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failed == nil {
		s.fail(errors.New("provider session is closed"))
	}
}

func encodeFrame(route string, body []byte) []byte {
	return []byte(base64.StdEncoding.EncodeToString(append([]byte(route), body...)))
}

func decodeFrame(frame []byte, route string) ([]byte, error) {
	body, err := base64.StdEncoding.DecodeString(string(frame))
	if err != nil || len(body) <= 36 || string(body[:36]) != route {
		return nil, errors.New("invalid response frame or route UUID")
	}
	return body[36:], nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
