//go:build beaconcrypt && (linux || darwin) && (amd64 || arm64)

package cryptoprovider

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
	"github.com/google/uuid"
)

// This is a native-library component test. The separate integration harness
// exercises the same agent in a real Mythic/provider deployment.
func TestNativeClientRegistrationAndLostResponseRetry(t *testing.T) {
	server, err := beaconcrypt.NewServer(77)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	publicKey, err := server.IdentityPK()
	if err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(beaconcryptMaterial{Version: 1, ServerKID: "77", ServerPublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	payload, stage, callback := uuid.NewString(), uuid.NewString(), uuid.NewString()
	session, err := New("beaconcrypt", base64.StdEncoding.EncodeToString(config), payload)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	cache := make(map[string][]byte)
	var registered bool
	var keyID uint64
	decryptions := 0
	serverRoundTrip := func(frame []byte) ([]byte, error) {
		if reply, ok := cache[string(frame)]; ok {
			return reply, nil
		}
		raw, err := base64.StdEncoding.DecodeString(string(frame))
		if err != nil || len(raw) <= 36 {
			t.Fatalf("invalid client frame: %v", err)
		}
		route, body := string(raw[:36]), raw[36:]
		var response []byte
		if !registered {
			if route != payload {
				t.Fatal("registration was not routed to payload")
			}
			var request struct {
				Action, SessionID string
				Data              []byte
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			_ = json.Unmarshal(fields["action"], &request.Action)
			_ = json.Unmarshal(fields["session_id"], &request.SessionID)
			_ = json.Unmarshal(fields["data"], &request.Data)
			if request.Action != "staging" || request.SessionID == "" {
				t.Fatal("invalid staging message")
			}
			claims, _ := json.Marshal(map[string]string{"action": "staging", "status": "success", "uuid": stage, "session_id": request.SessionID})
			registration, err := server.RegisterBeacon(request.Data, claims)
			if err != nil {
				t.Fatal(err)
			}
			outer, _ := json.Marshal(map[string]interface{}{"action": "staging", "uuid": stage, "session_id": request.SessionID, "data": registration.Serialized})
			response = encodeFrame(payload, outer)
			registered = true
			keyID = registration.KeyID
		} else {
			opened, err := server.DecryptAndUpdate(body)
			if err != nil {
				t.Fatal(err)
			}
			decryptions++
			plaintext := opened.Data
			if route == stage {
				plaintext = []byte(`{"action":"checkin","status":"success","id":"` + callback + `"}`)
			} else if route != callback {
				t.Fatal("application message used unauthenticated callback UUID")
			}
			sealed, err := server.EncryptAndUpdate(opened.KeyID, plaintext)
			if err != nil {
				t.Fatal(err)
			}
			response = encodeFrame(route, sealed.Data)
		}
		cache[string(frame)] = response
		return response, nil
	}
	if err := session.Register(serverRoundTrip); err != nil {
		t.Fatal(err)
	}
	if _, id, err := session.CheckIn([]byte(`{"action":"checkin"}`), serverRoundTrip); err != nil || id != callback {
		t.Fatalf("native checkin failed: %v", err)
	}
	plaintext := bytes.Repeat([]byte{0, 255, 128, '\n', '{', '}'}, 12000)
	var lostFrame []byte
	if _, err := session.Exchange(plaintext, func(frame []byte) ([]byte, error) {
		lostFrame = append([]byte(nil), frame...)
		if _, err := serverRoundTrip(frame); err != nil {
			return nil, err
		}
		return nil, errors.New("reply dropped after server committed")
	}); err == nil {
		t.Fatal("lost response was ignored")
	}
	reply, err := session.Exchange(plaintext, func(frame []byte) ([]byte, error) {
		if !bytes.Equal(frame, lostFrame) {
			t.Fatal("native ciphertext changed after lost response")
		}
		return serverRoundTrip(frame)
	})
	if err != nil || !bytes.Equal(reply, plaintext) || decryptions != 2 {
		t.Fatalf("native retry lost bytes or replayed decrypt: count=%d err=%v", decryptions, err)
	}
	if _, err := session.Exchange([]byte("subsequent live message"), serverRoundTrip); err != nil {
		t.Fatalf("native ratchets diverged after retry: %v", err)
	}
	// TCP children receive task pushes independently of outbound messages.
	for round := range 3 {
		tasks := []byte(fmt.Sprintf("unsolicited task %d", round))
		sealed, err := server.EncryptAndUpdate(keyID, tasks)
		if err != nil {
			t.Fatal(err)
		}
		body, err := session.ReceivePush(encodeFrame(callback, sealed.Data))
		if err != nil || !bytes.Equal(body, tasks) {
			t.Fatalf("native task push failed: %v", err)
		}
		output := []byte(fmt.Sprintf("task output %d", round))
		var reply []byte
		if err := session.SendPush(output, func(frame []byte) error {
			var err error
			reply, err = serverRoundTrip(frame)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		body, err = session.ReceivePush(reply)
		if err != nil || !bytes.Equal(body, output) {
			t.Fatalf("native push output reply failed: %v", err)
		}
	}

}
