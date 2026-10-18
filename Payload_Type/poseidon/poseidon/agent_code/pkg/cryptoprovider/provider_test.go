package cryptoprovider

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// These providers deliberately use neither Beaconcrypt configuration nor its
// framing. Their common lifecycle stub leaves only the operations exercised by
// each distinct implementation below.
type testSession struct{}

var errTestUnsupported = errors.New("unsupported test operation")

func (*testSession) Register(RoundTrip) error { return errTestUnsupported }
func (*testSession) CheckIn([]byte, RoundTrip) ([]byte, string, error) {
	return nil, "", errTestUnsupported
}
func (*testSession) Exchange([]byte, RoundTrip) ([]byte, error) {
	return nil, errTestUnsupported
}
func (*testSession) Resume(RoundTrip) ([]byte, error) { return nil, errTestUnsupported }
func (*testSession) SendPush([]byte, func([]byte) error) error {
	return errTestUnsupported
}
func (*testSession) StartPush([]byte, func([]byte) error) error {
	return errTestUnsupported
}
func (*testSession) ReceivePush([]byte) ([]byte, error) { return nil, errTestUnsupported }
func (*testSession) Failed() bool                       { return false }
func (*testSession) Close()                             {}

type testEchoSession struct {
	testSession
	config, payload string
}

func (s *testEchoSession) Exchange(body []byte, send RoundTrip) ([]byte, error) {
	return send(append([]byte(s.config+"|"+s.payload+"|"), body...))
}

type testPushSession struct {
	testSession
	config, payload string
}

func (s *testPushSession) SendPush(body []byte, send func([]byte) error) error {
	return send(append([]byte(s.payload+"/"+s.config+"/"), body...))
}

func (s *testPushSession) ReceivePush(frame []byte) ([]byte, error) {
	return append([]byte("opened:"), frame...), nil
}

func registerTestProvider(t *testing.T, suffix string, factory Factory) string {
	t.Helper()
	name := t.Name() + "/" + suffix
	if err := RegisterAvailableProvider(name, factory); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		availableProviders.Lock()
		delete(availableProviders.factories, name)
		availableProviders.Unlock()
	})
	return name
}

func TestNamedProvidersOwnConfigurationAndTransport(t *testing.T) {
	echoName := registerTestProvider(t, "echo", func(config, payload string) (Session, error) {
		return &testEchoSession{config: config, payload: payload}, nil
	})
	pushName := registerTestProvider(t, "push", func(config, payload string) (Session, error) {
		return &testPushSession{config: config, payload: payload}, nil
	})
	// Neither provider's configuration or payload identifier is valid Beaconcrypt
	// material. The registry must leave both arguments to the selected factory.
	echo, err := New(echoName, "opaque;not-base64-or-JSON", "echo-payload")
	if err != nil {
		t.Fatal(err)
	}
	push, err := New(pushName, "", "push-payload")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := echo.Exchange([]byte("message"), func(frame []byte) ([]byte, error) {
		if string(frame) != "opaque;not-base64-or-JSON|echo-payload|message" {
			t.Fatalf("echo implementation lost its configuration or payload: %q", frame)
		}
		return []byte("echo reply"), nil
	})
	if err != nil || string(reply) != "echo reply" {
		t.Fatalf("wrong request/response implementation: %q, %v", reply, err)
	}
	var sent []byte
	if err := push.SendPush([]byte("output"), func(frame []byte) error {
		sent = append([]byte(nil), frame...)
		return nil
	}); err != nil || string(sent) != "push-payload//output" {
		t.Fatalf("wrong push implementation: %q, %v", sent, err)
	}
	if opened, err := push.ReceivePush([]byte("task")); err != nil || string(opened) != "opened:task" {
		t.Fatalf("wrong push receive implementation: %q, %v", opened, err)
	}
	other, err := New(echoName, "separate", "other-payload")
	if err != nil || other == echo {
		t.Fatalf("factory reused another session: %v", err)
	}
	otherReply, err := other.Exchange([]byte("message"), func(frame []byte) ([]byte, error) { return frame, nil })
	if err != nil || !bytes.Equal(otherReply, []byte("separate|other-payload|message")) {
		t.Fatalf("new session inherited another instance's configuration: %q, %v", otherReply, err)
	}
}

func TestUnknownProviderHasNoFallback(t *testing.T) {
	called := false
	name := registerTestProvider(t, "known", func(string, string) (Session, error) {
		called = true
		return &testSession{}, nil
	})
	for _, unknown := range []string{"", name + "-unknown", strings.ToUpper(name)} {
		if session, err := New(unknown, "anything", "anything"); session != nil || err == nil || !strings.Contains(err.Error(), "unknown or unavailable") {
			t.Fatalf("unknown provider %q did not fail explicitly: %v, %v", unknown, session, err)
		}
	}
	if called {
		t.Fatal("an unknown provider fell back to a registered implementation")
	}
}

func TestRegistrationCannotReplaceAnImplementation(t *testing.T) {
	original := &testSession{}
	name := registerTestProvider(t, "original", func(string, string) (Session, error) { return original, nil })
	if err := RegisterAvailableProvider(name, func(string, string) (Session, error) {
		t.Fatal("duplicate factory replaced the registered implementation")
		return nil, nil
	}); err == nil {
		t.Fatal("duplicate provider registration succeeded")
	}
	if session, err := New(name, "", ""); err != nil || session != original {
		t.Fatalf("duplicate registration changed the selected implementation: %v", err)
	}
	for _, invalid := range []string{"", " provider", "provider "} {
		if err := RegisterAvailableProvider(invalid, func(string, string) (Session, error) { return original, nil }); err == nil {
			t.Fatalf("invalid provider name %q registered", invalid)
		}
	}
	if err := RegisterAvailableProvider(t.Name()+"/nil", nil); err == nil {
		t.Fatal("nil provider factory registered")
	}
}

func TestSelectedFactoryFailureIsReturned(t *testing.T) {
	want := errors.New("provider cannot open its configuration")
	name := registerTestProvider(t, "failed", func(string, string) (Session, error) { return nil, want })
	if session, err := New(name, "opaque", "payload"); session != nil || !errors.Is(err, want) {
		t.Fatalf("selected provider error was lost: %v, %v", session, err)
	}
}
