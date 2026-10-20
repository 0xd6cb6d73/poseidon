// Package cryptoprovider selects registered agent cryptographic providers.
// Implementations own their configuration and protocol; transports exchange their
// opaque frames through Session without interpreting either.
package cryptoprovider

import (
	"fmt"
	"strings"
	"sync"
)

// RoundTrip exchanges one complete provider frame. A transport may retry the
// same frame, but must not return a different request's response.
type RoundTrip func(frame []byte) ([]byte, error)

// Session owns the lifecycle and message state of one provider instance.
// Request/response transports use Exchange and Resume; ordered push transports
// use StartPush, SendPush and ReceivePush after registration and check-in.
// Methods may be called concurrently; implementations serialize their state.
type Session interface {
	// Register establishes the provider's session, or does nothing if unnecessary.
	Register(send RoundTrip) error
	// CheckIn returns the authenticated Mythic reply and assigned callback UUID.
	CheckIn(plaintext []byte, send RoundTrip) ([]byte, string, error)
	// Exchange retains an unfinished request across retries of the same plaintext.
	Exchange(plaintext []byte, send RoundTrip) ([]byte, error)
	// Resume finishes an interrupted Exchange, returning nil if none is pending.
	Resume(send RoundTrip) ([]byte, error)
	// SendPush retains a failed write for retry and does not wait for a reply.
	SendPush(plaintext []byte, send func([]byte) error) error
	// StartPush announces the callback on a new connection unless a write is pending.
	StartPush(plaintext []byte, send func([]byte) error) error
	// ReceivePush opens one server frame, including unsolicited task messages.
	ReceivePush(frame []byte) ([]byte, error)
	// Failed reports a terminal failure that prevents any further communication.
	Failed() bool
	// Close releases resources and makes the session unusable.
	Close()
}

// Factory consumes the provider's opaque configuration and the payload UUID.
type Factory func(config, payloadUUID string) (Session, error)

var availableProviders = struct {
	sync.RWMutex
	factories map[string]Factory
}{factories: make(map[string]Factory)}

// RegisterAvailableProvider exposes an implementation under its configured name.
// Providers register from init in files selected by their build constraints.
// Duplicate registrations fail rather than silently replacing an implementation.
func RegisterAvailableProvider(name string, factory Factory) error {
	if name == "" || strings.TrimSpace(name) != name {
		return fmt.Errorf("invalid crypto provider name %q", name)
	}
	if factory == nil {
		return fmt.Errorf("crypto provider %q has no factory", name)
	}
	availableProviders.Lock()
	defer availableProviders.Unlock()
	if _, exists := availableProviders.factories[name]; exists {
		return fmt.Errorf("crypto provider %q is already registered", name)
	}
	availableProviders.factories[name] = factory
	return nil
}

// New constructs the named implementation. Unknown or uncompiled providers fail
// without selecting another implementation or interpreting the configuration.
func New(name, config, payloadUUID string) (Session, error) {
	availableProviders.RLock()
	factory, exists := availableProviders.factories[name]
	availableProviders.RUnlock()
	if !exists {
		return nil, fmt.Errorf("unknown or unavailable crypto provider %q", name)
	}
	session, err := factory(config, payloadUUID)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, fmt.Errorf("crypto provider %q returned no session", name)
	}
	return session, nil
}
