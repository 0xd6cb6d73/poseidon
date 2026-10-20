//go:build !beaconcrypt || (!linux && !darwin) || (!amd64 && !arm64)

package cryptoprovider

import (
	"strings"
	"testing"
)

func TestBeaconcryptRequiresItsCompiledImplementation(t *testing.T) {
	if session, err := New("beaconcrypt", "opaque", "payload"); session != nil || err == nil || !strings.Contains(err.Error(), "unknown or unavailable") {
		t.Fatalf("uncompiled Beaconcrypt implementation was selected: %v, %v", session, err)
	}
}
