//go:build (linux || darwin) && http

package profiles

import (
	"encoding/json"
	"io"
	"testing"
)

func TestHTTPProviderConfigSelectsNamedImplementation(t *testing.T) {
	var config HTTPInitialConfig
	if err := json.Unmarshal([]byte(`{"crypto_provider":"alternate","crypto_provider_config":"opaque-material"}`), &config); err != nil {
		t.Fatal(err)
	}
	if config.CryptoProvider != "alternate" || config.CryptoProviderConfig != "opaque-material" {
		t.Fatalf("HTTP config changed provider selection: %+v", config)
	}
	for _, data := range []string{`{"crypto_provider":17}`, `{"crypto_provider_config":17}`} {
		if err := json.Unmarshal([]byte(data), &config); err == nil {
			t.Fatalf("non-string provider field accepted: %s", data)
		}
	}
}

// fillReader avoids allocating an unbounded source while exercising the actual
// HTTP reader's allocation and one-byte-over limit detection.
type fillReader struct{}

func (fillReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestHTTPProviderResponseSizeLimit(t *testing.T) {
	for _, test := range []struct {
		name      string
		size      int
		wantError bool
	}{
		{name: "above previous transport limit", size: (16 << 20) + 1},
		{name: "largest provider envelope", size: maxProviderHTTPResponseBytes},
		{name: "one byte over envelope", size: maxProviderHTTPResponseBytes + 1, wantError: true},
		{name: "unbounded response", size: maxProviderHTTPResponseBytes + 4096, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := &io.LimitedReader{R: fillReader{}, N: int64(test.size)}
			body, err := readProviderHTTPResponse(source)
			if (err != nil) != test.wantError {
				t.Fatalf("size %d: err=%v", test.size, err)
			}
			if !test.wantError && len(body) != test.size {
				t.Fatalf("response truncated to %d of %d bytes", len(body), test.size)
			}
			if read := int64(test.size) - source.N; read > int64(maxProviderHTTPResponseBytes)+1 {
				t.Fatalf("read %d bytes beyond bounded response", read)
			}
		})
	}
}
