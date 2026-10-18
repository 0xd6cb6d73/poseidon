//go:build (linux || darwin) && http

package profiles

import (
	"encoding/json"
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
