package agentfunctions

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func registerTestBuildProvider(t *testing.T, provider BuildProvider) {
	t.Helper()
	registerBuildProvider(provider)
	t.Cleanup(func() { delete(buildProviders, provider.Scheme) })
}

func testProviderProfile(scheme, config string) agentstructs.PayloadBuildC2Profile {
	return agentstructs.PayloadBuildC2Profile{
		Name: "http",
		Parameters: map[string]interface{}{
			"AESPSK": map[string]interface{}{
				"value":           "provider:test-service:" + scheme,
				"provider_config": config,
			},
		},
	}
}

func TestBuildProviderUsesItsOwnConfigTargetsAndPreparation(t *testing.T) {
	// Neither a binary format nor this larger configuration follows Beaconcrypt's
	// JSON identity schema or 64 KiB limit. The registry must not impose either.
	configs := []string{
		base64.StdEncoding.EncodeToString([]byte{0, 255, 128, 0, 17}),
		base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{255}, 70<<10)),
	}
	var validated []string
	preparations := 0
	type contextKey struct{}
	ctx := context.WithValue(context.Background(), contextKey{}, "build-context")
	registerTestBuildProvider(t, BuildProvider{
		Scheme:   "test-binary",
		BuildTag: "test_binary_client",
		Validate: func(message agentstructs.PayloadBuildMessage, config string) error {
			if message.SelectedOS != agentstructs.SUPPORTED_OS_MACOS || len(message.C2Profiles) != 3 {
				return fmt.Errorf("test provider received a different build")
			}
			if _, err := base64.StdEncoding.Strict().DecodeString(config); err != nil {
				return err
			}
			validated = append(validated, config)
			return nil
		},
		Prepare: func(received context.Context, target BuildTarget) ([]string, error) {
			if target != (BuildTarget{OS: "darwin", Arch: "arm64"}) {
				return nil, fmt.Errorf("provider received a different target: %+v", target)
			}
			if received.Value(contextKey{}) != "build-context" {
				return nil, fmt.Errorf("build context was lost")
			}
			preparations++
			return []string{"TEST_BINARY_CLIENT=enabled"}, nil
		},
	})
	message := agentstructs.PayloadBuildMessage{
		SelectedOS: agentstructs.SUPPORTED_OS_MACOS,
		C2Profiles: []agentstructs.PayloadBuildC2Profile{
			testProviderProfile("test-binary", configs[0]),
			testProviderProfile("test-binary", configs[1]),
			{Name: "websocket", Parameters: map[string]interface{}{"AESPSK": map[string]interface{}{"value": "aes256_hmac", "enc_key": "legacy-key"}}},
		},
	}
	message.C2Profiles[1].Name = "tcp"
	message.C2Profiles[1].IsP2P = true
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, &message); err != nil {
		t.Fatal(err)
	}
	selections, err := validateProviderBuild(message)
	if err != nil || len(selections) != 2 || !reflect.DeepEqual(validated, configs) || preparations != 0 {
		t.Fatalf("select=%v validation=%v preparations=%d error=%v", selections, validated, preparations, err)
	}
	for index, config := range configs {
		initial := map[string]interface{}{"headers": "preserved", "AESPSK": "old-key", "encrypted_exchange_check": true}
		selections[index].configureProfile(initial)
		if initial["crypto_provider"] != "test-binary" || initial["crypto_provider_config"] != config || initial["AESPSK"] != "" || initial["encrypted_exchange_check"] != false || initial["headers"] != "preserved" {
			t.Fatalf("profile %d changed provider configuration: %v", index, initial)
		}
	}
	if selections[2] != nil {
		t.Fatal("legacy profile selected an external implementation")
	}
	tags, env, err := prepareProviderBuild(ctx, selections, len(message.C2Profiles), BuildTarget{OS: "darwin", Arch: "arm64"})
	if err != nil || preparations != 1 || !reflect.DeepEqual(tags, []string{"test_binary_client"}) || !reflect.DeepEqual(env, []string{"TEST_BINARY_CLIENT=enabled"}) {
		t.Fatalf("preparations=%d tags=%v env=%v error=%v", preparations, tags, env, err)
	}
}

func TestBuildProvidersPrepareOnceInProfileOrder(t *testing.T) {
	var prepared []string
	for _, scheme := range []string{"test-z-last", "test-a-first"} {
		scheme := scheme
		registerTestBuildProvider(t, BuildProvider{
			Scheme: scheme, BuildTag: strings.ReplaceAll(scheme, "-", "_"),
			Validate: func(agentstructs.PayloadBuildMessage, string) error { return nil },
			Prepare: func(context.Context, BuildTarget) ([]string, error) {
				prepared = append(prepared, scheme)
				return []string{"PROVIDER_" + strings.ReplaceAll(scheme, "-", "_") + "=ready"}, nil
			},
		})
	}
	message := agentstructs.PayloadBuildMessage{C2Profiles: []agentstructs.PayloadBuildC2Profile{
		testProviderProfile("test-z-last", "first"),
		testProviderProfile("test-a-first", "second"),
		testProviderProfile("test-z-last", "third"),
	}}
	selections, err := validateProviderBuild(message)
	if err != nil {
		t.Fatal(err)
	}
	tags, env, err := prepareProviderBuild(context.Background(), selections, len(message.C2Profiles), BuildTarget{OS: "linux", Arch: "arm64"})
	if err != nil || !reflect.DeepEqual(prepared, []string{"test-z-last", "test-a-first"}) || !reflect.DeepEqual(tags, []string{"test_z_last", "test_a_first"}) || len(env) != 2 {
		t.Fatalf("preparation order=%v tags=%v env=%v error=%v", prepared, tags, env, err)
	}
	schemes := SupportedCryptoSchemes()
	if !sort.StringsAreSorted(schemes) || !strings.Contains(strings.Join(schemes, ","), "test-a-first") {
		t.Fatalf("registered schemes not advertised: %v", schemes)
	}
	schemes[0] = "changed"
	if reflect.DeepEqual(schemes, SupportedCryptoSchemes()) {
		t.Fatal("caller mutated registered schemes")
	}
}

func TestInvalidProviderSelectionsFailBeforePreparation(t *testing.T) {
	preparations := 0
	registerTestBuildProvider(t, BuildProvider{
		Scheme: "test-no-effects", BuildTag: "test_no_effects",
		Validate: func(agentstructs.PayloadBuildMessage, string) error { return nil },
		Prepare:  func(context.Context, BuildTarget) ([]string, error) { preparations++; return nil, nil },
	})
	for _, selection := range []string{
		"provider:test-service:unknown", "provider::test-no-effects", "provider:test-service:",
		"provider:bad service:test-no-effects", "provider:test-service:test-no-effects:extra",
	} {
		t.Run(selection, func(t *testing.T) {
			invalid := testProviderProfile("test-no-effects", "opaque")
			invalid.Parameters["AESPSK"].(map[string]interface{})["value"] = selection
			message := agentstructs.PayloadBuildMessage{C2Profiles: []agentstructs.PayloadBuildC2Profile{
				testProviderProfile("test-no-effects", "opaque"), invalid,
			}}
			result := build(context.Background(), message)
			if result.Success || !strings.Contains(result.BuildStdErr, "unsupported crypto provider") || preparations != 0 {
				t.Fatalf("invalid selection reached build preparation: success=%v preparations=%d error=%s", result.Success, preparations, result.BuildStdErr)
			}
		})
	}
}
