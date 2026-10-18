package agentfunctions

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

// BuildTarget uses Go target names, such as linux/arm64, independently of the
// host running the payload builder.
type BuildTarget struct {
	OS   string
	Arch string
}

// BuildProvider describes a client implementation available to payload builds.
// Providers register from their own source files, validate their own opaque
// configuration, and prepare any dependencies before Go compiles the payload.
type BuildProvider struct {
	Scheme   string
	BuildTag string
	Validate func(agentstructs.PayloadBuildMessage, string) error
	Prepare  func(context.Context, BuildTarget) ([]string, error)
}

var buildProviders = map[string]BuildProvider{}
var providerIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
var providerBuildTag = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.]*$`)

// Registration is performed during package initialization, like C2 profiles.
func registerBuildProvider(provider BuildProvider) {
	if !providerIdentifier.MatchString(provider.Scheme) || !providerBuildTag.MatchString(provider.BuildTag) || provider.Validate == nil {
		panic("invalid crypto build provider registration")
	}
	if _, present := buildProviders[provider.Scheme]; present {
		panic("duplicate crypto build provider: " + provider.Scheme)
	}
	buildProviders[provider.Scheme] = provider
}

// SupportedCryptoSchemes declares registered external client implementations.
// Built-in AES/none choices remain owned by the C2 profile definitions.
func SupportedCryptoSchemes() []string {
	schemes := make([]string, 0, len(buildProviders))
	for scheme := range buildProviders {
		schemes = append(schemes, scheme)
	}
	sort.Strings(schemes)
	return schemes
}

// The SDK's CryptoArg currently omits provider_config. Decode the complete
// Mythic projection here so the provider's exact bytes survive payload builds.
type providerCryptoArg struct {
	Value          string `json:"value"`
	ProviderConfig string `json:"provider_config"`
}

func decodeProviderCryptoArg(value interface{}) (providerCryptoArg, error) {
	var argument providerCryptoArg
	encoded, err := json.Marshal(value)
	if err != nil {
		return argument, fmt.Errorf("invalid crypto provider argument: %w", err)
	}
	if err := json.Unmarshal(encoded, &argument); err != nil {
		return argument, fmt.Errorf("invalid crypto provider argument: %w", err)
	}
	return argument, nil
}

type providerBuildSelection struct {
	BuildProvider
	Config string
}

func (selection *providerBuildSelection) configureProfile(config map[string]interface{}) {
	config["crypto_provider"] = selection.Scheme
	config["crypto_provider_config"] = selection.Config
	config["AESPSK"] = ""
	config["encrypted_exchange_check"] = false
}

// Resolve every external selection before provider-specific validation. The
// shared builder treats configuration as opaque and leaves target and C2
// restrictions to the selected implementation. Validation has no side effects.
func validateProviderBuild(message agentstructs.PayloadBuildMessage) (map[int]*providerBuildSelection, error) {
	selections := map[int]*providerBuildSelection{}
	for index, profile := range message.C2Profiles {
		raw, present := profile.Parameters["AESPSK"]
		if !present {
			continue
		}
		argument, err := decodeProviderCryptoArg(raw)
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(argument.Value, "provider:") {
			continue
		}
		parts := strings.Split(argument.Value, ":")
		if len(parts) != 3 || !providerIdentifier.MatchString(parts[1]) || !providerIdentifier.MatchString(parts[2]) {
			return nil, fmt.Errorf("unsupported crypto provider selection %q; expected provider:<service>:<scheme>", argument.Value)
		}
		provider, present := buildProviders[parts[2]]
		if !present {
			return nil, fmt.Errorf("unsupported crypto provider scheme %q", parts[2])
		}
		selections[index] = &providerBuildSelection{BuildProvider: provider, Config: argument.ProviderConfig}
	}
	for index := range message.C2Profiles {
		if selection := selections[index]; selection != nil {
			if err := selection.Validate(message, selection.Config); err != nil {
				return nil, err
			}
		}
	}
	return selections, nil
}

// Prepare each selected implementation once, in C2 profile order. Multiple
// profiles may use one implementation without repeating its native build.
func prepareProviderBuild(ctx context.Context, selections map[int]*providerBuildSelection, profileCount int, target BuildTarget) ([]string, []string, error) {
	var tags, env []string
	prepared, tagged := map[string]bool{}, map[string]bool{}
	for index := 0; index < profileCount; index++ {
		selection := selections[index]
		if selection == nil || prepared[selection.Scheme] {
			continue
		}
		prepared[selection.Scheme] = true
		if !tagged[selection.BuildTag] {
			tags = append(tags, selection.BuildTag)
			tagged[selection.BuildTag] = true
		}
		if selection.Prepare == nil {
			continue
		}
		providerEnv, err := selection.Prepare(ctx, target)
		if err != nil {
			return nil, nil, fmt.Errorf("prepare crypto provider %q: %w", selection.Scheme, err)
		}
		env = append(env, providerEnv...)
	}
	return tags, env, nil
}
