package agentfunctions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func init() {
	registerBuildProvider(BuildProvider{
		Scheme:   "beaconcrypt",
		BuildTag: "beaconcrypt",
		Validate: validateBeaconcryptBuild,
		Prepare:  prepareBeaconcryptBuild,
	})
}

func validateBeaconcryptBuild(message agentstructs.PayloadBuildMessage, config string) error {
	if len(message.C2Profiles) != 1 {
		return fmt.Errorf("Beaconcrypt currently requires exactly one direct HTTP or P2P TCP C2 profile")
	}
	profile := message.C2Profiles[0]
	if (profile.Name != "http" && profile.Name != "tcp") || profile.IsP2P != (profile.Name == "tcp") {
		return fmt.Errorf("Beaconcrypt currently requires exactly one direct HTTP or P2P TCP C2 profile")
	}
	if len(config) > 64*1024 {
		return fmt.Errorf("Beaconcrypt provider_config exceeds the 64 KiB agent limit")
	}
	material, err := base64.StdEncoding.Strict().DecodeString(config)
	if err != nil || len(material) == 0 {
		return fmt.Errorf("Beaconcrypt requires the base64 provider_config supplied by Mythic")
	}
	var materialConfig struct {
		Version         int    `json:"version"`
		ServerKID       string `json:"server_kid"`
		ServerPublicKey []byte `json:"server_public_key"`
	}
	if err := json.Unmarshal(material, &materialConfig); err != nil {
		return fmt.Errorf("invalid Beaconcrypt provider_config: %w", err)
	}
	serverKID, kidErr := strconv.ParseUint(materialConfig.ServerKID, 10, 64)
	if materialConfig.Version != 1 || kidErr != nil || strconv.FormatUint(serverKID, 10) != materialConfig.ServerKID || len(materialConfig.ServerPublicKey) != 32 {
		return fmt.Errorf("invalid Beaconcrypt v1 server identity in provider_config")
	}
	architecture, err := message.BuildParameters.GetStringArg("architecture")
	if err != nil {
		return err
	}
	mode, err := message.BuildParameters.GetStringArg("mode")
	if err != nil {
		return err
	}
	static, err := message.BuildParameters.GetBooleanArg("static")
	if err != nil {
		return err
	}
	garble, err := message.BuildParameters.GetBooleanArg("garble")
	if err != nil {
		return err
	}
	if message.SelectedOS != agentstructs.SUPPORTED_OS_LINUX || (architecture != "AMD_x64" && architecture != "ARM_x64") || mode != "default" || static || garble {
		return fmt.Errorf("Beaconcrypt currently supports Linux AMD_x64 or ARM_x64 executables with static and garble disabled")
	}
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") {
		return fmt.Errorf("Beaconcrypt payloads currently require a Linux amd64 or arm64 payload builder")
	}
	return nil
}

func prepareBeaconcryptBuild(ctx context.Context, target BuildTarget) ([]string, error) {
	directory, err := beaconcryptNativeLibraryDirectory(target)
	if err != nil {
		return nil, err
	}
	nativeCommand := exec.CommandContext(ctx, "bash", "./scripts/build-native.sh", target.OS, target.Arch)
	nativeCommand.Env = os.Environ()
	nativeOutput, err := nativeCommand.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("build Beaconcrypt native library: %v\n%s", err, nativeOutput)
	}
	return []string{"CGO_LDFLAGS=-L" + directory + " " + os.Getenv("CGO_LDFLAGS")}, nil
}

func beaconcryptTargetTriple(target BuildTarget) (string, error) {
	if target.OS == "linux" {
		switch target.Arch {
		case "amd64":
			return "x86_64-unknown-linux-gnu", nil
		case "arm64":
			return "aarch64-unknown-linux-gnu", nil
		}
	}
	return "", fmt.Errorf("unsupported Beaconcrypt native target %s/%s; expected linux/amd64 or linux/arm64", target.OS, target.Arch)
}

// Installed payload containers mount source over /Mythic. Keep their baked
// native artifacts outside that mount, with a separate directory per Rust target.
func beaconcryptNativeLibraryDirectory(target BuildTarget) (string, error) {
	triple, err := beaconcryptTargetTriple(target)
	if err != nil {
		return "", err
	}
	root := os.Getenv("POSEIDON_BEACONCRYPT_NATIVE_TARGET")
	if root == "" {
		root = ".build/beaconcrypt-native-target"
	} else if !filepath.IsAbs(root) {
		return "", fmt.Errorf("POSEIDON_BEACONCRYPT_NATIVE_TARGET must be an absolute path")
	}
	return filepath.Abs(filepath.Join(root, triple, "release"))
}
