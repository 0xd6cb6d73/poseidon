package agentfunctions

import (
	"bytes"
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
	if (message.SelectedOS != agentstructs.SUPPORTED_OS_LINUX && message.SelectedOS != agentstructs.SUPPORTED_OS_MACOS) || (architecture != "AMD_x64" && architecture != "ARM_x64") || mode != "default" || static || garble {
		return fmt.Errorf("Beaconcrypt currently supports Linux or macOS AMD_x64 or ARM_x64 executables with static and garble disabled")
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
	linkFlags := "-L" + directory + " " + os.Getenv("CGO_LDFLAGS")
	if target.OS != "darwin" {
		return []string{"CGO_LDFLAGS=" + linkFlags}, nil
	}
	// v0.6.0's macOS binding names an absolute archive inside the module.
	// Stage a private copy with this target's library; never edit the shared cache.
	moduleCommand := exec.CommandContext(ctx, "go", "mod", "download", "-json", "github.com/0xd6cb6d73/beaconcrypt")
	moduleCommand.Dir = "./poseidon/agent_code"
	moduleOutput, err := moduleCommand.Output()
	if err != nil {
		return nil, fmt.Errorf("locate Beaconcrypt Go module: %w", err)
	}
	var module struct{ Dir, Version string }
	if err := json.Unmarshal(moduleOutput, &module); err != nil || module.Dir == "" || module.Version == "" {
		return nil, fmt.Errorf("cannot locate Beaconcrypt Go module")
	}
	stageDirectory, err := filepath.Abs(filepath.Join(".build", "beaconcrypt-go-module", module.Version, target.Arch))
	if err != nil {
		return nil, err
	}
	modfile, err := beaconcryptDarwinModule(module.Dir, directory, stageDirectory)
	if err != nil {
		return nil, err
	}
	compiler, minimumOS := "o64-clang", "15.5"
	if target.Arch == "arm64" {
		compiler, minimumOS = "oa64-clang", "26.5"
	}
	// Pass the released library's deployment minimum directly to the linker.
	// osxcross's compiler wrapper rejects newer C targets with its older SDK.
	return []string{
		"CGO_LDFLAGS=" + linkFlags + " -Wl,-macosx_version_min," + minimumOS,
		"GOFLAGS=" + os.Getenv("GOFLAGS") + " " + strconv.Quote("-modfile="+modfile),
		"CC=" + compiler,
		"CXX=" + compiler + "++",
	}, nil
}

func beaconcryptDarwinModule(moduleDirectory, nativeDirectory, stageDirectory string) (string, error) {
	library, err := os.ReadFile(filepath.Join(nativeDirectory, "libbeaconcrypt.a"))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(stageDirectory, 0700); err != nil {
		return "", err
	}
	stagedModule := filepath.Join(stageDirectory, "module")
	if _, err := os.Stat(filepath.Join(stagedModule, "go.mod")); os.IsNotExist(err) {
		temporary, err := os.MkdirTemp(stageDirectory, ".module-*")
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(temporary)
		if err := os.CopyFS(temporary, os.DirFS(moduleDirectory)); err != nil {
			return "", err
		}
		libraryDirectory := filepath.Join(temporary, "target", "release")
		if err := os.MkdirAll(libraryDirectory, 0700); err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(libraryDirectory, "libbeaconcrypt.a"), library, 0644); err != nil {
			return "", err
		}
		if err := os.Rename(temporary, stagedModule); err != nil {
			// Another build may already have published the same complete target.
			if _, existing := os.Stat(filepath.Join(stagedModule, "go.mod")); existing != nil {
				return "", err
			}
		}
	} else if err != nil {
		return "", err
	}
	// The source archive was checksum-verified by build-native.sh. Validate the
	// staged copy as well, so a damaged cache cannot bypass the release pin.
	stagedLibrary := filepath.Join(stagedModule, "target", "release", "libbeaconcrypt.a")
	if cached, err := os.ReadFile(stagedLibrary); err != nil || !bytes.Equal(cached, library) {
		if err := writeBeaconcryptModuleFile(stagedLibrary, library); err != nil {
			return "", err
		}
	}
	modfile := filepath.Join(stageDirectory, "agent.mod")
	for _, extension := range []string{"mod", "sum"} {
		contents, err := os.ReadFile(filepath.Join("poseidon", "agent_code", "go."+extension))
		if err != nil {
			return "", err
		}
		if extension == "mod" {
			contents = append(contents, []byte("\nreplace github.com/0xd6cb6d73/beaconcrypt => "+strconv.Quote(stagedModule)+"\n")...)
		}
		if err := writeBeaconcryptModuleFile(filepath.Join(stageDirectory, "agent."+extension), contents); err != nil {
			return "", err
		}
	}
	return modfile, nil
}

// Atomic replacement keeps concurrent builds from observing partial files.
func writeBeaconcryptModuleFile(path string, contents []byte) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".module-file-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}

func beaconcryptTargetTriple(target BuildTarget) (string, error) {
	switch target.OS {
	case "linux":
		switch target.Arch {
		case "amd64":
			return "x86_64-unknown-linux-gnu", nil
		case "arm64":
			return "aarch64-unknown-linux-gnu", nil
		}
	case "darwin":
		switch target.Arch {
		case "amd64":
			return "x86_64-apple-darwin", nil
		case "arm64":
			return "aarch64-apple-darwin", nil
		}
	}
	return "", fmt.Errorf("unsupported Beaconcrypt native target %s/%s; expected linux or darwin on amd64 or arm64", target.OS, target.Arch)
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
