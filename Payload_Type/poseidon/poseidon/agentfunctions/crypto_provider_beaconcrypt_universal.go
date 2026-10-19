package agentfunctions

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func beaconcryptBuildBackend(message agentstructs.PayloadBuildMessage) (string, error) {
	if _, present := message.BuildParameters.Parameters["beaconcrypt_backend"]; !present {
		return "native", nil
	}
	backend, err := message.BuildParameters.GetStringArg("beaconcrypt_backend")
	if err != nil {
		return "", err
	}
	if _, err := beaconcryptBackendTags(BuildTarget{BeaconcryptBackend: backend}); err != nil {
		return "", err
	}
	return backend, nil
}

func beaconcryptBackendTags(target BuildTarget) ([]string, error) {
	switch target.BeaconcryptBackend {
	case "", "native":
		return nil, nil
	case "wasm":
		return []string{"beaconcrypt_wazero"}, nil
	default:
		return nil, fmt.Errorf("unsupported Beaconcrypt backend %q; expected native or wasm", target.BeaconcryptBackend)
	}
}

func prepareBeaconcryptWasmBuild(ctx context.Context, target BuildTarget) ([]string, error) {
	agentDirectory, err := filepath.Abs(filepath.Join("poseidon", "agent_code"))
	if err != nil {
		return nil, err
	}
	originalModfile := filepath.Join(agentDirectory, "go.mod")
	versionCommand := exec.CommandContext(ctx, "go", "list", "-modfile="+originalModfile, "-m", "-f", "{{.Version}}", "github.com/0xd6cb6d73/beaconcrypt")
	versionCommand.Dir = agentDirectory
	versionCommand.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	versionOutput, err := versionCommand.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("locate Beaconcrypt module version: %v\n%s", err, versionOutput)
	}
	version := strings.TrimSpace(string(versionOutput))
	if version == "" {
		return nil, fmt.Errorf("Beaconcrypt requires a pinned module version")
	}
	cacheDirectory := os.Getenv("POSEIDON_BEACONCRYPT_WASM_TARGET")
	if cacheDirectory == "" {
		cacheDirectory = filepath.Join(".build", "beaconcrypt-wasm")
	}
	cacheDirectory, err = filepath.Abs(cacheDirectory)
	if err != nil {
		return nil, err
	}
	args := []string{"./scripts/stage-wasm.py", "--version", version, "--cache-dir", cacheDirectory, "--manifest", "./scripts/beaconcrypt-wasm-releases.txt"}
	if bundle := os.Getenv("POSEIDON_BEACONCRYPT_WASM_BUNDLE"); bundle != "" {
		args = append(args, "--bundle", bundle, "--sha256", os.Getenv("POSEIDON_BEACONCRYPT_WASM_SHA256"))
	}
	stageCommand := exec.CommandContext(ctx, "python3", args...)
	stageOutput, err := stageCommand.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("stage Beaconcrypt WASM bundle: %v\n%s", err, stageOutput)
	}
	var staged struct {
		ModuleDirectory string `json:"module_directory"`
	}
	if err := json.Unmarshal(stageOutput, &staged); err != nil || !filepath.IsAbs(staged.ModuleDirectory) {
		return nil, fmt.Errorf("invalid staged Beaconcrypt WASM module: %s", stageOutput)
	}
	stageRoot := filepath.Join(".build", "beaconcrypt-go-module", version, "wasm", target.OS+"-"+target.Arch)
	if err := os.MkdirAll(stageRoot, 0700); err != nil {
		return nil, err
	}
	privateDirectory, err := os.MkdirTemp(stageRoot, "build-")
	if err != nil {
		return nil, err
	}
	modfile := filepath.Join(privateDirectory, "agent.mod")
	modfile, err = filepath.Abs(modfile)
	if err != nil {
		return nil, err
	}
	for _, extension := range []string{"mod", "sum"} {
		contents, err := os.ReadFile(filepath.Join("poseidon", "agent_code", "go."+extension))
		if err != nil {
			return nil, err
		}
		if err := writeBeaconcryptModuleFile(strings.TrimSuffix(modfile, ".mod")+"."+extension, contents); err != nil {
			return nil, err
		}
	}
	if err := configureWasmModfile(ctx, agentDirectory, originalModfile, modfile, staged.ModuleDirectory); err != nil {
		return nil, err
	}
	return []string{"GOFLAGS=" + os.Getenv("GOFLAGS") + " " + strconv.Quote("-modfile="+modfile) + " -mod=mod", "GOWORK=off"}, nil
}

func configureWasmModfile(ctx context.Context, agentDirectory, originalModfile, privateModfile, moduleDirectory string) error {
	inspect := exec.CommandContext(ctx, "go", "mod", "edit", "-json", originalModfile)
	inspect.Dir = agentDirectory
	inspect.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	output, err := inspect.CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect application module replacements: %v\n%s", err, output)
	}
	var parsed struct {
		Replace []struct {
			Old, New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal(output, &parsed); err != nil {
		return err
	}
	args := []string{"mod", "edit", "-modfile=" + privateModfile}
	for _, replacement := range parsed.Replace {
		old := replacement.Old.Path
		if replacement.Old.Version != "" {
			old += "@" + replacement.Old.Version
		}
		if replacement.Old.Path == "github.com/0xd6cb6d73/beaconcrypt" {
			args = append(args, "-dropreplace="+old)
			continue
		}
		if replacement.New.Version == "" && !filepath.IsAbs(replacement.New.Path) {
			// A copied modfile changes the base directory of relative replaces.
			args = append(args, "-replace="+old+"="+filepath.Join(agentDirectory, replacement.New.Path))
		}
	}
	args = append(args, "-replace=github.com/0xd6cb6d73/beaconcrypt="+moduleDirectory)
	edit := exec.CommandContext(ctx, "go", args...)
	edit.Dir = agentDirectory
	edit.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	if output, err := edit.CombinedOutput(); err != nil {
		return fmt.Errorf("configure private WASM modfile: %v\n%s", err, output)
	}
	return nil
}
