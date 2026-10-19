package agentfunctions

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestBeaconcryptBackendBuildSelection(t *testing.T) {
	message := beaconcryptBuildFixture()
	if backend, err := beaconcryptBuildBackend(message); err != nil || backend != "native" {
		t.Fatalf("default backend=%q error=%v", backend, err)
	}
	for _, backend := range []string{"native", "wasm"} {
		t.Run(backend, func(t *testing.T) {
			message := beaconcryptBuildFixture()
			message.BuildParameters.Parameters["beaconcrypt_backend"] = backend
			selections, err := validateProviderBuild(message)
			if err != nil {
				t.Fatal(err)
			}
			selections[0].Prepare = nil
			tags, env, err := prepareProviderBuild(context.Background(), selections, 1, BuildTarget{OS: "darwin", Arch: "arm64", BeaconcryptBackend: backend})
			expected := []string{"beaconcrypt"}
			if backend == "wasm" {
				expected = append(expected, "beaconcrypt_wazero")
			}
			if err != nil || !reflect.DeepEqual(tags, expected) || len(env) != 0 {
				t.Fatalf("tags=%v env=%v error=%v", tags, env, err)
			}
		})
	}
	message.BuildParameters.Parameters["beaconcrypt_backend"] = "automatic"
	if _, err := validateProviderBuild(message); err == nil {
		t.Fatal("unsupported backend accepted")
	}
	message.C2Profiles[0].Parameters["AESPSK"] = map[string]interface{}{"value": "none"}
	if _, err := validateProviderBuild(message); err != nil {
		t.Fatalf("unused Beaconcrypt option affected legacy provider: %v", err)
	}
}

func testWasmBundle(t *testing.T, directory string) (string, string) {
	t.Helper()
	wasm := []byte{'\x00', 'a', 's', 'm', 1, 0, 0, 0}
	files := map[string][]byte{"go.mod": []byte("module github.com/0xd6cb6d73/beaconcrypt\n\ngo 1.25.0\n"), "api.go": []byte("package beaconcrypt\n"), "internal/wasm/beaconcrypt.wasm": wasm}
	hashes := map[string]string{}
	for name, data := range files {
		sum := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(sum[:])
	}
	manifest := map[string]interface{}{"schema_version": 1, "wasm_abi_version": 1, "module": "github.com/0xd6cb6d73/beaconcrypt", "version": "v0.6.0", "source_dirty": true, "files_sha256": hashes, "wasm": map[string]interface{}{"path": "internal/wasm/beaconcrypt.wasm", "sha256": hashes["internal/wasm/beaconcrypt.wasm"], "bytes": len(wasm)}}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files["beaconcrypt-wasm-manifest.json"] = encoded
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tarWriter := tar.NewWriter(gz)
	for name, data := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: "beaconcrypt-go-v0.6.0/" + name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "bundle.tar.gz")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(archive.Bytes())
	return path, hex.EncodeToString(sum[:])
}

func TestBeaconcryptWasmPreparationPreservesAgentSourceAndNativeFlags(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join("..", "..", "scripts", "stage-wasm.py"))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	bundle, checksum := testWasmBundle(t, work)
	for _, directory := range []string{"scripts", filepath.Join("poseidon", "agent_code")} {
		if err := os.MkdirAll(filepath.Join(work, directory), 0700); err != nil {
			t.Fatal(err)
		}
	}
	agentDirectory := filepath.Join(work, "poseidon", "agent_code")
	mod := []byte("module fixture\n\ngo 1.25.0\n\nrequire github.com/0xd6cb6d73/beaconcrypt v0.6.0\n")
	for path, data := range map[string][]byte{
		filepath.Join(work, "scripts", "stage-wasm.py"):   script,
		filepath.Join(work, "scripts", "build-native.sh"): []byte("touch native-called\nexit 99\n"),
		filepath.Join(work, "go"):                         []byte("#!/bin/sh\nif [ \"$1\" = list ]; then test \"$GOWORK\" = off && test -z \"$GOFLAGS\" && test \"$2\" = \"-modfile=$POSEIDON_TEST_ORIGINAL_MODFILE\" || exit 98; printf 'v0.6.0\\n'; else exec \"$POSEIDON_TEST_REAL_GO\" \"$@\"; fi\n"),
		filepath.Join(agentDirectory, "go.mod"):           mod,
		filepath.Join(agentDirectory, "go.sum"):           nil,
	} {
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", work+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("POSEIDON_TEST_REAL_GO", goBinary)
	t.Setenv("POSEIDON_TEST_ORIGINAL_MODFILE", filepath.Join(agentDirectory, "go.mod"))
	t.Setenv("GOWORK", filepath.Join(work, "nonexistent.work"))
	t.Setenv("POSEIDON_BEACONCRYPT_WASM_BUNDLE", bundle)
	t.Setenv("POSEIDON_BEACONCRYPT_WASM_SHA256", checksum)
	t.Setenv("POSEIDON_BEACONCRYPT_WASM_TARGET", filepath.Join(work, "wasm-cache"))
	t.Setenv("GOFLAGS", "-mod=readonly")
	t.Setenv("CGO_LDFLAGS", "-lother")
	t.Chdir(work)
	target := BuildTarget{OS: "darwin", Arch: "arm64", BeaconcryptBackend: "wasm"}
	env, err := prepareBeaconcryptBuild(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(env, "\n")
	for _, expected := range []string{"-modfile=", "-mod=mod", "GOWORK=off"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("missing %q in %v", expected, env)
		}
	}
	for _, unexpected := range []string{"CGO_LDFLAGS=", "-macosx_version_min", "CC=", "CXX="} {
		if strings.Contains(joined, unexpected) {
			t.Fatalf("WASM path set native flags: %v", env)
		}
	}
	if _, err := os.Stat(filepath.Join(work, "native-called")); !os.IsNotExist(err) {
		t.Fatal("WASM preparation invoked native dependency build")
	}
	command := exec.Command(goBinary, "list", "-m", "-f", "{{.Dir}}", "github.com/0xd6cb6d73/beaconcrypt")
	command.Dir = agentDirectory
	command.Env = append(os.Environ(), env...)
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "wasm-cache") {
		t.Fatalf("Go did not resolve staged bundle: %s: %v", output, err)
	}
	contents, err := os.ReadFile(filepath.Join(agentDirectory, "go.mod"))
	if err != nil || !bytes.Equal(contents, mod) {
		t.Fatal("WASM preparation modified application go.mod")
	}
	contents, err = os.ReadFile(filepath.Join(agentDirectory, "go.sum"))
	if err != nil || len(contents) != 0 {
		t.Fatal("WASM preparation modified application go.sum")
	}
	second, err := prepareBeaconcryptBuild(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(env, second) {
		t.Fatal("concurrent builds would share writable modfiles")
	}
}

func TestDarwinBuildCompilers(t *testing.T) {
	for _, test := range []struct{ arch, cc, cxx string }{
		{"amd64", "o64-clang", "o64-clang++"},
		{"arm64", "oa64-clang", "oa64-clang++"},
	} {
		cc, cxx := darwinBuildCompilers(test.arch)
		if cc != test.cc || cxx != test.cxx {
			t.Fatalf("%s: %s %s", test.arch, cc, cxx)
		}
	}
}

func TestWasmModfileRebasesReplacements(t *testing.T) {
	work := t.TempDir()
	agentDirectory := filepath.Join(work, "agent")
	privateDirectory := filepath.Join(work, "private")
	for _, directory := range []string{agentDirectory, privateDirectory} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	original := []byte(`module fixture

go 1.25.0

require github.com/0xd6cb6d73/beaconcrypt v0.6.0

replace github.com/0xd6cb6d73/beaconcrypt => ../old-beaconcrypt
replace github.com/0xd6cb6d73/beaconcrypt v0.6.0 => ../versioned-beaconcrypt
replace example.com/local => ../local
replace example.com/versioned v1.2.3 => ./versioned
replace example.com/remote => example.com/fork v1.0.0
`)
	originalModfile := filepath.Join(agentDirectory, "go.mod")
	privateModfile := filepath.Join(privateDirectory, "agent.mod")
	for _, name := range []string{originalModfile, privateModfile} {
		if err := os.WriteFile(name, original, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Ambient workspace and modfile choices must not affect the original module.
	t.Setenv("GOWORK", filepath.Join(work, "nonexistent.work"))
	t.Setenv("GOFLAGS", "-modfile="+filepath.Join(work, "nonexistent.mod"))
	stagedDirectory := filepath.Join(work, "staged-beaconcrypt")
	if err := configureWasmModfile(context.Background(), agentDirectory, originalModfile, privateModfile, stagedDirectory); err != nil {
		t.Fatal(err)
	}
	inspect := exec.Command("go", "mod", "edit", "-json", privateModfile)
	inspect.Dir = agentDirectory
	inspect.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	output, err := inspect.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, output)
	}
	var parsed struct {
		Replace []struct {
			Old, New struct{ Path, Version string }
		}
	}
	if err := json.Unmarshal(output, &parsed); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"github.com/0xd6cb6d73/beaconcrypt": stagedDirectory,
		"example.com/local":                 filepath.Join(work, "local"),
		"example.com/versioned@v1.2.3":      filepath.Join(agentDirectory, "versioned"),
		"example.com/remote":                "example.com/fork@v1.0.0",
	}
	if len(parsed.Replace) != len(want) {
		t.Fatalf("unexpected replacements: %s", output)
	}
	for _, r := range parsed.Replace {
		old, replacement := r.Old.Path, r.New.Path
		if r.Old.Version != "" {
			old += "@" + r.Old.Version
		}
		if r.New.Version != "" {
			replacement += "@" + r.New.Version
		}
		if want[old] != replacement {
			t.Errorf("replacement %s=%s; want %s", old, replacement, want[old])
		}
	}
	contents, err := os.ReadFile(originalModfile)
	if err != nil || !bytes.Equal(contents, original) {
		t.Fatal("original modfile changed")
	}
}

// This opt-in test exercises the production preparation path and compiles the
// unchanged agent. A config file can be emitted for container cross-builds.
func TestBeaconcryptWasmLocalBundleBuild(t *testing.T) {
	if os.Getenv("POSEIDON_TEST_WASM_BUILD") != "1" {
		t.Skip("set POSEIDON_TEST_WASM_BUILD=1 and provide a local bundle plus SHA256")
	}
	if os.Getenv("POSEIDON_BEACONCRYPT_WASM_BUNDLE") == "" || os.Getenv("POSEIDON_BEACONCRYPT_WASM_SHA256") == "" {
		t.Fatal("explicit local bundle and SHA256 required")
	}
	project, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	agent := filepath.Join(project, "poseidon", "agent_code")
	originals := map[string][]byte{}
	for _, name := range []string{"go.mod", "go.sum"} {
		originals[name], err = os.ReadFile(filepath.Join(agent, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for name, original := range originals {
			actual, err := os.ReadFile(filepath.Join(agent, name))
			if err != nil || !bytes.Equal(actual, original) {
				t.Errorf("application %s changed", name)
			}
		}
	}()
	target := BuildTarget{OS: "linux", Arch: "amd64", BeaconcryptBackend: "wasm"}
	if value := os.Getenv("POSEIDON_TEST_WASM_OS"); value != "" {
		target.OS = value
	}
	if value := os.Getenv("POSEIDON_TEST_WASM_ARCH"); value != "" {
		target.Arch = value
	}
	environment, err := prepareBeaconcryptBuild(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	environment = append(environment, "CGO_ENABLED=1", "GOOS="+target.OS, "GOARCH="+target.Arch)
	if target.OS == "darwin" {
		cc, cxx := darwinBuildCompilers(target.Arch)
		environment = append(environment, "CC="+cc, "CXX="+cxx)
	}
	if configPath := os.Getenv("POSEIDON_TEST_WASM_BUILD_CONFIG"); configPath != "" {
		config, err := json.MarshalIndent(map[string]interface{}{"agent_directory": agent, "environment": environment, "tags": "http,beaconcrypt,beaconcrypt_wazero"}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(configPath, config, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("POSEIDON_TEST_WASM_PREPARE_ONLY") == "1" {
		return
	}
	output := filepath.Join(project, ".build", fmt.Sprintf("poseidon-wasm-%s-%s", target.OS, target.Arch))
	command := exec.Command("go", "build", "-tags=http,beaconcrypt,beaconcrypt_wazero", "-o", output, ".")
	command.Dir = agent
	command.Env = append(os.Environ(), environment...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("agent compile: %v\n%s", err, output)
	}
	t.Logf("compiled unchanged agent to %s", output)
	command = exec.Command("go", "test", "-tags=beaconcrypt,beaconcrypt_wazero", "./pkg/cryptoprovider")
	command.Dir = agent
	command.Env = append(os.Environ(), environment...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("provider test: %v\n%s", err, output)
	}
}
