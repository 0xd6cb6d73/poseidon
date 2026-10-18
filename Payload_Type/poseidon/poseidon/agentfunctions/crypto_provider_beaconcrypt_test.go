package agentfunctions

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	agentstructs "github.com/MythicMeta/MythicContainer/agent_structs"
)

func beaconcryptBuildFixture() agentstructs.PayloadBuildMessage {
	return agentstructs.PayloadBuildMessage{
		SelectedOS: agentstructs.SUPPORTED_OS_LINUX,
		BuildParameters: agentstructs.BuildParameters{Parameters: map[string]interface{}{
			"architecture": "AMD_x64", "mode": "default", "static": false, "garble": false,
		}},
		C2Profiles: []agentstructs.PayloadBuildC2Profile{{
			Name: "http",
			Parameters: map[string]interface{}{
				"AESPSK": map[string]interface{}{
					"value":           "provider:mythic-beaconcrypt:beaconcrypt",
					"enc_key":         nil,
					"dec_key":         nil,
					"provider_config": base64.StdEncoding.EncodeToString([]byte(`{ "version": 1, "server_kid": "0", "server_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" }`)),
				},
			},
		}},
	}
}

func TestBeaconcryptBuildAcceptsMythicProjection(t *testing.T) {
	message := beaconcryptBuildFixture()
	// Exercise the actual JSON boundary rather than a Go-only map shape.
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded agentstructs.PayloadBuildMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	managed, err := validateProviderBuild(decoded)
	if err != nil || len(managed) != 1 {
		t.Fatalf("provider build rejected: managed=%v error=%v", managed, err)
	}
	argument, err := decodeProviderCryptoArg(decoded.C2Profiles[0].Parameters["AESPSK"])
	if err != nil {
		t.Fatal(err)
	}
	original := message.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["provider_config"]
	if argument.ProviderConfig != original {
		t.Fatal("provider config changed while crossing the builder JSON boundary")
	}
}

func TestBeaconcryptBuildAcceptsP2PTCP(t *testing.T) {
	message := beaconcryptBuildFixture()
	message.C2Profiles[0].Name = "tcp"
	message.C2Profiles[0].IsP2P = true
	encoded, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	var decoded agentstructs.PayloadBuildMessage
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	managed, err := validateProviderBuild(decoded)
	if err != nil || len(managed) != 1 {
		t.Fatalf("P2P TCP provider build rejected: managed=%v error=%v", managed, err)
	}
	decoded.C2Profiles[0].IsP2P = false
	if managed, err := validateProviderBuild(decoded); len(managed) != 0 || err == nil {
		t.Fatal("direct TCP provider profile accepted")
	}
}

func TestBeaconcryptBuildRejectsUnsupportedAndMissingConfiguration(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*agentstructs.PayloadBuildMessage)
		want   string
	}{
		{"missing config", func(m *agentstructs.PayloadBuildMessage) {
			delete(m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{}), "provider_config")
		}, "supplied by Mythic"},
		{"invalid base64", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["provider_config"] = "%%%"
		}, "supplied by Mythic"},
		{"oversized config", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["provider_config"] = strings.Repeat("A", 64*1024+1)
		}, "64 KiB agent limit"},
		{"wrong public key size", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["provider_config"] = base64.StdEncoding.EncodeToString([]byte(`{"version":1,"server_kid":"0","server_public_key":"AA=="}`))
		}, "v1 server identity"},
		{"unknown version", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["provider_config"] = base64.StdEncoding.EncodeToString([]byte(`{"version":2,"server_kid":"0","server_public_key":"AA=="}`))
		}, "v1 server identity"},
		{"noncanonical kid", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["provider_config"] = base64.StdEncoding.EncodeToString([]byte(`{"version":1,"server_kid":"00","server_public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
		}, "v1 server identity"},
		{"unknown scheme", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["value"] = "provider:another:unknown"
		}, "unsupported crypto provider"},
		{"empty service", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles[0].Parameters["AESPSK"].(map[string]interface{})["value"] = "provider::beaconcrypt"
		}, "unsupported crypto provider"},
		{"multiple profiles", func(m *agentstructs.PayloadBuildMessage) {
			m.C2Profiles = append(m.C2Profiles, agentstructs.PayloadBuildC2Profile{Name: "http"})
		}, "exactly one direct HTTP"},
		{"p2p", func(m *agentstructs.PayloadBuildMessage) { m.C2Profiles[0].IsP2P = true }, "exactly one direct HTTP"},
		{"push transport", func(m *agentstructs.PayloadBuildMessage) { m.C2Profiles[0].Name = "websocket" }, "exactly one direct HTTP"},
		{"unsupported operating system", func(m *agentstructs.PayloadBuildMessage) { m.SelectedOS = agentstructs.SUPPORTED_OS_WINDOWS }, "Linux or macOS AMD_x64"},
		{"unsupported architecture", func(m *agentstructs.PayloadBuildMessage) { m.BuildParameters.Parameters["architecture"] = "386" }, "Linux or macOS AMD_x64 or ARM_x64"},
		{"shared library", func(m *agentstructs.PayloadBuildMessage) { m.BuildParameters.Parameters["mode"] = "c-shared" }, "Linux or macOS AMD_x64"},
		{"static", func(m *agentstructs.PayloadBuildMessage) { m.BuildParameters.Parameters["static"] = true }, "Linux or macOS AMD_x64"},
		{"garble", func(m *agentstructs.PayloadBuildMessage) { m.BuildParameters.Parameters["garble"] = true }, "Linux or macOS AMD_x64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			message := beaconcryptBuildFixture()
			test.change(&message)
			managed, err := validateProviderBuild(message)
			if len(managed) != 0 || err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("managed=%v error=%v; expected %q", managed, err, test.want)
			}
		})
	}
}

func TestBeaconcryptBuildPreservesLegacyTargets(t *testing.T) {
	for _, selection := range []string{"aes256_hmac", "none", ""} {
		message := beaconcryptBuildFixture()
		message.SelectedOS = agentstructs.SUPPORTED_OS_MACOS
		message.C2Profiles[0].Name = "websocket"
		message.BuildParameters.Parameters["garble"] = true
		message.C2Profiles[0].Parameters["AESPSK"] = map[string]interface{}{"value": selection, "enc_key": "legacy-key", "dec_key": "legacy-key"}
		managed, err := validateProviderBuild(message)
		if err != nil || len(managed) != 0 {
			t.Fatalf("legacy %q changed: managed=%v error=%v", selection, managed, err)
		}
	}
}

func TestBeaconcryptBuildAcceptsSupportedTargets(t *testing.T) {
	for _, selectedOS := range []string{agentstructs.SUPPORTED_OS_LINUX, agentstructs.SUPPORTED_OS_MACOS} {
		for _, architecture := range []string{"AMD_x64", "ARM_x64"} {
			for _, profile := range []string{"http", "tcp"} {
				t.Run(selectedOS+"/"+architecture+"/"+profile, func(t *testing.T) {
					message := beaconcryptBuildFixture()
					message.SelectedOS = selectedOS
					message.BuildParameters.Parameters["architecture"] = architecture
					message.C2Profiles[0].Name = profile
					message.C2Profiles[0].IsP2P = profile == "tcp"
					selections, err := validateProviderBuild(message)
					if err != nil || len(selections) != 1 {
						t.Fatalf("%s %s %s build rejected: selections=%v error=%v", selectedOS, architecture, profile, selections, err)
					}
				})
			}
		}
	}
}

func TestBeaconcryptNativeLibraryDirectory(t *testing.T) {
	for _, test := range []struct {
		name      string
		cacheRoot string
		target    BuildTarget
		want      string
		wantError string
	}{
		{name: "host amd64", target: BuildTarget{OS: "linux", Arch: "amd64"}, want: ".build/beaconcrypt-native-target/x86_64-unknown-linux-gnu/release"},
		{name: "host arm64", target: BuildTarget{OS: "linux", Arch: "arm64"}, want: ".build/beaconcrypt-native-target/aarch64-unknown-linux-gnu/release"},
		{name: "container amd64", cacheRoot: "/opt/poseidon/beaconcrypt-native-target", target: BuildTarget{OS: "linux", Arch: "amd64"}, want: "/opt/poseidon/beaconcrypt-native-target/x86_64-unknown-linux-gnu/release"},
		{name: "container arm64", cacheRoot: "/opt/poseidon/beaconcrypt-native-target", target: BuildTarget{OS: "linux", Arch: "arm64"}, want: "/opt/poseidon/beaconcrypt-native-target/aarch64-unknown-linux-gnu/release"},
		{name: "macOS amd64", target: BuildTarget{OS: "darwin", Arch: "amd64"}, want: ".build/beaconcrypt-native-target/x86_64-apple-darwin/release"},
		{name: "macOS arm64", cacheRoot: "/opt/poseidon/beaconcrypt-native-target", target: BuildTarget{OS: "darwin", Arch: "arm64"}, want: "/opt/poseidon/beaconcrypt-native-target/aarch64-apple-darwin/release"},
		{name: "relative override", cacheRoot: "native-target", target: BuildTarget{OS: "linux", Arch: "arm64"}, wantError: "must be an absolute path"},
		{name: "unsupported architecture", target: BuildTarget{OS: "linux", Arch: "386"}, wantError: "unsupported Beaconcrypt native target linux/386"},
		{name: "unsupported operating system", target: BuildTarget{OS: "windows", Arch: "arm64"}, wantError: "unsupported Beaconcrypt native target windows/arm64"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("POSEIDON_BEACONCRYPT_NATIVE_TARGET", test.cacheRoot)
			got, err := beaconcryptNativeLibraryDirectory(test.target)
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("native directory=%q error=%v; want %q", got, err, test.wantError)
				}
				return
			}
			want, pathErr := filepath.Abs(test.want)
			if err != nil || pathErr != nil || got != want {
				t.Fatalf("native library directory = %q, %v; want %q", got, err, want)
			}
		})
	}
}

func TestBeaconcryptPreparationUsesTheRequestedTarget(t *testing.T) {
	work := t.TempDir()
	t.Chdir(work)
	if err := os.Mkdir("scripts", 0700); err != nil {
		t.Fatal(err)
	}
	// Stand in for native compilation and require the preparation hook to pass
	// the payload target, rather than substituting the build host architecture.
	script := []byte(`set -eu
[ "$1/$2" = "$POSEIDON_TEST_EXPECTED_TARGET" ]
`)
	if err := os.WriteFile(filepath.Join("scripts", "build-native.sh"), script, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POSEIDON_BEACONCRYPT_NATIVE_TARGET", filepath.Join(work, "native"))
	t.Setenv("CGO_LDFLAGS", "-lexisting")
	for _, target := range []BuildTarget{{OS: "linux", Arch: "amd64"}, {OS: "linux", Arch: "arm64"}} {
		t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
			t.Setenv("POSEIDON_TEST_EXPECTED_TARGET", target.OS+"/"+target.Arch)
			env, err := prepareBeaconcryptBuild(context.Background(), target)
			directory, pathErr := beaconcryptNativeLibraryDirectory(target)
			if err != nil || pathErr != nil || len(env) != 1 || env[0] != "CGO_LDFLAGS=-L"+directory+" -lexisting" {
				t.Fatalf("target=%+v env=%v error=%v path_error=%v", target, env, err, pathErr)
			}
		})
	}
	if _, err := prepareBeaconcryptBuild(context.Background(), BuildTarget{OS: "linux", Arch: "386"}); err == nil || !strings.Contains(err.Error(), "unsupported Beaconcrypt native target") {
		t.Fatalf("unsupported target reached native compilation: %v", err)
	}
}

func TestSupportedCryptoSchemesDeclaration(t *testing.T) {
	declared := SupportedCryptoSchemes()
	if len(declared) != 1 || declared[0] != "beaconcrypt" {
		t.Fatalf("unexpected supported crypto schemes: %v", declared)
	}
	declared[0] = "changed"
	if SupportedCryptoSchemes()[0] != "beaconcrypt" {
		t.Fatal("caller mutated the payload declaration")
	}
}

func TestBeaconcryptDarwinPreparationKeepsModuleAndTargetsIsolated(t *testing.T) {
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	moduleDirectory := filepath.Join(work, "module")
	if err := os.MkdirAll(moduleDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("package beaconcrypt\n/*\n#cgo darwin LDFLAGS: ${SRCDIR}/target/release/libbeaconcrypt.a\n*/\nimport \"C\"\n")
	moduleSource := filepath.Join(moduleDirectory, "beaconcrypt.go")
	if err := os.WriteFile(moduleSource, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(work, "scripts"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "scripts", "build-native.sh"), []byte("exit 0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	agentDirectory := filepath.Join(work, "poseidon", "agent_code")
	if err := os.MkdirAll(agentDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	for path, contents := range map[string]string{
		filepath.Join(moduleDirectory, "go.mod"): "module github.com/0xd6cb6d73/beaconcrypt\n\ngo 1.24.0\n",
		filepath.Join(agentDirectory, "go.mod"):  "module fixture\n\ngo 1.24.0\n\nrequire github.com/0xd6cb6d73/beaconcrypt v0.6.0\n",
		filepath.Join(agentDirectory, "go.sum"):  "",
	} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	mockGo := filepath.Join(work, "go")
	moduleJSON, _ := json.Marshal(map[string]string{"Dir": moduleDirectory, "Version": "v0.6.0"})
	// Supply module discovery; the real Go tool resolves each staged replacement.
	if err := os.WriteFile(mockGo, []byte("#!/bin/sh\nprintf '%s\\n' \"$POSEIDON_TEST_MODULE\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("POSEIDON_TEST_MODULE", string(moduleJSON))
	t.Setenv("PATH", work+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("POSEIDON_BEACONCRYPT_NATIVE_TARGET", filepath.Join(work, "native"))
	t.Setenv("GOFLAGS", "-mod=readonly")
	t.Chdir(work)
	for _, test := range []struct{ arch, compiler, minimum string }{{"amd64", "o64-clang", "15.5"}, {"arm64", "oa64-clang", "26.5"}} {
		t.Run(test.arch, func(t *testing.T) {
			directory, err := beaconcryptNativeLibraryDirectory(BuildTarget{OS: "darwin", Arch: test.arch})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, "libbeaconcrypt.a"), []byte(test.arch), 0600); err != nil {
				t.Fatal(err)
			}
			env, err := prepareBeaconcryptBuild(context.Background(), BuildTarget{OS: "darwin", Arch: test.arch})
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(env, "\n")
			for _, want := range []string{"CC=" + test.compiler, "CXX=" + test.compiler + "++", "-Wl,-macosx_version_min," + test.minimum, "beaconcrypt-go-module/v0.6.0/" + test.arch} {
				if !strings.Contains(joined, want) {
					t.Fatalf("missing %q from prepared environment %v", want, env)
				}
			}
			if strings.Contains(joined, "CGO_CFLAGS=") || strings.Contains(joined, "OSXCROSS_OSX_VERSION_MIN=") {
				t.Fatalf("library deployment minimum was passed to the compiler wrapper: %v", env)
			}
			command := exec.Command(goBinary, "list", "-m", "-f", "{{.Dir}}", "github.com/0xd6cb6d73/beaconcrypt")
			command.Dir = agentDirectory
			command.Env = append(os.Environ(), env...)
			output, err := command.CombinedOutput()
			wantModule := filepath.Join(work, ".build", "beaconcrypt-go-module", "v0.6.0", test.arch, "module")
			if err != nil || strings.TrimSpace(string(output)) != wantModule {
				t.Fatalf("Go did not resolve target module: %s: %v", output, err)
			}
			library := filepath.Join(wantModule, "target", "release", "libbeaconcrypt.a")
			contents, err := os.ReadFile(library)
			if err != nil || string(contents) != test.arch {
				t.Fatalf("target library=%q error=%v", contents, err)
			}
			if err := os.WriteFile(library, []byte("damaged cache"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := prepareBeaconcryptBuild(context.Background(), BuildTarget{OS: "darwin", Arch: test.arch}); err != nil {
				t.Fatal(err)
			}
			if restored, err := os.ReadFile(library); err != nil || string(restored) != test.arch {
				t.Fatalf("damaged staged library was reused: %q: %v", restored, err)
			}
		})
	}
	contents, err := os.ReadFile(moduleSource)
	if err != nil || string(contents) != string(original) {
		t.Fatalf("preparation edited shared module source: %s: %v", contents, err)
	}
}
