# Poseidon

<p align="center">
  <img alt="Poseidon Logo" src="documentation-payload/poseidon/poseidon.svg" height="30%" width="30%">
</p>

Poseidon is a Golang agent that compiles into Linux and macOS executables.
This Poseidon instance supports Mythic 3.0.0 and will be updated as necessary.
It does not support Mythic 2.3 and lower.

## Optional crypto providers

With Mythic's external crypto-provider API, select
`provider:<service>:<scheme>` in the HTTP or TCP profile's `AESPSK` parameter.
The builder selects the implementation's Go build tag and embeds its scheme
and opaque provider configuration into the profile's compile-time settings.

Implementations register a session factory from a build-tagged file in
`pkg/cryptoprovider`, alongside a provider-specific builder registration in
`poseidon/agentfunctions`. Adding a provider does not require transport changes.

Beaconcrypt supports Linux and macOS `AMD_x64` and `ARM_x64` executables
(`mode=default`) with one HTTP or TCP profile and `static` and `garble` disabled.
Choose **Native (beaconcrypt)** or **WASM (beaconcrypt)** in the C2 profile's
Encryption Type selector. Poseidon advertises the `Native` and `WASM` crypto
schemes; that single selection chooses the backend automatically. Their API
values are `provider:beaconcrypt:Native` and `provider:beaconcrypt:WASM`.
Both choices use the same agent imports, constructors and protocol. The
Beaconcrypt provider must advertise these aliases; the server uses the same
native engine and campaign identity for both client implementations.

The native backend uses SHA256-verified GitHub release libraries. Linux amd64
and arm64 payload containers include libraries for all four targets. The v0.6.0
macOS native archives require macOS 15.5 on Intel or macOS 26.5 on Apple Silicon;
the builder sets matching deployment targets. Manual native builds need Go,
curl and the target's C compiler; run
`Payload_Type/poseidon/scripts/build-native.sh` with `linux amd64`,
`linux arm64`, `darwin amd64`, or `darwin arm64`. Rust and Cap'n Proto are not
required. Target archives are kept separately under
`POSEIDON_BEACONCRYPT_NATIVE_TARGET` (default `.build/beaconcrypt-native-target`).
Pins live in `scripts/beaconcrypt-releases.txt`; verified cached archives work
offline. For native macOS builds the builder copies the binding into a private
module directory and adds the target library there. The original Go module
cache is not edited. When manually replacing a native archive at the same
module version, clear Go's build cache once so Go relinks it.

The WASM backend embeds Beaconcrypt's prebuilt WASM in the executable and runs
it with wazero. Builds require Go 1.25 or later, and need no Beaconcrypt native
archive or Rust toolchain.
Poseidon's other dependencies still use CGO, so this choice keeps CGO enabled
and adds `beaconcrypt_wazero` to the build tags. It removes the native archive's
macOS deployment minimum; the Go toolchain, wazero and Poseidon's other
libraries still determine supported operating system versions. An older macOS
runtime has not been tested by this integration.

The builder downloads a complete Beaconcrypt Go module bundle, validates its
pinned archive SHA256, manifest and source hashes, and stages it outside the Go
module cache under `POSEIDON_BEACONCRYPT_WASM_TARGET` (default
`.build/beaconcrypt-wasm`). A separate modfile for each build selects that module.
The agent's Go sources, `go.mod` and `go.sum` stay unchanged. Downloads happen
only while building; the resulting agent needs no external WASM file or runtime
download. Future released bundle pins belong in
`scripts/beaconcrypt-wasm-releases.txt`. That file currently has no published
pins, so select an explicit local development bundle to test this feature:

```sh
export POSEIDON_BEACONCRYPT_WASM_BUNDLE=/absolute/path/beaconcrypt-go-v0.6.0-wasm.tar.gz
export POSEIDON_BEACONCRYPT_WASM_SHA256=<independently-verified-archive-sha256>
```

The bundle's version must match the agent's required Beaconcrypt module version.
A local path always requires its SHA256; it does not fall back to a download if
the file is missing or invalid. The local development v0.6.0 bundle is distinct
from the existing native-only v0.6.0 release and must not be published over it.

Container builds can optionally bake a bundle with
`BEACONCRYPT_WASM_BUNDLE_URL`, `BEACONCRYPT_WASM_BUNDLE_SHA256` and
`BEACONCRYPT_WASM_BUNDLE_VERSION`. Supply all three build arguments together.
The URL must use HTTPS and the archive is checked before it is included. With
these arguments omitted, the native container behavior remains the default;
a future pinned release can be downloaded when a WASM build is requested.
Set local bundle environment variables in the payload container, not on the
agent's target machine.

Run `python3 scripts/test_stage_wasm.py` and
`go test ./poseidon/agentfunctions` from `Payload_Type/poseidon` to check bundle
validation and build configuration. To compile the unchanged HTTP agent and
run its provider tests against a local bundle, set the two bundle variables
above and run:

```sh
POSEIDON_TEST_WASM_BUILD=1 go test -v -count=1 \
  -run '^TestBeaconcryptWasmLocalBundleBuild$' ./poseidon/agentfunctions
```

Beaconcrypt includes generated EverCBOR code under Apache-2.0. Include the
[Beaconcrypt notices](Payload_Type/poseidon/licenses/Beaconcrypt-NOTICE.txt)
and accompanying license texts when redistributing Beaconcrypt-enabled agents.

## Poseidon's Icon

poseidon's icon made by Eucalyp from www.flaticon.com

## How to install an agent in this format within Mythic

When it's time for you to test out your install or for another user to install your agent, it's pretty simple. Within Mythic you can run the `mythic-cli` binary to install this in one of three ways:

* `sudo ./mythic-cli install github https://github.com/user/repo` to install the main branch
* `sudo ./mythic-cli install github https://github.com/user/repo branchname` to install a specific branch of that repo
* `sudo ./mythic-cli install folder /path/to/local/folder/cloned/from/github` to install from an already cloned down version of an agent repo

Now, you might be wondering _when_ should you or a user do this to properly add your agent to their Mythic instance. There's no wrong answer here, just depends on your preference. The three options are:

* Mythic is already up and going, then you can run the install script and just direct that agent's containers to start (i.e. `sudo ./mythic-cli start agentName` and if that agent has its own special C2 containers, you'll need to start them too via `sudo ./mythic-cli start c2profileName`).
* Mythic is already up and going, but you want to minimize your steps, you can just install the agent and run `sudo ./mythic-cli start`. That script will first _stop_ all of your containers, then start everything back up again. This will also bring in the new agent you just installed.
* Mythic isn't running, you can install the script and just run `sudo ./mythic-cli start`. 

## Documentation

The Poseidon documentation source code can be found in the `documenation-payload/poseidon` directory.
View the rendered documentation by clicking on **Docs -> Agent Documentation** in the upper right-hand corner of the Mythic
interface. 

## Building Outside of Mythic

If you want to build outside of Mythic, you can use the `Makefile` included in the project's `agent_code` directory. You will need to modify the variables at the top of the Makefile to match the C2 profile information you want to build into your agent. To get all the pieces you need (like UUID and AES key), you need to build the agent within Mythic (or at least kick off an unsuccessful build), then copy that information. To find the information you need, simply go to the Payloads page and click the blue info icon. You'll see the UUID, encryption key, and any other information you need for building to put into your Makefile.
