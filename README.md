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

Beaconcrypt v0.6.0 supports Linux and macOS `AMD_x64` and `ARM_x64` executables
(`mode=default`) with one HTTP or TCP profile and `static` and `garble` disabled.
Linux amd64 and arm64 payload containers include matching, SHA256-verified GitHub
release libraries for all four targets. The macOS release archives require
macOS 15.5 on Intel or macOS 26.5 on Apple Silicon; the builder sets matching
deployment targets. Manual builds need a Linux builder with Go, curl and the
target's C compiler; run `Payload_Type/poseidon/scripts/build-native.sh` with
`linux amd64`, `linux arm64`, `darwin amd64`, or `darwin arm64`.
Native archives use separate Rust-target subdirectories under
`POSEIDON_BEACONCRYPT_NATIVE_TARGET` (default `.build/beaconcrypt-native-target`),
so one target cannot reuse the other's cached library. Release filenames and
digests are pinned in `scripts/beaconcrypt-releases.txt` alongside the helper;
module version changes require a matching manifest entry. Verified cached archives
work offline. Rust and Cap'n Proto are not required. When replacing a source-built
archive at the same module version, clear Go's build cache once (`go clean -cache`)
so manual builds relink the downloaded library.

The v0.6.0 Go binding names its macOS archive inside the Go module. For macOS
builds, the preparation hook stages an unchanged copy of the module and the
verified target library under `.build/beaconcrypt-go-module`, then selects it
with a private Go modfile. This keeps both architectures separate without
editing the shared Go module cache. Manual macOS cross-builds must likewise
make the matching archive available at the binding's `target/release` path.
The deployment minimum is passed directly to the linker, allowing the existing
osxcross SDK to compile the C bindings while marking the final executable with
the native library's required macOS version.

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
