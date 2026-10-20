FROM --platform=$BUILDPLATFORM golang:1.27.2-bookworm AS beaconcrypt-native
RUN apt-get update && apt-get install --yes --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY poseidon/agent_code/go.mod poseidon/agent_code/go.sum ./poseidon/agent_code/
COPY scripts ./scripts
RUN ./scripts/build-native.sh linux amd64 && \
    ./scripts/build-native.sh linux arm64 && \
    ./scripts/build-native.sh darwin amd64 && \
    ./scripts/build-native.sh darwin arm64 && \
    cp -a .build/beaconcrypt-native-target /out

FROM beaconcrypt-native AS beaconcrypt-wasm
ARG BEACONCRYPT_WASM_BUNDLE_URL=""
ARG BEACONCRYPT_WASM_BUNDLE_SHA256=""
ARG BEACONCRYPT_WASM_BUNDLE_VERSION=""
RUN apt-get update && apt-get install --yes --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /wasm-out/cache && \
    if [ -n "$BEACONCRYPT_WASM_BUNDLE_URL" ]; then \
      test -n "$BEACONCRYPT_WASM_BUNDLE_SHA256" && test -n "$BEACONCRYPT_WASM_BUNDLE_VERSION" && \
      curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' \
        --output /wasm-out/bundle.tar.gz "$BEACONCRYPT_WASM_BUNDLE_URL" && \
      python3 scripts/stage-wasm.py --version "$BEACONCRYPT_WASM_BUNDLE_VERSION" \
        --bundle /wasm-out/bundle.tar.gz --sha256 "$BEACONCRYPT_WASM_BUNDLE_SHA256" \
        --cache-dir /wasm-out/cache > /wasm-out/staged.json; \
    else \
      test -z "$BEACONCRYPT_WASM_BUNDLE_SHA256$BEACONCRYPT_WASM_BUNDLE_VERSION"; \
    fi

FROM itsafeaturemythic/mythic_go_macos:latest

ARG TARGETARCH
ARG BEACONCRYPT_WASM_BUNDLE_SHA256=""

RUN chmod +x /go/bin/garble
RUN garble version

WORKDIR /

RUN if [ "$TARGETARCH" = "arm64" ]; then \
    echo "Installing ARM-specific packages" && \
    # Add your ARM-specific commands here; \
    wget https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F0.29.0/apple-codesign-0.29.0-aarch64-unknown-linux-musl.tar.gz && \
    gunzip apple-codesign-0.29.0-aarch64-unknown-linux-musl.tar.gz && \
    tar -xvf apple-codesign-0.29.0-aarch64-unknown-linux-musl.tar && \
    mv apple-codesign-0.29.0-aarch64-unknown-linux-musl/rcodesign /rcodesign && \
    chmod +x /rcodesign; \
    elif [ "$TARGETARCH" = "amd64" ]; then \
    echo "Installing AMD-specific packages" && \
    # Add your AMD-specific commands here; \
    wget -o /rcodesign.tar.gz https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F0.29.0/apple-codesign-0.29.0-x86_64-unknown-linux-musl.tar.gz && \
    gunzip apple-codesign-0.29.0-x86_64-unknown-linux-musl.tar.gz && \
    tar -xvf apple-codesign-0.29.0-x86_64-unknown-linux-musl.tar && \
    mv apple-codesign-0.29.0-x86_64-unknown-linux-musl/rcodesign /rcodesign && \
    chmod +x /rcodesign; \
    fi

WORKDIR /Mythic/

COPY [".", "."]
COPY --from=beaconcrypt-native /out/ /opt/poseidon/beaconcrypt-native-target/
COPY --from=beaconcrypt-wasm /wasm-out/ /opt/poseidon/beaconcrypt-wasm/
ENV POSEIDON_BEACONCRYPT_NATIVE_TARGET=/opt/poseidon/beaconcrypt-native-target
ENV POSEIDON_BEACONCRYPT_WASM_TARGET=/opt/poseidon/beaconcrypt-wasm/cache
ENV POSEIDON_BEACONCRYPT_WASM_BUNDLE=${BEACONCRYPT_WASM_BUNDLE_SHA256:+/opt/poseidon/beaconcrypt-wasm/bundle.tar.gz}
ENV POSEIDON_BEACONCRYPT_WASM_SHA256=$BEACONCRYPT_WASM_BUNDLE_SHA256

RUN make build

RUN apt-get update && apt-get install --yes --no-install-recommends \
    python3 g++-x86-64-linux-gnu libc6-dev-amd64-cross \
    g++-aarch64-linux-gnu libc6-dev-arm64-cross \
    && rm -rf /var/lib/apt/lists/*

CMD make run
