//go:build (linux || darwin) && tcp

package profiles

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestTCPProviderConfigIsAnOpaqueString(t *testing.T) {
	var config TCPInitialConfig
	if err := json.Unmarshal([]byte(`{"crypto_provider":"alternate","crypto_provider_config":"opaque-material","port":4444}`), &config); err != nil {
		t.Fatal(err)
	}
	if config.CryptoProvider != "alternate" || config.CryptoProviderConfig != "opaque-material" || config.Port != 4444 {
		t.Fatalf("TCP config changed provider material: %+v", config)
	}
	if err := json.Unmarshal([]byte(`{"crypto_provider_config":17}`), &config); err == nil {
		t.Fatal("non-string provider configuration accepted")
	}
	if err := json.Unmarshal([]byte(`{"crypto_provider":17}`), &config); err == nil {
		t.Fatal("non-string provider name accepted")
	}
}

func TestTCPFramingPreservesMultiChunkProviderFrames(t *testing.T) {
	writer, reader := net.Pipe()
	defer writer.Close()
	defer reader.Close()
	_ = writer.SetDeadline(time.Now().Add(5 * time.Second))
	_ = reader.SetDeadline(time.Now().Add(5 * time.Second))
	profile := &C2PoseidonTCP{chunkSize: 30000}
	frame := bytes.Repeat([]byte("base64-provider-frame"), 4000)
	written := make(chan error, 1)
	go func() { written <- profile.ChunkAndWriteData(writer, frame) }()
	actual, err := profile.ReadAndChunkData(reader)
	if err != nil || !bytes.Equal(actual, frame) {
		t.Fatalf("TCP frame changed across chunks: got=%d want=%d error=%v", len(actual), len(frame), err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
}

func TestTCPFramingRejectsPartialAndUnderflowChunks(t *testing.T) {
	for _, test := range []struct {
		name string
		wire []byte
	}{
		{name: "truncated data", wire: append(tcpTestWords(11, 1, 0), 'a', 'b')},
		{name: "size underflow", wire: tcpTestWords(7)},
	} {
		t.Run(test.name, func(t *testing.T) {
			writer, reader := net.Pipe()
			defer reader.Close()
			_ = reader.SetDeadline(time.Now().Add(5 * time.Second))
			go func() {
				_, _ = writer.Write(test.wire)
				_ = writer.Close()
			}()
			if frame, err := (&C2PoseidonTCP{}).ReadAndChunkData(reader); err == nil {
				t.Fatalf("incomplete TCP frame returned as complete: %q", frame)
			}
		})
	}
}

func tcpTestWords(words ...uint32) []byte {
	wire := make([]byte, 4*len(words))
	for index, word := range words {
		binary.BigEndian.PutUint32(wire[4*index:], word)
	}
	return wire
}
