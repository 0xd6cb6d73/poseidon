//go:build beaconcrypt && (linux || darwin) && (amd64 || arm64)

package cryptoprovider

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	beaconcrypt "github.com/0xd6cb6d73/beaconcrypt"
)

type beaconcryptMaterial struct {
	Version         int    `json:"version"`
	ServerKID       string `json:"server_kid"`
	ServerPublicKey []byte `json:"server_public_key"`
}

func init() {
	if err := RegisterAvailableProvider("beaconcrypt", newBeaconcrypt); err != nil {
		panic(err)
	}
}

// newBeaconcrypt consumes the unmodified, base64 provider_config projected by
// Mythic. The server identity is pinned, never learned from the network.
func newBeaconcrypt(encoded, payloadUUID string) (Session, error) {
	if !canonicalUUID(payloadUUID) {
		return nil, errors.New("invalid payload UUID")
	}
	if len(encoded) > 64<<10 {
		return nil, errors.New("provider configuration is too large")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode provider configuration: %w", err)
	}
	var config beaconcryptMaterial
	if err = json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("parse provider configuration: %w", err)
	}
	kid, err := strconv.ParseUint(config.ServerKID, 10, 64)
	if err != nil || strconv.FormatUint(kid, 10) != config.ServerKID || config.Version != 1 || len(config.ServerPublicKey) != 32 {
		return nil, errors.New("invalid Beaconcrypt provider configuration")
	}
	native, err := beaconcrypt.NewBeacon(kid, config.ServerPublicKey)
	if err != nil {
		return nil, err
	}
	return newBeaconcryptSession(native, payloadUUID)
}
