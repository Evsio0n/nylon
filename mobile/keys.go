package mobile

import (
	"encoding/base64"
	"fmt"

	"github.com/encodeous/nylon/state"
)

// GeneratePrivateKey generates a new nylon private key, returns base64-encoded string.
func GeneratePrivateKey() string {
	key := state.GenerateKey()
	return base64.StdEncoding.EncodeToString(key[:])
}

// PublicKeyFromPrivate derives the public key from a base64 private key, returns base64.
func PublicKeyFromPrivate(privateKeyB64 string) (string, error) {
	bytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}
	if len(bytes) != 32 {
		return "", fmt.Errorf("expected 32 bytes, got %d", len(bytes))
	}
	var key state.NyPrivateKey
	copy(key[:], bytes)
	pub := key.Pubkey()
	return base64.StdEncoding.EncodeToString(pub[:]), nil
}
