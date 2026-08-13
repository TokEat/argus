package credentialvault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const EnvKey = "ARGUS_CREDENTIAL_ENCRYPT_KEY"

var developmentKey = []byte("argus-credential-dev-key-only!!!")

type Vault struct {
	aead cipher.AEAD
}

func NewFromEnvironment(allowDevelopmentFallback bool) (*Vault, error) {
	key, err := resolveKey(os.Getenv(EnvKey))
	if err != nil {
		if !allowDevelopmentFallback || !errors.Is(err, errMissingKey) {
			return nil, err
		}
		key = append([]byte(nil), developmentKey...)
	}
	return New(key)
}

func New(key []byte) (*Vault, error) {
	if len(key) != 32 {
		return nil, errors.New("credential encryption key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create credential cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create credential AEAD: %w", err)
	}
	return &Vault{aead: aead}, nil
}

func ValidateEnvironment() error {
	_, err := resolveKey(os.Getenv(EnvKey))
	return err
}

func (v *Vault) Seal(plaintext, associatedData []byte) (ciphertext, nonce []byte, err error) {
	if v == nil || v.aead == nil {
		return nil, nil, errors.New("credential vault is unavailable")
	}
	nonce = make([]byte, v.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate credential nonce: %w", err)
	}
	return v.aead.Seal(nil, nonce, plaintext, associatedData), nonce, nil
}

func (v *Vault) Open(ciphertext, nonce, associatedData []byte) ([]byte, error) {
	if v == nil || v.aead == nil {
		return nil, errors.New("credential vault is unavailable")
	}
	if len(nonce) != v.aead.NonceSize() {
		return nil, errors.New("invalid credential nonce")
	}
	plaintext, err := v.aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, errors.New("credential ciphertext authentication failed")
	}
	return plaintext, nil
}

var errMissingKey = errors.New("credential encryption key is missing")

func resolveKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("%w: %s is required in production", errMissingKey, EnvKey)
	}
	if decoded, err := base64.StdEncoding.DecodeString(raw); err == nil {
		if len(decoded) != 32 {
			return nil, fmt.Errorf("%s base64 must decode to 32 bytes", EnvKey)
		}
		return decoded, nil
	}
	if len(raw) == 32 {
		return []byte(raw), nil
	}
	return nil, fmt.Errorf("%s must be base64-encoded 32 bytes or 32 raw bytes", EnvKey)
}
