package credentialvault

import (
	"bytes"
	"testing"
)

func TestVaultBindsCiphertextToPurpose(t *testing.T) {
	vault, err := New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, nonce, err := vault.Seal([]byte("operator:secret"), []byte("dictionary:tenant-a:dict-1:1"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := vault.Open(ciphertext, nonce, []byte("dictionary:tenant-a:dict-1:1"))
	if err != nil || string(plaintext) != "operator:secret" {
		t.Fatalf("round trip = %q, %v", plaintext, err)
	}
	if _, err := vault.Open(ciphertext, nonce, []byte("bundle:tenant-a:attempt-1")); err == nil {
		t.Fatal("ciphertext opened with a different purpose")
	}
}
