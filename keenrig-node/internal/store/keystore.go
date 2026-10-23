package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
)

// keystore mã hoá/giải mã secret bằng AES-256-GCM.
// Blob format: nonce(12B) || ciphertext. Unexported — chỉ store dùng.
type keystore struct {
	aead cipher.AEAD
}

const masterKeySize = 32 // AES-256

// loadOrCreateMasterKey đọc master key 32 byte từ path; nếu file chưa tồn tại
// thì sinh mới bằng crypto/rand và ghi với perm 0600 (tự MkdirAll thư mục cha).
func loadOrCreateMasterKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != masterKeySize {
			return nil, fmt.Errorf("store: master key %s is %d bytes, exactly %d bytes are required", path, len(key), masterKeySize)
		}
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("store: reading the master key: %w", err)
	}
	key = make([]byte, masterKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("store: sinh master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("store: creating the master key directory: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("store: ghi master key: %w", err)
	}
	return key, nil
}

func newKeystore(key []byte) (*keystore, error) {
	if len(key) != masterKeySize {
		return nil, fmt.Errorf("store: keystore requires a %d-byte key, got %d", masterKeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &keystore{aead: aead}, nil
}

// seal mã hoá plaintext → nonce||ciphertext.
func (k *keystore) seal(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// open giải mã blob nonce||ciphertext.
func (k *keystore) open(blob []byte) ([]byte, error) {
	ns := k.aead.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("store: ciphertext blob is too short (%d bytes)", len(blob))
	}
	return k.aead.Open(nil, blob[:ns], blob[ns:], nil)
}
