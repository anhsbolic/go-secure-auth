package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"
)

func generateNonce(gcm cipher.AEAD) ([]byte, error) {
	nonce := make([]byte, gcm.NonceSize())

	// First 8 bytes: timestamp
	timestamp := uint64(time.Now().UnixNano())
	if len(nonce) >= 8 {
		binary.BigEndian.PutUint64(nonce[:8], timestamp)
	}

	// Remaining bytes: random
	if len(nonce) > 8 {
		if _, err := io.ReadFull(rand.Reader, nonce[8:]); err != nil {
			return nil, fmt.Errorf("failed to generate random part of nonce: %w", err)
		}
	}
	return nonce, nil
}

// EncryptAESGCM encrypts plaintext using AES-GCM, and key must be 32 bytes for AES-256
func EncryptAESGCM(key string, plaintext string) ([]byte, error) {
	// Check Key
	if key == "" {
		return nil, fmt.Errorf("key is empty")
	}

	// Check Plaintext
	if plaintext == "" {
		return nil, fmt.Errorf("plaintext is empty")
	}

	// Create AES cipher block
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM mode instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Generate a unique nonce
	nonce, err := generateNonce(gcm)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt plaintext and append nonce to the ciphertext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return ciphertext, nil
}

// DecryptAESGCM decrypts ciphertext using AES-GCM, and key must be 32 bytes for AES-256
func DecryptAESGCM(key string, ciphertext []byte) (string, error) {
	// Check Key
	if key == "" {
		return "", fmt.Errorf("key is empty")
	}

	// Check Encrypted Text
	if len(ciphertext) == 0 {
		return "", fmt.Errorf("encrypted text is empty")
	}

	// Create AES cipher block
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	// Create GCM mode instance
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM mode: %w", err)
	}

	// Extract nonce and actual ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	return string(plaintext), nil
}
