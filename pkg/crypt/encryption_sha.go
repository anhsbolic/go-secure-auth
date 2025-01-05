package crypt

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
)

// ComputeSHA256 generates SHA-256 hash for a given input
func ComputeSHA256(text string) string {
	hash := sha256.Sum256([]byte(text))
	return hex.EncodeToString(hash[:])
}

// ComputeSHA512 generates SHA-512 hash for a given input
func ComputeSHA512(text string) string {
	hash := sha512.Sum512([]byte(text))
	return hex.EncodeToString(hash[:])
}
