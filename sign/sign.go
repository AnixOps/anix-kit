// Package sign is the AnixOps Ed25519 signing format, shared by every
// product that signs or verifies releases, packages, scripts or reports:
//
//   - public key: base64 (standard) of the 32 raw Ed25519 bytes; a PEM
//     SubjectPublicKeyInfo is accepted too;
//   - private key: PKCS#8 PEM ("PRIVATE KEY");
//   - signature: base64 (standard) of the 64 raw bytes over the exact
//     message bytes, detached; whitespace in it is ignored;
//   - key id: the first 16 hex characters of SHA-256 of the raw public key;
//   - digest: lowercase hex SHA-256.
//
// These formats are what deployed Agents and Controls verify with, so they
// only ever grow.
package sign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"strings"
)

var (
	// ErrKey means a key is not in the AnixOps format.
	ErrKey = errors.New("sign: not an Ed25519 key in the AnixOps format")
	// ErrSignature means a signature is malformed or does not match.
	ErrSignature = errors.New("sign: signature does not verify")
)

// GenerateKey returns a new key pair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// ParsePublicKey reads base64 raw bytes or a PEM public key.
func ParsePublicKey(encoded string) (ed25519.PublicKey, error) {
	encoded = strings.TrimSpace(encoded)
	if block, _ := pem.Decode([]byte(encoded)); block != nil {
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if pub, ok := key.(ed25519.PublicKey); err == nil && ok {
			return pub, nil
		}
		return nil, ErrKey
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrKey
	}
	return ed25519.PublicKey(raw), nil
}

// ParsePrivateKey reads a PKCS#8 PEM private key.
func ParsePrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, ErrKey
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if priv, ok := key.(ed25519.PrivateKey); err == nil && ok {
		return priv, nil
	}
	return nil, ErrKey
}

// MarshalPrivateKey encodes key as PKCS#8 PEM.
func MarshalPrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKey returns the base64 raw form of key.
func EncodePublicKey(key ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(key)
}

// KeyID returns the key's id: 16 hex characters of SHA-256 of the raw key.
func KeyID(key ed25519.PublicKey) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:8])
}

// Digest returns the lowercase hex SHA-256 of data.
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Sign returns the base64 detached signature of message.
func Sign(key ed25519.PrivateKey, message []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(key, message))
}

// Verify checks a base64 detached signature of message by key.
func Verify(key ed25519.PublicKey, message []byte, signature string) error {
	raw, err := base64.StdEncoding.DecodeString(string(bytes.Join(bytes.Fields([]byte(signature)), nil)))
	if err != nil || len(raw) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize {
		return ErrSignature
	}
	if !ed25519.Verify(key, message, raw) {
		return ErrSignature
	}
	return nil
}
