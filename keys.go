package umbra

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// GenerateKey creates a new ECDSA key pair using the specified curve.
// If curve is nil, P256 will be used by default.
func GenerateKey(curve elliptic.Curve) (*ecdsa.PrivateKey, error) {
	if curve == nil {
		curve = elliptic.P256()
	}
	return ecdsa.GenerateKey(curve, rand.Reader)
}

// EncodePrivateKey encodes a private key to PEM format.
func EncodePrivateKey(key *ecdsa.PrivateKey) (string, error) {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// DecodePrivateKey decodes a private key from PEM format.
func DecodePrivateKey(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	return x509.ParseECPrivateKey(block.Bytes)
}

// EncodePublicKey encodes a public key to PEM format.
func EncodePublicKey(key *ecdsa.PublicKey) (string, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: keyBytes,
	}
	return string(pem.EncodeToMemory(block)), nil
}

// DecodePublicKey decodes a public key from PEM format.
func DecodePublicKey(pemData string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecPub, nil
}

// deriveKey is a helper function that uses HKDF to derive a key of keySize bytes
// from the secret using the provided salt and info parameters.
func deriveKey(secret, salt, info []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, secret, salt, info)
	key := make([]byte, keySize)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}
	return key, nil
}
