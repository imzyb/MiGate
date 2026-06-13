package xray

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// DeriveRealityPublicKey derives the REALITY public key from a private key using xray x25519 -i.
func DeriveRealityPublicKey(privateKey string) (string, error) {
	if publicKey, err := deriveRealityPublicKeyLocal(privateKey); err == nil {
		return publicKey, nil
	}
	cmd := exec.Command("xray", "x25519", "-i", privateKey)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("xray x25519 -i: %w", err)
	}
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Password (PublicKey):") {
			return strings.TrimSpace(strings.TrimPrefix(line, "Password (PublicKey):")), nil
		}
	}
	return "", fmt.Errorf("could not parse xray x25519 -i output: %s", out.String())
}

// GenerateRealityKey generates a REALITY X25519 key pair using xray x25519.
// Returns the private key and public key on success.
func GenerateRealityKey() (privateKey, publicKey string, err error) {
	cmd := exec.Command("xray", "x25519")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err == nil {
		for _, line := range strings.Split(out.String(), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "PrivateKey:") {
				privateKey = strings.TrimSpace(strings.TrimPrefix(line, "PrivateKey:"))
			} else if strings.HasPrefix(line, "Password (PublicKey):") {
				publicKey = strings.TrimSpace(strings.TrimPrefix(line, "Password (PublicKey):"))
			}
		}
		if privateKey != "" && publicKey == "" {
			publicKey, _ = deriveRealityPublicKeyLocal(privateKey)
		}
		if privateKey != "" && publicKey != "" {
			return privateKey, publicKey, nil
		}
	}

	return generateRealityKeyLocal()
}

func generateRealityKeyLocal() (privateKey, publicKey string, err error) {
	privateBytes := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateBytes); err != nil {
		return "", "", fmt.Errorf("generate x25519 private key: %w", err)
	}
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return "", "", fmt.Errorf("derive x25519 public key: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(privateBytes), base64.RawURLEncoding.EncodeToString(publicBytes), nil
}

func deriveRealityPublicKeyLocal(privateKey string) (string, error) {
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateKey)
	if err != nil {
		return "", err
	}
	if len(privateBytes) != curve25519.ScalarSize {
		return "", fmt.Errorf("invalid x25519 private key length: %d", len(privateBytes))
	}
	publicBytes, err := curve25519.X25519(privateBytes, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(publicBytes), nil
}
