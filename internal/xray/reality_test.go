package xray_test

import (
	"testing"

	"github.com/imzyb/MiGate/internal/xray"
)

func TestGenerateRealityKeyGeneratesValidKeyPair(t *testing.T) {
	privateKey, publicKey, err := xray.GenerateRealityKey()
	if err != nil {
		t.Fatalf("generate reality key: %v", err)
	}
	if len(privateKey) == 0 {
		t.Fatal("expected non-empty private key")
	}
	if len(publicKey) == 0 {
		t.Fatal("expected non-empty public key")
	}
	if len(privateKey) != 43 {
		t.Fatalf("expected 43-char base64 private key, got %d chars: %q", len(privateKey), privateKey)
	}
	if len(publicKey) != 43 {
		t.Fatalf("expected 43-char base64 public key, got %d chars: %q", len(publicKey), publicKey)
	}
}
