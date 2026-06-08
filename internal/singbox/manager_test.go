package singbox

import (
	"strings"
	"testing"
)

func TestNormalizeVersionDropsTagsSuffix(t *testing.T) {
	raw := "sing-box version 1.13.13\nEnvironment: go1.25 linux/amd64\nTags: with_quic,with_gvisor\n"
	got := NormalizeVersion(raw)
	if got != "sing-box version 1.13.13" {
		t.Fatalf("expected first version line without Tags suffix, got %q", got)
	}
	if strings.Contains(got, "Tags:") {
		t.Fatalf("normalized version must not include Tags suffix: %q", got)
	}
}
