package architecture_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Clean(filepath.Join(dir, ".."))
}

func read(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{repoRoot(t)}, parts...)...)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func TestServiceRunsSinglePrebuiltBinaryLike轻量面板(t *testing.T) {
	service := read(t, "packaging", "migate.service")
	if !strings.Contains(service, "ExecStart=/usr/local/migate/migate") {
		t.Fatalf("service must run single prebuilt binary:\n%s", service)
	}
	forbidden := []string{"python", "uv", "pip", "npm", "migate-proxy", "openvpn", "tun", "egress", "remote", "leak", "rollout"}
	lower := strings.ToLower(service)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("service must not contain %q:\n%s", word, service)
		}
	}
}

func TestInstallerDownloadsReleaseTarballOnly(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{"migate-linux-${ARCH}.tar.gz", "/usr/local/migate", "systemctl enable migate", "systemctl start migate"} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer missing %q:\n%s", want, script)
		}
	}
	forbidden := []string{"git clone", "pip install", "uv ", "python3 -m", "npm install", "openvpn", "migate-proxy", "rollout", "leak", "egress"}
	lower := strings.ToLower(script)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("installer must not contain %q:\n%s", word, script)
		}
	}
}

func TestReadmeDeclaresLiteScopeAndExplicitlyExcludesLegacyHeavyFeatures(t *testing.T) {
	readme := read(t, "README.md")
	for _, want := range []string{"Go single-binary", "轻量面板-style", "VLESS", "VMess", "Trojan", "Shadowsocks"} {
		if !strings.Contains(readme, want) {
			t.Fatalf("README missing scope marker %q", want)
		}
	}
	for _, removed := range []string{"OpenVPN", "TUN", "egress tunnel", "remote readiness", "leak check", "rollout plan", "proxy service", "multi-node remote checks"} {
		if !strings.Contains(readme, "Not included: "+removed) {
			t.Fatalf("README must explicitly exclude %q", removed)
		}
	}
}
