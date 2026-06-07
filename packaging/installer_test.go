package packaging_test

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"os/exec"
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

func TestInstallerIsLightweightInteractiveReleaseInstaller(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"read -r -p \"Panel port",
		"read -r -p \"Panel username",
		"read -r -s -p \"Panel password",
		"read -r -p \"Web base path",
		"/etc/migate/panel.json",
		"panel_port",
		"panel_username",
		"panel_password",
		"web_base_path",
		"migate-linux-${ARCH}.tar.gz",
		"systemctl enable migate",
		"systemctl start migate",
		"cp \"$TMP/packaging/uninstall.sh\" /usr/local/bin/migate-uninstall",
		"chmod +x /usr/local/bin/migate-uninstall",
		"ln -sf /usr/local/bin/migate /usr/local/bin/mg",
		"CLI: mg",
		"WebUI",
		"xray.json",
		"/usr/local/etc/xray/xray.json",
		"ln -sf /usr/local/migate/xray.json /usr/local/etc/xray/xray.json",
		"install_xray",
		"Xray-install",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer missing %q", want)
		}
	}

	forbidden := []string{"git clone", "pip install", "uv ", "python3 -m", "npm install", "go build", "openvpn", "migate-proxy", "rollout", "leak", "egress", "armv7"}
	lower := strings.ToLower(script)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("installer must not contain %q", word)
		}
	}
	for _, forbiddenName := range []string{"MiGate Go Lite", "Go Lite"} {
		if strings.Contains(script, forbiddenName) {
			t.Fatalf("installer should use MiGate as the product name, found %q", forbiddenName)
		}
	}
}

func TestInstallerGeneratesRandomPasswordWhenBlank(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"generate_password()",
		"panel_password=\"$(generate_password)\"",
		"No password entered; generated a random panel password.",
		"Password: ${panel_password}",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer random password contract missing %q", want)
		}
	}
	for _, forbidden := range []string{"super-secret-password", "hidden default"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not contain fixed/default password marker %q", forbidden)
		}
	}
}

func TestInstallerDefaultsWebBasePathToPanel(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"Web base path [/panel]",
		"web_base_path=\"${web_base_path:-/panel}\"",
		"WebUI: http://${host_ip}:${panel_port}${web_base_path}",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer /panel web base path contract missing %q", want)
		}
	}
}

func TestInstallerDownloadsReleaseAssetAndVerifiesChecksum(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"MIGATE_VERSION:-latest",
		"releases/latest/download",
		"releases/download/${VERSION}",
		"CHECKSUM_URL",
		"checksums.txt",
		"curl -fL \"$CHECKSUM_URL\"",
		"grep \"migate-linux-${ARCH}.tar.gz\"",
		"sha256sum -c",
		"tar -xzf \"$TMP/migate-linux-${ARCH}.tar.gz\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer release checksum contract missing %q", want)
		}
	}
	if strings.Index(script, "sha256sum -c") > strings.Index(script, "tar -xzf") {
		t.Fatalf("installer must verify checksum before extracting release archive")
	}
}

func TestUninstallScriptStopsServicesAndRemovesInstalledArtifacts(t *testing.T) {
	script := read(t, "packaging", "uninstall.sh")
	for _, want := range []string{
		"systemctl stop migate",
		"systemctl disable migate",
		"rm -f /etc/systemd/system/migate.service",
		"rm -f /usr/local/bin/migate",
		"rm -f /usr/local/bin/mg",
		"systemctl stop migate-singbox",
		"systemctl disable migate-singbox",
		"rm -f /etc/systemd/system/migate-singbox.service",
		"systemctl daemon-reload",
		"systemctl reset-failed",
		"--purge",
		"rm -rf /etc/migate",
		"rm -rf /usr/local/migate",
		"rm -rf /etc/sing-box",
		"rm -f /usr/local/etc/xray/config.json",
		"rm -f /usr/local/etc/xray/xray.json",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("uninstall script missing %q", want)
		}
	}

	if strings.Contains(strings.ToLower(script), "xray-install") {
		t.Fatalf("uninstall must not remove third-party Xray installation by default")
	}
}

func TestReleaseArchivesIncludeUninstallScript(t *testing.T) {
	root := repoRoot(t)
	distDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "packaging", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST_DIR="+distDir, "VERSION=v0.0.0-test")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build release failed: %v\n%s", err, output)
	}
	for _, artifact := range []string{"migate-linux-amd64.tar.gz", "migate-linux-arm64.tar.gz"} {
		entries := tarEntries(t, filepath.Join(distDir, artifact))
		if !entries["packaging/uninstall.sh"] {
			t.Fatalf("%s missing packaging/uninstall.sh, entries=%v", artifact, entries)
		}
	}
}

func TestServiceUsesGeneratedPanelConfigAndSingleBinary(t *testing.T) {
	service := read(t, "packaging", "migate.service")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/migate serve",
		"--config /etc/migate/panel.json",
		"User=root",
		"Restart=on-failure",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("service missing %q: %s", want, service)
		}
	}
	forbidden := []string{"python", "uv", "pip", "npm", "openvpn", "tun", "egress", "remote", "leak", "rollout"}
	lower := strings.ToLower(service)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("service must not contain %q: %s", word, service)
		}
	}
}

func TestBuildReleaseScriptProducesLinuxArchivesAndChecksums(t *testing.T) {
	root := repoRoot(t)
	distDir := t.TempDir()
	cmd := exec.Command("bash", filepath.Join(root, "packaging", "build-release.sh"))
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "DIST_DIR="+distDir, "VERSION=v0.0.0-test")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build release failed: %v\n%s", err, output)
	}

	for _, artifact := range []string{"migate-linux-amd64.tar.gz", "migate-linux-arm64.tar.gz", "checksums.txt"} {
		path := filepath.Join(distDir, artifact)
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("expected non-empty artifact %s, stat=%v info=%+v\noutput:\n%s", artifact, err, info, output)
		}
	}

	checksums := mustReadFile(t, filepath.Join(distDir, "checksums.txt"))
	for _, artifact := range []string{"migate-linux-amd64.tar.gz", "migate-linux-arm64.tar.gz"} {
		if !strings.Contains(checksums, artifact) {
			t.Fatalf("checksums missing %s: %s", artifact, checksums)
		}
		entries := tarEntries(t, filepath.Join(distDir, artifact))
		for _, want := range []string{"migate", "packaging/migate.service", "packaging/install.sh"} {
			if !entries[want] {
				t.Fatalf("%s missing %s, entries=%v", artifact, want, entries)
			}
		}
		forbidden := []string{".git/", "node_modules/", "python", "openvpn", "rollout", "leak", "egress"}
		for name := range entries {
			lower := strings.ToLower(name)
			for _, word := range forbidden {
				if strings.Contains(lower, word) {
					t.Fatalf("%s contains forbidden release entry %q", artifact, name)
				}
			}
		}
	}
}

func TestReleaseWorkflowBuildsAndUploadsReleaseAssets(t *testing.T) {
	workflow := read(t, ".github", "workflows", "release.yml")
	for _, want := range []string{
		"name: Release",
		"push:",
		"tags:",
		"v*",
		"contents: write",
		"actions/checkout",
		"actions/setup-go",
		"go-version-file: go.mod",
		"packaging/build-release.sh",
		"softprops/action-gh-release",
		"dist/migate-linux-amd64.tar.gz",
		"dist/migate-linux-arm64.tar.gz",
		"dist/checksums.txt",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}

	forbidden := []string{"npm", "node_modules", "pip", "uv ", "python", "openvpn", "rollout", "leak", "egress"}
	lower := strings.ToLower(workflow)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("release workflow must not contain %q", word)
		}
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func tarEntries(t *testing.T, path string) map[string]bool {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open archive %s: %v", path, err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader %s: %v", path, err)
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	entries := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar %s: %v", path, err)
		}
		entries[header.Name] = true
	}
	return entries
}
