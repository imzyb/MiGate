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

func join(parts ...string) string { return strings.Join(parts, "") }

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

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func TestInstallerIsProductizedReleaseInstaller(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"log_info()",
		"section()",
		"detect_os()",
		"detect_arch()",
		"detect_systemd()",
		"dependency_status()",
		"detect_existing_install()",
		"interactive_menu()",
		"升级 MiGate，并保留现有配置",
		"重装 MiGate，并重新生成面板配置",
		"只修复 migate systemd 服务",
		"只安装/修复 Xray",
		"只安装/修复 sing-box",
		"/etc/migate/panel.json",
		"panel_port",
		"panel_username",
		"panel_password",
		"web_base_path",
		"management_direct_enabled",
		"management_direct_auto_detect",
		"ensure-management-direct",
		"migate-linux-${ARCH}.tar.gz",
		"enable_systemd_service migate",
		"systemctl restart migate",
		"MIGATE_PANEL_BIND_HOST=0.0.0.0",
		`mktemp "$(dirname "$UNINSTALLER_BIN")/.migate-uninstall.XXXXXX"`,
		"mv -f \"$uninstaller_tmp\" \"$UNINSTALLER_BIN\"",
		"ln -sf \"$MIGATE_BIN\" \"$MIGATE_LINK\"",
		"CLI 命令",
		"WebUI",
		"xray.json",
		"/etc/migate/cores/xray.json",
		"install_xray",
		"Xray-linux-${xray_asset_arch}.zip",
		"hash-password",
		"/var/lib/migate/versions.json",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer missing %q", want)
		}
	}

	forbidden := []string{"git clone", "pip install", "uv ", "python3 -m", "npm install", "go build", "Xray-install/raw/main/install-release.sh", join("open", "vpn"), "migate-proxy", "rollout", "leak", "egress", "armv7"}
	lower := strings.ToLower(script)
	for _, word := range forbidden {
		if strings.Contains(lower, word) {
			t.Fatalf("installer must not contain %q", word)
		}
	}
	for _, forbiddenName := range []string{join("MiGate Go", " Lite"), "Go Lite"} {
		if strings.Contains(script, forbiddenName) {
			t.Fatalf("installer should use MiGate as the product name, found %q", forbiddenName)
		}
	}
}

func TestInstallerSupportsNonInteractiveActionsAndDryRun(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"--yes, -y",
		"--install",
		"--upgrade, --update",
		"--uninstall",
		"--repair-service",
		"--install-xray",
		"--install-singbox",
		"--dry-run",
		"DRY_RUN=0",
		"run_cmd()",
		"[DRY-RUN]",
		"install_release_flow",
		"repair_service_flow",
		"uninstall_flow",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer non-interactive/dry-run contract missing %q", want)
		}
	}
}

func TestInstallerChecksRootBeforeTakingInstallLock(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	mainIdx := strings.Index(script, "main()")
	if mainIdx < 0 {
		t.Fatalf("installer must define main")
	}
	mainBody := script[mainIdx:]
	for _, want := range []string{
		"install|upgrade|reinstall|repair-service|install-xray-only|install-singbox-only|install-cores-only|uninstall)",
		"require_root",
		"with_install_lock run_action",
	} {
		if !strings.Contains(mainBody, want) {
			t.Fatalf("installer main lock/root contract missing %q", want)
		}
	}
	rootIdx := strings.Index(mainBody, "require_root")
	lockIdx := strings.Index(mainBody, "with_install_lock run_action")
	if rootIdx < 0 || lockIdx < 0 || rootIdx > lockIdx {
		t.Fatalf("installer must check root before creating install lock")
	}
}

func TestInstallerInstallLockCreatesParentDirectoryBeforeFallbackLock(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	lockIdx := strings.Index(script, "with_install_lock()")
	if lockIdx < 0 {
		t.Fatalf("installer must define with_install_lock")
	}
	lockBody := script[lockIdx:]
	for _, want := range []string{
		`mkdir -p "$(dirname "$INSTALL_LOCK")"`,
		`( set -e; "$@" )`,
		`code="$?"`,
		`flock -u 9 || true`,
		`lock_dir="${INSTALL_LOCK}.d"`,
		`mkdir "$lock_dir"`,
		`rmdir "$lock_dir" 2>/dev/null || true`,
		`return "$code"`,
	} {
		if !strings.Contains(lockBody, want) {
			t.Fatalf("installer lock contract missing %q", want)
		}
	}
	parentIdx := strings.Index(lockBody, `mkdir -p "$(dirname "$INSTALL_LOCK")"`)
	fallbackIdx := strings.Index(lockBody, `lock_dir="${INSTALL_LOCK}.d"`)
	if parentIdx < 0 || fallbackIdx < 0 || parentIdx > fallbackIdx {
		t.Fatalf("installer must create install lock parent directory before fallback lock dir")
	}
	fallbackBody := lockBody[fallbackIdx:]
	runIdx := strings.Index(fallbackBody, `( set -e; "$@" )`)
	codeIdx := strings.Index(fallbackBody, `code="$?"`)
	cleanupIdx := strings.Index(fallbackBody, `rmdir "$lock_dir" 2>/dev/null || true`)
	returnIdx := strings.Index(fallbackBody, `return "$code"`)
	if runIdx < 0 || codeIdx < 0 || cleanupIdx < 0 || returnIdx < 0 || !(runIdx < codeIdx && codeIdx < cleanupIdx && cleanupIdx < returnIdx) {
		t.Fatalf("installer fallback lock must capture action failure, remove lock dir, and return original code")
	}
}

func TestInstallerPreservesExistingConfigByDefault(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"read_existing_config_defaults()",
		"if [ -f \"$CONFIG_PATH\" ] && [ \"$REGENERATE_CONFIG\" -ne 1 ]; then",
		"保留已有配置",
		"使用已有配置，不重新生成 panel.json",
		"--fresh-config",
		"REGENERATE_CONFIG=1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer config preservation contract missing %q", want)
		}
	}
}

func TestInstallerValidatesAutoDetectedManagementIP(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"is_valid_public_ip()",
		`is_valid_public_ip "$ip"`,
		`'^([0-9]{1,3}\.){3}[0-9]{1,3}$'`,
		`[ "$octet" -le 255 ]`,
		`*:*) is_valid_ipv6_literal "$ip"`,
		"is_valid_ipv6_literal()",
		`''|*[!0-9a-fA-F:]*|*:::*) return 1 ;;`,
		`:*) case "$ip" in ::*) ;; *) return 1 ;; esac ;;`,
		`*:) case "$ip" in *::) ;; *) return 1 ;; esac ;;`,
		`double_colon_count="$(printf '%s' "$ip" | awk -F'::' '{print NF-1}')"`,
		`colon_count="$(printf '%s' "$ip" | awk -F: '{print NF-1}')"`,
		`[ "$double_colon_count" -le 1 ] || return 1`,
		`[ "$colon_count" -eq 7 ] || return 1`,
		`[ "$colon_count" -ge 2 ] || return 1`,
		`explicit_count=$((explicit_count + 1))`,
		`[ "$explicit_count" -lt 8 ] || return 1`,
		`[ "$count" -le 8 ] || return 1`,
		`*) return 1 ;;`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer public IP validation missing %q", want)
		}
	}
}

func TestInstallerPublicIPValidationRejectsMalformedIPv6(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	start := strings.Index(script, "is_valid_public_ip()")
	end := strings.Index(script, "ensure_management_direct_defaults()")
	if start < 0 || end < 0 || start >= end {
		t.Fatal("could not extract public IP validation functions")
	}
	checker := script[start:end] + `
expect_valid() {
  is_valid_public_ip "$1" || { echo "expected valid: $1"; exit 1; }
}
expect_invalid() {
  if is_valid_public_ip "$1"; then
    echo "expected invalid: $1"
    exit 1
  fi
}
expect_valid 103.193.149.217
expect_valid 2001:db8::1
expect_valid 2606:4700::1111
expect_valid 2001:db8::
expect_valid ::1
expect_valid 2001:0db8:0000:0000:0000:ff00:0042:8329
expect_invalid 999.1.1.1
expect_invalid :1
expect_invalid 2001:db8:
expect_invalid ::::
expect_invalid 1::2::3
expect_invalid 1:2:3:4:5:6:7::8
expect_invalid 1:2:3:4:5:6:7:8::
expect_invalid 1:2:3
`
	path := filepath.Join(t.TempDir(), "check-ip.sh")
	if err := os.WriteFile(path, []byte(checker), 0o700); err != nil {
		t.Fatalf("write checker: %v", err)
	}
	out, err := exec.Command("bash", path).CombinedOutput()
	if err != nil {
		t.Fatalf("public IP validation checker failed: %v\n%s", err, out)
	}
}

func TestInstallerFinishMessageNormalizesWebUIPath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{name: "missing leading slash", path: "migate", want: ":9999/migate"},
		{name: "leading slash", path: "/migate", want: ":9999/migate"},
		{name: "trailing slash", path: "/migate/", want: ":9999/migate"},
		{name: "root", path: "/", want: ":9999/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := repoRoot(t)
			tmp := t.TempDir()
			configPath := filepath.Join(tmp, "panel.json")
			if err := os.WriteFile(configPath, []byte(`{"panel_port":9999,"panel_username":"admin","web_base_path":"`+tc.path+`"}`), 0o600); err != nil {
				t.Fatalf("write config: %v", err)
			}
			cmd := exec.Command("bash", filepath.Join(root, "packaging", "install.sh"), "--upgrade", "--yes", "--dry-run")
			cmd.Dir = root
			cmd.Env = append(os.Environ(),
				"MIGATE_CONFIG_PATH="+configPath,
				"MIGATE_CONFIG_DIR="+tmp,
				"MIGATE_INSTALL_DIR="+tmp,
			)
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("dry-run upgrade failed: %v\n%s", err, output)
			}
			out := string(output)
			if !strings.Contains(out, "WebUI 地址:") || !strings.Contains(out, tc.want) {
				t.Fatalf("finish message missing normalized WebUI path %q:\n%s", tc.want, out)
			}
			proxyTarget := "反向代理到 0.0.0.0:9999" + strings.TrimPrefix(tc.want, ":9999")
			if !strings.Contains(out, proxyTarget) {
				t.Fatalf("finish message missing normalized reverse proxy target %q:\n%s", proxyTarget, out)
			}
			if strings.Contains(out, ":9999migate") || strings.Contains(out, ":9999//migate") {
				t.Fatalf("finish message contains malformed URL path:\n%s", out)
			}
		})
	}
}

func TestInstallerConfigPathsFollowInstallDir(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"\"database_path\": \"$(json_escape \"$DATA_DIR\")/migate.db\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer config path contract missing %q", want)
		}
	}
	if strings.Contains(script, "xray_"+"config_path") {
		t.Fatalf("installer must not write legacy Xray config path field")
	}
}

func TestInstallerDetectsCorePathsVersionsAndServices(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"detect_core()",
		"core_binary_path()",
		"\"/usr/local/bin/${command_name}\" \"/usr/bin/${command_name}\"",
		"core_version()",
		"systemctl list-unit-files \"${service_name}.service\"",
		"if detect_core \"Xray\" \"xray\" \"migate-xray\"; then XRAY_FOUND=1; else XRAY_FOUND=0; fi",
		"if detect_core \"sing-box\" \"sing-box\" \"migate-sing-box\"; then SINGBOX_FOUND=1; else SINGBOX_FOUND=0; fi",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer core detection contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"if detect_core \"Xray\" \"xray\" \"xray\"; then XRAY_FOUND=1; else XRAY_FOUND=0; fi",
		"if detect_core \"sing-box\" \"sing-box\" \"sing-box\"; then SINGBOX_FOUND=1; else SINGBOX_FOUND=0; fi",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not detect legacy core service %q", forbidden)
		}
	}
}

func TestInstallerPromptsForMissingCoresByDefaultAndPreservesExistingCores(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"XRAY_FOUND=0",
		"SINGBOX_FOUND=0",
		"CORE_PROMPTS_CONFIRMED=0",
		"confirm_yes \"未检测到 Xray，是否安装 Xray？\"",
		"confirm_yes \"未检测到 sing-box，是否安装 sing-box？\"",
		"confirm_no \"检测到 Xray 已安装，是否重新安装/修复 Xray？\"",
		"confirm_no \"检测到 sing-box 已安装，是否重新安装/修复 sing-box？\"",
		"保留现有 Xray 安装。",
		"保留现有 sing-box 安装。",
		"CORE_PROMPTS_CONFIRMED=1",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer core prompt contract missing %q", want)
		}
	}
}

func TestInstallerGeneratesRandomPasswordWhenBlank(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"generate_password()",
		"PANEL_PASSWORD=\"$(generate_password)\"",
		"未输入密码，已生成随机密码。",
		"管理员密码",
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

func TestInstallerUsesPanelBasePath(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"prompt_line \"Web base path [${WEB_BASE_PATH:-/panel}]: \"",
		"WEB_BASE_PATH=\"${input_web_base_path:-${WEB_BASE_PATH:-/panel}}\"",
		"normalize_web_base_path",
		"WEB_BASE_PATH=\"$(normalize_web_base_path \"$WEB_BASE_PATH\")\"",
		"WebUI 地址",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer /panel web base path contract missing %q", want)
		}
	}
}

func TestInstallerOffersSingBoxRuntime(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"install_singbox",
		"confirm_yes \"未检测到 sing-box，是否安装 sing-box？\"",
		"migate-sing-box.service",
		"ExecStart=/usr/local/bin/sing-box run -c ${SINGBOX_CONFIG_PATH}",
		"systemctl stop migate-sing-box",
		"enable_systemd_service migate-sing-box",
		`check_singbox_config_silent "$SINGBOX_CONFIG_PATH"`,
		"sing-box 默认配置校验失败：${SINGBOX_CONFIG_PATH}",
		"sing-box 配置校验通过：${SINGBOX_CONFIG_PATH}",
		"journalctl -u migate-sing-box -n 80 --no-pager",
		"systemctl restart migate-sing-box",
		"systemctl is-active --quiet migate-sing-box",
		"sing-box 安装/修复完成",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer sing-box runtime contract missing %q", want)
		}
	}
	serviceWrite := strings.Index(script, `atomic_write_file "$SINGBOX_SERVICE_PATH" 0644 root:root`)
	if serviceWrite < 0 || !strings.Contains(script[serviceWrite:], "systemctl daemon-reload") {
		t.Fatalf("installer must daemon-reload after writing sing-box service")
	}
	singboxConfigCheck := strings.Index(script, "if ! ensure_valid_singbox_config; then")
	singboxRestart := strings.Index(script, "systemctl restart migate-sing-box")
	if singboxConfigCheck < 0 || singboxRestart < 0 || singboxConfigCheck > singboxRestart {
		t.Fatalf("installer must check sing-box config before starting service")
	}
	checkBlock := script[singboxConfigCheck:]
	if !strings.Contains(checkBlock, "return 1") || strings.Index(checkBlock, "return 1") > strings.Index(checkBlock, "systemctl restart migate-sing-box") {
		t.Fatalf("installer must fail before sing-box service restart when config check fails")
	}
}

func TestInstallerReplacesCoreBinariesAtomically(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"systemctl stop migate-xray 2>/dev/null || true",
		"local xray_install_tmp=\"/usr/local/bin/.xray.new.$$\"",
		"cp \"$tmp_xray/xray/xray\" \"$xray_install_tmp\" && chmod +x \"$xray_install_tmp\" && mv -f \"$xray_install_tmp\" /usr/local/bin/xray",
		"rm -f \"$xray_install_tmp\"",
		"systemctl stop migate-sing-box 2>/dev/null || true",
		"systemctl stop migate-sing-box 2>/dev/null || true",
		"local sb_install_tmp=\"/usr/local/bin/.sing-box.new.$$\"",
		"cp \"$tmp_sb\"/sing-box-*/sing-box \"$sb_install_tmp\" && chmod +x \"$sb_install_tmp\" && mv -f \"$sb_install_tmp\" /usr/local/bin/sing-box",
		"rm -f \"$sb_install_tmp\"",
		"[DRY-RUN] systemctl stop migate-xray",
		"[DRY-RUN] atomic install /usr/local/bin/xray via /usr/local/bin/.xray.new.$$",
		"[DRY-RUN] systemctl stop migate-sing-box",
		"[DRY-RUN] systemctl stop migate-sing-box",
		"[DRY-RUN] atomic install /usr/local/bin/sing-box via /usr/local/bin/.sing-box.new.$$",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer core atomic replacement contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		"cp \"$tmp_xray/xray/xray\" /usr/local/bin/xray",
		"cp \"$tmp_sb\"/sing-box-*/sing-box /usr/local/bin/sing-box",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not directly overwrite a running core binary with %q", forbidden)
		}
	}
}

func TestInstallerXrayRepairUsesStandardSystemdUnit(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		`atomic_write_file "$XRAY_SERVICE_PATH" 0644 root:root`,
		"systemctl daemon-reload",
		"systemctl restart migate-xray",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer must manage standard Xray service before restart, missing %q", want)
		}
	}
	for _, forbidden := range []string{"10-donot_touch_single_conf.conf", "migate-xray.service.d"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not retain legacy Xray drop-in handling %q", forbidden)
		}
	}
}

func TestInstallerSeedsCoreConfigsMatchingGeneratedDefaults(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"atomic_write_file()",
		"write_default_xray_config()",
		"write_default_singbox_config()",
		`install_default_xray_config()`,
		`install_default_singbox_config()`,
		`"tag": "xray-out-1"`,
		`"tag": "xray-out-2"`,
		`"tag": "xray-out-3"`,
		`"tag": "api"`,
		`"StatsService"`,
		`"tag": "singbox-out-1"`,
		`"tag": "singbox-out-2"`,
		`install_default_xray_config`,
		`install_default_singbox_config`,
		`ensure_valid_xray_config()`,
		`ensure_valid_singbox_config()`,
		`现有 Xray 配置校验失败，将备份并写入 MiGate 默认配置。`,
		`现有 sing-box 配置校验失败，将备份并写入 MiGate 默认配置。`,
		`"${BACKUP_DIR}/${core}-config-invalid-$(date +%Y%m%d-%H%M%S).json"`,
		`set_core_config_permissions()`,
		`chown root:migate "$path"`,
		`chmod 0640 "$path"`,
		`validate_xray_config "$tmp"`,
		`validate_singbox_config "$tmp"`,
		`mv -f "$tmp" "$XRAY_CONFIG_PATH"`,
		`mv -f "$tmp" "$SINGBOX_CONFIG_PATH"`,
		`set_core_config_permissions "$XRAY_CONFIG_PATH"`,
		`set_core_config_permissions "$SINGBOX_CONFIG_PATH"`,
		`check_xray_config_silent "$XRAY_CONFIG_PATH"`,
		`check_singbox_config_silent "$SINGBOX_CONFIG_PATH"`,
		`validate_xray_config "$XRAY_CONFIG_PATH" "Xray 配置校验通过：${XRAY_CONFIG_PATH}"`,
		`validate_singbox_config "$SINGBOX_CONFIG_PATH" "sing-box 配置校验通过：${SINGBOX_CONFIG_PATH}"`,
		`check_xray_config_silent "$XRAY_CONFIG_PATH"`,
		`Xray 配置校验通过：${XRAY_CONFIG_PATH}`,
		`systemctl is-active --quiet migate-xray`,
		`check_singbox_config_silent "$SINGBOX_CONFIG_PATH"`,
		`sing-box 配置校验通过：${SINGBOX_CONFIG_PATH}`,
		`systemctl is-active --quiet migate-sing-box`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer default core config contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`"tag": "direct"`,
		`"tag": "blocked"`,
		`"outbounds":[{"type":"direct","tag":"direct"}]`,
		`"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}`,
		`ln -sf "${DATA_DIR}/xray.json" "${CONFIG_DIR}/xray.json"`,
		`systemctl is-active --quiet xray`,
		`systemctl is-active --quiet sing-box`,
		strings.Join([]string{`.migate`, `-backup.$(date +%Y%m%d%H%M%S)`}, ""),
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not seed legacy default core config marker %q", forbidden)
		}
	}
}

func TestInstallerUsesAtomicWritesForRuntimeContractFiles(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		`atomic_write_file "$CONFIG_PATH" 0640 root:migate`,
		`atomic_write_file "$SERVICE_PATH" 0644 root:root`,
		`atomic_write_file "$XRAY_SERVICE_PATH" 0644 root:root`,
		`atomic_write_file "$SINGBOX_SERVICE_PATH" 0644 root:root`,
		`atomic_write_file "$VERSIONS_PATH" 0640 root:migate`,
		`[DRY-RUN] atomic write`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer atomic write contract missing %q", want)
		}
	}
	for _, forbidden := range []string{
		`cat > "$CONFIG_PATH"`,
		`cat > "$SERVICE_PATH"`,
		`cat > "$XRAY_SERVICE_PATH"`,
		`cat > "$SINGBOX_SERVICE_PATH"`,
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not directly write runtime contract file with %q", forbidden)
		}
	}
}

func TestInstallerWritesVersionStateFile(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		`VERSIONS_PATH="${MIGATE_VERSIONS_PATH:-/var/lib/migate/versions.json}"`,
		`write_versions_state()`,
		`"installed_at":`,
		`"installer_version":`,
		`"configured_version":`,
		`write_versions_state`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer version state contract missing %q", want)
		}
	}
}

func TestInstallerConfiguresBoundedLogRetention(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	service := read(t, "packaging", "migate.service")
	for _, want := range []string{
		"configure_log_retention()",
		"SystemMaxUse=128M",
		"RuntimeMaxUse=64M",
		"MaxRetentionSec=14day",
		"journalctl --vacuum-size=128M",
		"/var/log/migate-update.log",
		"size 5M",
		"rotate 3",
		"copytruncate",
		"configure_log_retention",
		"StandardOutput=journal",
		"StandardError=journal",
		"LogRateLimitIntervalSec=30s",
		"LogRateLimitBurst=200",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer log retention contract missing %q", want)
		}
	}
	for _, want := range []string{
		"StandardOutput=journal",
		"StandardError=journal",
		"LogRateLimitIntervalSec=30s",
		"LogRateLimitBurst=200",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("packaged systemd unit log limit missing %q", want)
		}
	}
	if strings.Index(script, "configure_log_retention") > strings.Index(script, "write_systemd_service") {
		t.Fatalf("installer should define log retention before service-writing flow")
	}
}

func TestInstallerCompletionPrintsSaveableInstallSummary(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"安装完成，请保存以下信息",
		"数据目录",
		"面板监听",
		"Web base path",
		"WebUI 地址",
		"管理员用户",
		"管理员密码",
		"面板配置",
		"数据库",
		"Xray 配置",
		"Xray 二进制",
		"sing-box 配置",
		"sing-box 二进制",
		"安装器",
		"卸载器",
		"MiGate 服务文件",
		"常用命令",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer completion summary missing %q", want)
		}
	}
}

func TestInstallerDoesNotOfferArchivedRuntimeDependencies(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, forbidden := range []string{
		"install_" + join("vpn", "gate") + "_runtime_dependencies",
		"是否安装 removed VPN feature runtime 依赖？[Y/n]",
		join("micro", "socks"),
		join("soft", "ether", "-vpn", "client"),
		join("soft", "ether", "-vpn", "cmd"),
		"dhclient",
		join("vpn", "cmd"),
		join("vpn", "client"),
		"removed VPN feature runtime dependencies:",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer must not offer removed VPN feature runtime dependency %q", forbidden)
		}
	}
}

func TestInstallerDownloadsReleaseAssetAndVerifiesChecksum(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"MIGATE_VERSION:-latest",
		"release_base_url()",
		"latest_release_tag()",
		"ensure_latest_release_version",
		"releases/latest/download",
		"releases/download/%s",
		"CHECKSUM_URL",
		"checksums.txt",
		"download_file \"$CHECKSUM_URL\"",
		"grep \"migate-linux-${ARCH}.tar.gz\"",
		"verify_sha256 \"${ARTIFACT}.sha256\" \"$TMP\"",
		"tar --no-same-owner -xzf \"$TMP/migate-linux-${ARCH}.tar.gz\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer release checksum contract missing %q", want)
		}
	}
	if strings.Index(script, "verify_sha256 \"${ARTIFACT}.sha256\" \"$TMP\"") > strings.Index(script, "tar --no-same-owner -xzf \"$TMP/migate-linux-${ARCH}.tar.gz\"") {
		t.Fatalf("installer must verify checksum before extracting MiGate release archive")
	}
}

func TestInstallerVerifiesSingBoxArchiveChecksumBeforeExtracting(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"sb_artifact=\"sing-box-${sb_version}-linux-${sb_asset_arch}.tar.gz\"",
		"sb_release_api_url=\"https://api.github.com/repos/SagerNet/sing-box/releases/tags/v${sb_version}\"",
		"curl -fL \"$sb_url\" -o \"$tmp_sb/$sb_artifact\"",
		"curl -fsSL \"$sb_release_api_url\" -o \"$tmp_sb/release.json\"",
		"/\"name\": \"/ { in_asset=0 }",
		"printf '%s  %s\\n' \"$sb_digest\" \"$sb_artifact\" > \"$tmp_sb/$sb_artifact.sha256\"",
		"verify_sha256 \"$sb_artifact.sha256\" \"$tmp_sb\"",
		"tar --no-same-owner -xzf \"$tmp_sb/$sb_artifact\" -C \"$tmp_sb\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer sing-box checksum contract missing %q", want)
		}
	}
	if strings.Index(script, "verify_sha256 \"$sb_artifact.sha256\" \"$tmp_sb\"") > strings.Index(script, "tar --no-same-owner -xzf \"$tmp_sb/$sb_artifact\"") {
		t.Fatalf("installer must verify sing-box checksum before extracting archive")
	}
}

func TestInstallerDoesNotAbortMainFlowWhenOptionalCoreInstallFails(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"maybe_install_core()",
		"( set -e; \"$installer\" )",
		"${label} 安装/修复失败",
		"MiGate 安装/升级将继续",
		"if [ \"$EXPLICIT_INSTALL_XRAY\" -eq 1 ]; then install_xray; else maybe_install_core \"Xray\" install_xray; fi",
		"if [ \"$EXPLICIT_INSTALL_SINGBOX\" -eq 1 ]; then install_singbox; else maybe_install_core \"sing-box\" install_singbox; fi",
		"MiGate 升级事务不同时安装/修复核心",
		"install-singbox-only)",
		"install_singbox",
		"install-xray-only)",
		"install_xray",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer optional core failure contract missing %q", want)
		}
	}
	upgradeBody := script[strings.Index(script, "apply_upgrade_release_from_backup()"):]
	upgradeBody = upgradeBody[:strings.Index(upgradeBody, "print_config_summary()")]
	if strings.Contains(upgradeBody, "install_xray; else maybe_install_core") || strings.Contains(upgradeBody, "install_singbox; else maybe_install_core") {
		t.Fatalf("upgrade transaction must not run core installers without backing up core state")
	}
}

func TestInstallerCoreOnlyAndRepairActionsEnsureMigateUserGroup(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"ensure_migate_user_group()",
		"groupadd --system migate",
		"useradd --system --home-dir \"$DATA_DIR\" --no-create-home --gid migate --shell /usr/sbin/nologin migate",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer migate user/group contract missing %q", want)
		}
	}
	repairFlow := script[strings.Index(script, "repair_service_flow()"):]
	for _, want := range []string{
		"require_root",
		"ensure_migate_user_group",
		"write_systemd_service",
	} {
		if !strings.Contains(repairFlow, want) {
			t.Fatalf("repair-service user/group contract missing %q", want)
		}
	}
	if strings.Index(repairFlow, "require_root") > strings.Index(repairFlow, "ensure_migate_user_group") ||
		strings.Index(repairFlow, "ensure_migate_user_group") > strings.Index(repairFlow, "write_systemd_service") {
		t.Fatalf("repair-service must ensure migate user/group after root check and before service rewrite")
	}
	runAction := script[strings.Index(script, "run_action()"):]
	for _, tc := range []struct {
		action string
		call   string
	}{
		{action: "install-xray-only)", call: "install_xray"},
		{action: "install-singbox-only)", call: "install_singbox"},
		{action: "install-cores-only)", call: "install_xray"},
	} {
		actionIdx := strings.Index(runAction, tc.action)
		if actionIdx < 0 {
			t.Fatalf("run_action missing %s", tc.action)
		}
		body := runAction[actionIdx:]
		rootIdx := strings.Index(body, "require_root")
		ensureIdx := strings.Index(body, "ensure_migate_user_group")
		callIdx := strings.Index(body, tc.call)
		if rootIdx < 0 || ensureIdx < 0 || callIdx < 0 || !(rootIdx < ensureIdx && ensureIdx < callIdx) {
			t.Fatalf("%s must ensure migate user/group after root check and before %s", tc.action, tc.call)
		}
	}
}

func TestInstallerExplicitCoreInstallFlagsRemainStrict(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"EXPLICIT_INSTALL_XRAY=0",
		"EXPLICIT_INSTALL_SINGBOX=0",
		"--install-xray) INSTALL_XRAY=1; EXPLICIT_INSTALL_XRAY=1",
		"--install-singbox) INSTALL_SINGBOX=1; EXPLICIT_INSTALL_SINGBOX=1",
		"if [ \"$EXPLICIT_INSTALL_XRAY\" -eq 1 ]; then install_xray; else maybe_install_core \"Xray\" install_xray; fi",
		"if [ \"$EXPLICIT_INSTALL_SINGBOX\" -eq 1 ]; then install_singbox; else maybe_install_core \"sing-box\" install_singbox; fi",
		"MiGate 升级事务不同时安装/修复核心",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer explicit core strictness contract missing %q", want)
		}
	}
}

func TestInstallerVerifiesXrayArchiveChecksumBeforeExtracting(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"xray_artifact=\"Xray-linux-${xray_asset_arch}.zip\"",
		"xray_dgst_url=\"${xray_url}.dgst\"",
		"curl -fL \"$xray_url\" -o \"$tmp_xray/$xray_artifact\"",
		"awk -F'= ' -v asset=\"$xray_artifact\" '/^SHA2-256=/{print $2 \"  \" asset}' \"$tmp_xray/$xray_artifact.dgst\" > \"$tmp_xray/$xray_artifact.sha256\"",
		"verify_sha256 \"$xray_artifact.sha256\" \"$tmp_xray\"",
		"unzip -oq \"$tmp_xray/$xray_artifact\" -d \"$tmp_xray/xray\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer Xray checksum contract missing %q", want)
		}
	}
	if strings.Index(script, "verify_sha256 \"$xray_artifact.sha256\" \"$tmp_xray\"") > strings.Index(script, "unzip -oq \"$tmp_xray/$xray_artifact\" -d \"$tmp_xray/xray\"") {
		t.Fatalf("installer must verify Xray checksum before extracting archive")
	}
}

func TestInstallerSkipsSingBoxSystemdUnitWhenSystemdUnavailable(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"if [ \"$SYSTEMD_AVAILABLE\" -ne 1 ]; then",
		"systemd 不可用，跳过 migate-sing-box.service 写入。",
		"Manual run: /usr/local/bin/sing-box run -c ${SINGBOX_CONFIG_PATH}",
		`atomic_write_file "$SINGBOX_SERVICE_PATH" 0644 root:root`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer sing-box non-systemd contract missing %q", want)
		}
	}
	if strings.Index(script, "systemd 不可用，跳过 migate-sing-box.service 写入。") > strings.Index(script, `atomic_write_file "$SINGBOX_SERVICE_PATH" 0644 root:root`) {
		t.Fatalf("installer must skip sing-box unit before writing service file when systemd is unavailable")
	}
}

func TestInstallerSupportsNonInteractiveUpdateMode(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"--upgrade|--update) ACTION=\"upgrade\"; SKIP_CORE_PROMPTS=1",
		"--check)",
		"--version)",
		"check_update()",
		"note_current_release_state",
		"guard_default_latest_upgrade",
		"compare_versions",
		"normalize_version",
		"install_release_flow",
		"download_release_asset",
		"install_migate_binary_from_tmp",
		"systemctl restart migate",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer update contract missing %q", want)
		}
	}
}

func TestInstallerRepairServiceRefreshesSandboxPermissions(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		`ReadWritePaths=${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR} ${RUN_DIR} $(dirname "$MIGATE_BIN") ${XRAY_SHARE_DIR} $(dirname "$SERVICE_PATH")`,
		"repair_service_flow()",
		"write_systemd_service",
		"restart_migate_service",
		"run_cmd systemctl daemon-reload",
		"run_cmd systemctl restart migate",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("repair-service cannot refresh sandbox permission %q", want)
		}
	}
	repairIdx := strings.Index(script, "repair_service_flow()")
	if repairIdx < 0 {
		t.Fatalf("repair-service must define repair_service_flow")
	}
	repairBody := script[repairIdx:]
	writeIdx := strings.Index(repairBody, "write_systemd_service")
	restartIdx := strings.Index(repairBody, "restart_migate_service")
	if writeIdx < 0 || restartIdx < 0 || writeIdx > restartIdx {
		t.Fatalf("repair-service must rewrite migate.service before restarting service")
	}
}

func TestInstallerUpdateFlowRewritesServiceBeforeRestart(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	writeIdx := strings.Index(script, "write_systemd_service")
	restartIdx := strings.Index(script, "section \"服务启动\"")
	if writeIdx < 0 || restartIdx < 0 || writeIdx > restartIdx {
		t.Fatalf("update/install flow must rewrite migate.service before service restart")
	}
	for _, want := range []string{
		"install_release_flow()",
		"write_systemd_service",
		"restart_migate_service",
		"run_cmd systemctl daemon-reload",
		"run_cmd systemctl restart migate",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("update flow service refresh contract missing %q", want)
		}
	}
}

func TestInstallerExplicitVersionUpdateFlowRefreshesServiceEvenWhenCurrent(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	if strings.Contains(script, "if skip_update_if_current; then") {
		t.Fatalf("update flow must not return before service and installer self-repair when already current")
	}
	for _, want := range []string{
		"note_current_release_state",
		"MiGate 已是最新版本",
		"将刷新安装器和服务配置",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("update flow current-version repair contract missing %q", want)
		}
	}
	flowIdx := strings.Index(script, "install_release_flow()")
	if flowIdx < 0 {
		t.Fatalf("update flow must define install_release_flow")
	}
	flowBody := script[flowIdx:]
	noteIdx := strings.Index(flowBody, "note_current_release_state")
	downloadIdx := strings.Index(flowBody, "download_release_asset")
	installIdx := strings.Index(flowBody, "install_migate_binary_from_tmp")
	writeIdx := strings.Index(flowBody, "write_systemd_service")
	restartIdx := strings.Index(flowBody, "section \"服务启动\"")
	if noteIdx < 0 || downloadIdx < 0 || installIdx < 0 || writeIdx < 0 || restartIdx < 0 {
		t.Fatalf("update flow must include current-version note, release download, installer refresh, service rewrite, and restart")
	}
	if !(noteIdx < downloadIdx && downloadIdx < installIdx && installIdx < writeIdx && writeIdx < restartIdx) {
		t.Fatalf("update flow must continue from current-version note through installer/service refresh before restart")
	}
}

func TestInstallerDefaultLatestUpgradeRefusesNewerCurrentVersion(t *testing.T) {
	env := newInstallerHarness(t, "newer-current")
	result := env.runWithVersion(t, "latest")
	if result.err == nil {
		t.Fatalf("expected default latest upgrade to refuse newer current version\n%s", result.output)
	}
	if got := readFile(t, env.migateBin); !strings.Contains(got, "old migate") {
		t.Fatalf("default latest guard must not replace newer local binary, got %q", got)
	}
	if !strings.Contains(result.output, "高于最新发布版本") || strings.Contains(result.output, "Run: mg update") {
		t.Fatalf("newer-current output missing clear refusal:\n%s", result.output)
	}
	status := readFile(t, env.updateStatusPath)
	if !strings.Contains(status, `"status": "failed"`) || !strings.Contains(status, "不可执行默认 latest 升级") {
		t.Fatalf("newer-current status missing refusal: %s", status)
	}
}

func TestInstallerDryRunDefaultLatestUpgradeRefusesNewerCurrentVersion(t *testing.T) {
	env := newInstallerHarness(t, "newer-current")
	result := env.runWithArgs(t, "latest", "--dry-run")
	if result.err != nil {
		t.Fatalf("dry-run newer-current guard should exit successfully after preview refusal: %v\n%s", result.err, result.output)
	}
	if !strings.Contains(result.output, "高于最新发布版本") || !strings.Contains(result.output, "不可执行默认 latest 升级") {
		t.Fatalf("dry-run newer-current output missing clear refusal:\n%s", result.output)
	}
	if strings.Contains(result.output, "下载 Release 包") || strings.Contains(result.output, "[DRY-RUN] install") {
		t.Fatalf("dry-run newer-current guard must not preview download or replacement:\n%s", result.output)
	}
}

func TestInstallerUpdateDoesNotInstallCoresInsideUpgradeTransaction(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "packaging", "install.sh"), "--upgrade", "--yes", "--dry-run")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("dry-run upgrade failed: %v\n%s", err, out)
	}
	text := string(out)
	for _, forbidden := range []string{
		"[DRY-RUN] install /usr/local/bin/xray",
		"[DRY-RUN] install /usr/local/bin/sing-box",
		"确认安装/修复",
		"未指定 --install-xray",
		"未指定 --install-singbox",
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("dry-run upgrade must not run/prompt core install %q:\n%s", forbidden, text)
		}
	}
}

func TestInstallerReplacesRunningBinaryAtomicallyDuringUpdate(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"local migate_tmp",
		`mktemp "$(dirname "$MIGATE_BIN")/.migate.XXXXXX"`,
		"cat \"$TMP/migate\" > \"$migate_tmp\"",
		"chmod +x \"$migate_tmp\"",
		"mv -f \"$migate_tmp\" \"$MIGATE_BIN\"",
		"ln -sf \"$MIGATE_BIN\" \"$MIGATE_LINK\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer atomic binary replacement contract missing %q", want)
		}
	}
	if strings.Contains(script, "cp \"$TMP/migate\" /usr/local/bin/migate") {
		t.Fatalf("installer must not cp over the running migate binary; use temp file plus atomic mv")
	}
}

func TestInstallerUpgradeSuccessWritesPersistentStatusAfterHealthCheck(t *testing.T) {
	env := newInstallerHarness(t, "success")
	result := env.run(t)
	if result.err != nil {
		t.Fatalf("upgrade failed: %v\n%s", result.err, result.output)
	}
	if got := readFile(t, env.migateBin); !strings.Contains(got, "new migate") {
		t.Fatalf("expected new migate binary, got %q", got)
	}
	if got := readFile(t, env.servicePath); !strings.Contains(got, "ExecStart="+env.migateBin) {
		t.Fatalf("expected rewritten service, got %q", got)
	}
	status := readFile(t, env.updateStatusPath)
	for _, want := range []string{`"status": "completed"`, `"target_version": "v2.0.0"`, `"health_check": "systemctl is-active migate: active`, `"rolled_back": false`} {
		if !strings.Contains(status, want) {
			t.Fatalf("successful status missing %q: %s", want, status)
		}
	}
	versions := readFile(t, env.versionsPath)
	if !strings.Contains(versions, `"installer_version": "v2.0.0"`) {
		t.Fatalf("versions state must be written after success: %s", versions)
	}
}

func TestInstallerUpgradeRollsBackOldBinaryAndServiceWhenNewHealthCheckFails(t *testing.T) {
	env := newInstallerHarness(t, "fail-new")
	result := env.run(t)
	if result.err == nil {
		t.Fatalf("expected failed upgrade with rollback\n%s", result.output)
	}
	if got := readFile(t, env.migateBin); !strings.Contains(got, "old migate") {
		t.Fatalf("expected old migate binary after rollback, got %q", got)
	}
	if got := readFile(t, env.servicePath); !strings.Contains(got, "old-service") {
		t.Fatalf("expected old service after rollback, got %q", got)
	}
	status := readFile(t, env.updateStatusPath)
	for _, want := range []string{`"status": "failed"`, `"message": "升级失败，已回滚，服务已恢复"`, `"rolled_back": true`, `"rollback_status": "restored"`} {
		if !strings.Contains(status, want) {
			t.Fatalf("rollback status missing %q: %s", want, status)
		}
	}
	if !strings.Contains(result.output, "升级失败，已回滚") {
		t.Fatalf("rollback output missing clear message:\n%s", result.output)
	}
}

func TestInstallerUpgradeRollsBackWhenLocalAPIHealthFails(t *testing.T) {
	env := newInstallerHarness(t, "fail-http")
	result := env.run(t)
	if result.err == nil {
		t.Fatalf("expected local API health failure with rollback\n%s", result.output)
	}
	if got := readFile(t, env.migateBin); !strings.Contains(got, "old migate") {
		t.Fatalf("expected old migate binary after API health rollback, got %q", got)
	}
	status := readFile(t, env.updateStatusPath)
	for _, want := range []string{`"status": "failed"`, `"message": "升级失败，已回滚，服务已恢复"`, `"rolled_back": true`, `"rollback_status": "restored"`} {
		if !strings.Contains(status, want) {
			t.Fatalf("API health rollback status missing %q: %s", want, status)
		}
	}
	if !strings.Contains(result.output, "/api/health: failed") || !strings.Contains(result.output, "/api/version: failed") {
		t.Fatalf("API health rollback output missing endpoint failures:\n%s", result.output)
	}
}

func TestInstallerUpgradeRollsBackWhenReplacementFailsAfterBackup(t *testing.T) {
	env := newInstallerHarness(t, "fail-replace")
	result := env.run(t)
	if result.err == nil {
		t.Fatalf("expected replacement failure with rollback\n%s", result.output)
	}
	if got := readFile(t, env.migateBin); !strings.Contains(got, "old migate") {
		t.Fatalf("expected old migate binary after replacement rollback, got %q", got)
	}
	if got := readFile(t, env.servicePath); !strings.Contains(got, "old-service") {
		t.Fatalf("expected old service after replacement rollback, got %q", got)
	}
	status := readFile(t, env.updateStatusPath)
	for _, want := range []string{`"status": "failed"`, `"message": "升级失败，已回滚，服务已恢复"`, `"rolled_back": true`, `"rollback_status": "restored"`} {
		if !strings.Contains(status, want) {
			t.Fatalf("replacement rollback status missing %q: %s", want, status)
		}
	}
	if !strings.Contains(result.output, "升级过程失败或健康检查失败") || !strings.Contains(result.output, "升级失败，已回滚") {
		t.Fatalf("replacement rollback output missing clear messages:\n%s", result.output)
	}
}

func TestInstallerRollbackDoesNotDeleteUnexpectedDirectories(t *testing.T) {
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		`elif [ -d "$dest" ] && [ ! -L "$dest" ]; then`,
		`log_error "回滚目标是目录，未自动删除：$dest"`,
		`return 1`,
		`restore_file_if_backed_up "$backup_root/bin/migate" "$MIGATE_BIN" || ok=0`,
		`[ "$ok" -eq 1 ] || return 1`,
		`systemctl daemon-reload || return 1`,
		`systemctl restart migate || return 1`,
		`rm -f "$dest"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("rollback directory safety contract missing %q", want)
		}
	}
	if strings.Contains(script, `rm -rf "$dest"`) {
		t.Fatalf("rollback must not recursively delete configured target paths")
	}
}

func TestUninstallScriptStopsServicesAndRemovesInstalledArtifacts(t *testing.T) {
	script := read(t, "packaging", "uninstall.sh")
	for _, want := range []string{
		"DRY_RUN=0",
		"--dry-run",
		"run_cmd()",
		"[DRY-RUN]",
		`MIGATE_SERVICE="migate"`,
		`XRAY_SERVICE="migate-xray"`,
		`SINGBOX_SERVICE="migate-sing-box"`,
		`systemctl stop "$service"`,
		`systemctl disable "$service"`,
		`rm -f "$unit_path"`,
		`rm -f "$MIGATE_BINARY"`,
		`rm -f "$MIGATE_LINK"`,
		`SINGBOX_SERVICE_PATH="/etc/systemd/system/migate-sing-box.service"`,
		`XRAY_SERVICE_PATH="/etc/systemd/system/migate-xray.service"`,
		"systemctl daemon-reload",
		"systemctl reset-failed",
		"--purge",
		`rm -rf "$MIGATE_CONFIG_DIR"`,
		`rm -rf "$MIGATE_DATA_DIR"`,
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("uninstall script missing %q", want)
		}
	}

	if strings.Contains(strings.ToLower(script), "xray-install") {
		t.Fatalf("uninstall must not remove third-party Xray installation by default")
	}
	for _, forbidden := range []string{
		"XRAY_LEGACY_DROPIN",
		"XRAY_COMPAT_CONFIG_LINK",
		"rm -f /etc/migate/cores/xray.json",
		"rm -rf /etc/migate/cores",
	} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("uninstall must not keep legacy runtime cleanup marker %q", forbidden)
		}
	}
}

func TestInstallAndUninstallScriptsKeepOpsContractPathsAndSafety(t *testing.T) {
	install := read(t, "packaging", "install.sh")
	uninstall := read(t, "packaging", "uninstall.sh")

	for _, want := range []string{
		`CONFIG_DIR="${MIGATE_CONFIG_DIR:-/etc/migate}"`,
		`CONFIG_PATH="${MIGATE_CONFIG_PATH:-/etc/migate/panel.json}"`,
		`VERSIONS_PATH="${MIGATE_VERSIONS_PATH:-/var/lib/migate/versions.json}"`,
		`BACKUP_DIR="${MIGATE_BACKUP_DIR:-/var/lib/migate/backups}"`,
		`RUN_DIR="${MIGATE_RUN_DIR:-/run/migate}"`,
		`INSTALL_LOCK="${MIGATE_INSTALL_LOCK:-/run/migate/install.lock}"`,
		`XRAY_SERVICE_PATH="${XRAY_SERVICE_PATH:-/etc/systemd/system/migate-xray.service}"`,
		`SINGBOX_SERVICE_PATH="${SINGBOX_SERVICE_PATH:-/etc/systemd/system/migate-sing-box.service}"`,
		`INSTALL_LOCK="${TMPDIR:-/tmp}/migate-install.$$.lock"`,
	} {
		if !strings.Contains(install, want) {
			t.Fatalf("install script ops contract missing %q", want)
		}
	}

	for _, want := range []string{
		`MIGATE_SERVICE="migate"`,
		`XRAY_SERVICE="migate-xray"`,
		`SINGBOX_SERVICE="migate-sing-box"`,
		`MIGATE_CONFIG_DIR="/etc/migate"`,
		`MIGATE_DATA_DIR="/var/lib/migate"`,
		`MIGATE_LOG_DIR="/var/log/migate"`,
		`MIGATE_RUN_DIR="/run/migate"`,
		"Default uninstall keeps:",
		"Keeping MiGate config/data/logs",
		`if [ "$PURGE" -eq 1 ]; then`,
	} {
		if !strings.Contains(uninstall, want) {
			t.Fatalf("uninstall script ops contract missing %q", want)
		}
	}

	combined := install + "\n" + uninstall
	for _, forbidden := range []string{"/etc/sing-box/config.json", "/usr/local/migate", "/usr/local/etc/xray", "migate-singbox"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("install/uninstall scripts must not contain legacy marker %q", forbidden)
		}
	}
}

func TestUninstallDryRunPrintsPlannedCommands(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "packaging", "uninstall.sh"), "--dry-run", "--yes")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("uninstall dry-run failed: %v\n%s", err, output)
	}
	for _, want := range []string{
		"[DRY-RUN] systemctl stop migate",
		"[DRY-RUN] rm -f /usr/local/bin/migate",
		"Keeping MiGate config/data",
	} {
		if !strings.Contains(string(output), want) {
			t.Fatalf("uninstall dry-run missing %q:\n%s", want, output)
		}
	}
}

func TestInstallerUninstallDryRunDelegatesWithoutEmptyArgument(t *testing.T) {
	root := repoRoot(t)
	cmd := exec.Command("bash", filepath.Join(root, "packaging", "install.sh"), "--uninstall", "--dry-run", "--yes")
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("installer uninstall dry-run failed: %v\n%s", err, output)
	}
	out := string(output)
	for _, want := range []string{
		"[DRY-RUN] systemctl stop migate",
		"[DRY-RUN] rm -f /usr/local/bin/migate",
		"MiGate uninstalled.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("installer uninstall dry-run missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Unknown option") {
		t.Fatalf("installer passed an empty or invalid option to uninstaller:\n%s", out)
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
	script := read(t, "packaging", "install.sh")
	for _, want := range []string{
		"ExecStart=/usr/local/bin/migate serve",
		"--host 0.0.0.0",
		"--config /etc/migate/panel.json",
		"Restart=on-failure",
		"NoNewPrivileges=true",
		"PrivateTmp=true",
		"ProtectSystem=strict",
		"ReadWritePaths=/etc/migate /var/lib/migate /var/log/migate /run/migate /usr/local/bin /usr/local/share/xray /etc/systemd/system",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("service missing %q: %s", want, service)
		}
	}
	for _, want := range []string{
		`mkdir -p "$CONFIG_DIR" "$CORE_CONFIG_DIR" "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$RUN_DIR" "$(dirname "$MIGATE_BIN")" "$(dirname "$INSTALLER_BIN")" "$(dirname "$UNINSTALLER_BIN")" "$XRAY_SHARE_DIR" "$(dirname "$SERVICE_PATH")"`,
		`chown root:migate "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$RUN_DIR"`,
		`chmod 0770 "$DATA_DIR" "$BACKUP_DIR" "$LOG_DIR" "$RUN_DIR"`,
		"ProtectSystem=strict",
		`ReadWritePaths=${CONFIG_DIR} ${DATA_DIR} ${LOG_DIR} ${RUN_DIR} $(dirname "$MIGATE_BIN") ${XRAY_SHARE_DIR} $(dirname "$SERVICE_PATH")`,
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("installer-generated service missing permission contract %q", want)
		}
	}
	for _, forbidden := range []string{
		"ProtectHome=",
		"SystemCallFilter=",
	} {
		if strings.Contains(service, forbidden) {
			t.Fatalf("service must not restrict runtime management permissions with %q: %s", forbidden, service)
		}
		if strings.Contains(script, forbidden) {
			t.Fatalf("installer-generated service must not restrict runtime management permissions with %q", forbidden)
		}
	}
	forbidden := []string{"python", "uv", "pip", "npm", join("open", "vpn"), "tun", "egress", "remote", "leak", "rollout"}
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
		forbidden := []string{".git/", "node_modules/", "python", join("open", "vpn"), "rollout", "leak", "egress"}
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

func TestBuildReleaseScriptStripsReleaseBinaries(t *testing.T) {
	script := read(t, "packaging", "build-release.sh")
	if !strings.Contains(script, "-ldflags \"-s -w -X main.Version=${VERSION}\"") {
		t.Fatalf("release build must strip symbols/debug info with -s -w: %s", script)
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
		"actions/setup-node",
		"node-version: 24",
		"cache: npm",
		"cache-dependency-path: web/package-lock.json",
		"packaging/build-release.sh",
		"sha256sum -c checksums.txt",
		"softprops/action-gh-release",
		"dist/migate-linux-amd64.tar.gz",
		"dist/migate-linux-arm64.tar.gz",
		"dist/checksums.txt",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing %q", want)
		}
	}

	forbidden := []string{"npm install", "npm run", "node_modules", "pip", "uv ", "python", join("open", "vpn"), "rollout", "leak", "egress"}
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

type installerHarness struct {
	root             string
	binDir           string
	fakeBin          string
	releaseDir       string
	configDir        string
	dataDir          string
	backupDir        string
	logDir           string
	runDir           string
	systemdDir       string
	configPath       string
	servicePath      string
	migateBin        string
	migateLink       string
	installerBin     string
	uninstallerBin   string
	versionsPath     string
	updateStatusPath string
	scenario         string
}

type installerRunResult struct {
	output string
	err    error
}

func newInstallerHarness(t *testing.T, scenario string) *installerHarness {
	t.Helper()
	root := t.TempDir()
	env := &installerHarness{
		root:       root,
		binDir:     filepath.Join(root, "bin"),
		fakeBin:    filepath.Join(root, "fake-bin"),
		releaseDir: filepath.Join(root, "release"),
		configDir:  filepath.Join(root, "etc", "migate"),
		dataDir:    filepath.Join(root, "var", "lib", "migate"),
		backupDir:  filepath.Join(root, "var", "lib", "migate", "backups"),
		logDir:     filepath.Join(root, "var", "log", "migate"),
		runDir:     filepath.Join(root, "run", "migate"),
		systemdDir: filepath.Join(root, "etc", "systemd", "system"),
		scenario:   scenario,
	}
	env.configPath = filepath.Join(env.configDir, "panel.json")
	env.servicePath = filepath.Join(env.systemdDir, "migate.service")
	env.migateBin = filepath.Join(env.binDir, "migate")
	env.migateLink = filepath.Join(env.binDir, "mg")
	env.installerBin = filepath.Join(env.binDir, "migate-install")
	env.uninstallerBin = filepath.Join(env.binDir, "migate-uninstall")
	env.versionsPath = filepath.Join(env.dataDir, "versions.json")
	env.updateStatusPath = filepath.Join(env.dataDir, "update-status.json")
	for _, dir := range []string{env.binDir, env.fakeBin, env.releaseDir, env.configDir, env.dataDir, env.backupDir, env.logDir, env.runDir, env.systemdDir, filepath.Join(env.root, "run", "systemd", "system")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	writeExecutable(t, env.migateBin, "#!/usr/bin/env bash\ncase \"$1\" in version) if [ \"${MIGATE_TEST_SCENARIO:-}\" = \"newer-current\" ]; then echo 'MiGate version: v2.1.0'; else echo 'MiGate version: v1.0.0'; fi ;; hash-password) echo 'hashed-password' ;; ensure-management-direct) echo 'management direct defaults ensured' ;; *) echo 'old migate' ;; esac\n")
	writeExecutable(t, env.installerBin, "#!/usr/bin/env bash\necho old installer\n")
	writeExecutable(t, env.uninstallerBin, "#!/usr/bin/env bash\necho old uninstaller\n")
	if err := os.WriteFile(env.servicePath, []byte("[Service]\nExecStart=old-service\n"), 0644); err != nil {
		t.Fatalf("write service: %v", err)
	}
	if err := os.WriteFile(env.configPath, []byte(`{"panel_port":19999,"panel_username":"admin","web_base_path":"/panel","database_path":"`+env.dataDir+`/migate.db"}`), 0640); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(env.versionsPath, []byte(`{"installer_version":"v1.0.0"}`), 0640); err != nil {
		t.Fatalf("write versions: %v", err)
	}
	createFakeRelease(t, env.releaseDir)
	env.writeFakeCommands(t)
	return env
}

func (h *installerHarness) run(t *testing.T) installerRunResult {
	t.Helper()
	return h.runWithVersion(t, "v2.0.0")
}

func (h *installerHarness) runWithVersion(t *testing.T, version string) installerRunResult {
	t.Helper()
	return h.runWithArgs(t, version)
}

func (h *installerHarness) runWithArgs(t *testing.T, version string, args ...string) installerRunResult {
	t.Helper()
	cmdArgs := append([]string{filepath.Join(repoRoot(t), "packaging", "install.sh"), "--upgrade", "--yes"}, args...)
	cmd := exec.Command("bash", cmdArgs...)
	cmd.Env = append(os.Environ(),
		"PATH="+h.fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MIGATE_VERSION="+version,
		"MIGATE_REPO=local/MiGate",
		"MIGATE_DATA_DIR="+h.dataDir,
		"MIGATE_BACKUP_DIR="+h.backupDir,
		"MIGATE_LOG_DIR="+h.logDir,
		"MIGATE_RUN_DIR="+h.runDir,
		"MIGATE_INSTALL_LOCK="+filepath.Join(h.runDir, "install.lock"),
		"MIGATE_CONFIG_DIR="+h.configDir,
		"MIGATE_CONFIG_PATH="+h.configPath,
		"MIGATE_CORE_CONFIG_DIR="+filepath.Join(h.configDir, "cores"),
		"MIGATE_XRAY_CONFIG_PATH="+filepath.Join(h.configDir, "cores", "xray.json"),
		"MIGATE_SINGBOX_CONFIG_PATH="+filepath.Join(h.configDir, "cores", "sing-box.json"),
		"MIGATE_SERVICE_PATH="+h.servicePath,
		"MIGATE_BIN="+h.migateBin,
		"MIGATE_LINK="+h.migateLink,
		"INSTALLER_BIN="+h.installerBin,
		"UNINSTALLER_BIN="+h.uninstallerBin,
		"MIGATE_VERSIONS_PATH="+h.versionsPath,
		"MIGATE_UPDATE_STATUS_PATH="+h.updateStatusPath,
		"MIGATE_XRAY_SHARE_DIR="+filepath.Join(h.root, "usr", "local", "share", "xray"),
		"JOURNALD_CONF_DIR="+filepath.Join(h.root, "etc", "systemd", "journald.conf.d"),
		"LOGROTATE_CONF_DIR="+filepath.Join(h.root, "etc", "logrotate.d"),
		"MIGATE_FAKE_RELEASE_DIR="+h.releaseDir,
		"MIGATE_TEST_SCENARIO="+h.scenario,
		"MIGATE_TEST_STATE="+filepath.Join(h.root, "systemctl-state"),
		"MIGATE_SYSTEMD_RUNTIME_DIR="+filepath.Join(h.root, "run", "systemd", "system"),
	)
	out, err := cmd.CombinedOutput()
	return installerRunResult{output: string(out), err: err}
}

func createFakeRelease(t *testing.T, releaseDir string) {
	t.Helper()
	work := filepath.Join(releaseDir, "work")
	if err := os.MkdirAll(filepath.Join(work, "packaging"), 0755); err != nil {
		t.Fatalf("mkdir release work: %v", err)
	}
	writeExecutable(t, filepath.Join(work, "migate"), "#!/usr/bin/env bash\ncase \"$1\" in version) echo 'MiGate version: v2.0.0' ;; hash-password) echo 'hashed-password' ;; *) echo 'new migate' ;; esac\n")
	writeExecutable(t, filepath.Join(work, "packaging", "install.sh"), "#!/usr/bin/env bash\necho new installer\n")
	writeExecutable(t, filepath.Join(work, "packaging", "uninstall.sh"), "#!/usr/bin/env bash\necho new uninstaller\n")
	archive := filepath.Join(releaseDir, "migate-linux-amd64.tar.gz")
	file, err := os.Create(archive)
	if err != nil {
		t.Fatalf("create archive: %v", err)
	}
	gz := gzip.NewWriter(file)
	tw := tar.NewWriter(gz)
	for _, rel := range []string{"migate", "packaging/install.sh", "packaging/uninstall.sh"} {
		path := filepath.Join(work, rel)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat release file: %v", err)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			t.Fatalf("tar header: %v", err)
		}
		header.Name = rel
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("tar write header: %v", err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read release file: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write file: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("archive close: %v", err)
	}
	if err := os.WriteFile(filepath.Join(releaseDir, "checksums.txt"), []byte("skip  migate-linux-amd64.tar.gz\n"), 0644); err != nil {
		t.Fatalf("write checksums: %v", err)
	}
}

func (h *installerHarness) writeFakeCommands(t *testing.T) {
	t.Helper()
	writeExecutable(t, filepath.Join(h.fakeBin, "uname"), "#!/usr/bin/env bash\nif [ \"${1:-}\" = \"-s\" ]; then echo Linux; else echo x86_64; fi\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "id"), "#!/usr/bin/env bash\nif [ \"${1:-}\" = \"-u\" ]; then echo 0; else /usr/bin/id \"$@\"; fi\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "getent"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "pgrep"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "chown"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "journalctl"), "#!/usr/bin/env bash\nexit 0\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "ss"), "#!/usr/bin/env bash\nexit 1\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "cat"), "#!/usr/bin/env bash\nif [ \"${MIGATE_TEST_SCENARIO:-}\" = \"fail-replace\" ] && [ \"$#\" -eq 1 ] && [ \"$(basename \"$1\")\" = \"migate\" ]; then exit 1; fi\n/bin/cat \"$@\"\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "curl"), "#!/usr/bin/env bash\nset -euo pipefail\nout=''\nurl=''\nwhile [ \"$#\" -gt 0 ]; do\n  case \"$1\" in\n    -o) out=\"$2\"; shift 2 ;;\n    --max-time) shift 2 ;;\n    -*) shift ;;\n    *) url=\"$1\"; shift ;;\n  esac\ndone\nif [ -n \"$out\" ]; then\n  case \"$url\" in\n    *checksums.txt) cp \"$MIGATE_FAKE_RELEASE_DIR/checksums.txt\" \"$out\" ;;\n    *migate-linux-amd64.tar.gz) cp \"$MIGATE_FAKE_RELEASE_DIR/migate-linux-amd64.tar.gz\" \"$out\" ;;\n    *) echo '{}' > \"$out\" ;;\n  esac\n  exit 0\nfi\ncase \"$url\" in\n  *api/health|*api/version)\n    count=0\n    [ -f \"${MIGATE_TEST_STATE:-}\" ] && count=$(cat \"$MIGATE_TEST_STATE\")\n    if [ \"${MIGATE_TEST_SCENARIO:-}\" = \"fail-http\" ] && [ \"$count\" -eq 1 ]; then exit 7; fi\n    exit 0\n    ;;\n  *releases/latest) echo '{\"tag_name\":\"v2.0.0\"}' ;;\n  *) echo '{}' ;;\nesac\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "sha256sum"), "#!/usr/bin/env bash\nif [ \"${1:-}\" = \"-c\" ]; then exit 0; fi\n/usr/bin/shasum -a 256 \"$@\"\n")
	writeExecutable(t, filepath.Join(h.fakeBin, "systemctl"), "#!/usr/bin/env bash\nset -euo pipefail\nstate=\"${MIGATE_TEST_STATE:-/tmp/migate-test-systemctl-state}\"\ncmd=\"${1:-}\"\nsvc=\"${2:-}\"\ncase \"$cmd\" in\n  list-unit-files|daemon-reload|enable|stop) exit 0 ;;\n  restart)\n    if [ \"$svc\" = \"migate\" ]; then\n      count=0\n      [ -f \"$state\" ] && count=$(cat \"$state\")\n      count=$((count + 1))\n      echo \"$count\" > \"$state\"\n    fi\n    exit 0\n    ;;\n  is-active)\n    count=0\n    [ -f \"$state\" ] && count=$(cat \"$state\")\n    if [ \"${MIGATE_TEST_SCENARIO:-}\" = \"fail-new\" ] && [ \"$count\" -eq 1 ]; then exit 3; fi\n    if [ \"${2:-}\" != \"--quiet\" ]; then echo active; fi\n    exit 0\n    ;;\nesac\nexit 0\n")
}

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir executable dir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}
