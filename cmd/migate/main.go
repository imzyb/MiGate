package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	panelcfg "github.com/imzyb/MiGate/internal/config"
	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/paths"
	runtimecmd "github.com/imzyb/MiGate/internal/runtime/command"
	"github.com/imzyb/MiGate/internal/scheduler"
	certsvc "github.com/imzyb/MiGate/internal/service/cert"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/xray"
	_ "modernc.org/sqlite"
)

// Version is set via ldflags at build time.
var Version = "dev"

var defaultPanelConfigPath = paths.PanelConfig

type lang string

const (
	langZh lang = "zh"
	langEn lang = "en"
)

func detectLang(args []string) (lang, []string) {
	for i, arg := range args {
		if arg == "--lang" && i+1 < len(args) {
			rest := append([]string{}, args[:i]...)
			rest = append(rest, args[i+2:]...)
			return lang(args[i+1]), rest
		}
	}
	if v := os.Getenv("MIGATE_LANG"); v != "" {
		return lang(v), args
	}
	return langZh, args
}

func (l lang) valid() bool {
	return l == langZh || l == langEn
}

type messages struct {
	cliMenuHeader             string
	cliMenuUsage              string
	cliMenuCommonCommands     string
	cliMenuServiceMode        string
	statusPanelRunning        string
	statusPanelStopped        string
	statusXrayRunning         string
	statusXrayStopped         string
	statusSingboxRunning      string
	statusSingboxStopped      string
	doctorHeader              string
	doctorConfigOk            string
	doctorConfigMissing       string
	doctorDatabaseOk          string
	doctorDatabaseMissing     string
	doctorDatabaseUnreadable  string
	doctorXrayInstalled       string
	doctorXrayNotInstalled    string
	doctorSingboxInstalled    string
	doctorSingboxNotInstalled string
	doctorServiceStatus       string
	doctorCoreConfig          string
	doctorDirectory           string
	doctorExists              string
	doctorMissing             string
	doctorMemory              string
	doctorDisk                string
	infoHeader                string
	infoVersion               string
	infoUsername              string
	infoConfig                string
	infoDatabase              string
	infoPasswordHidden        string
	resetPasswordUpdated      string
	portsHeader               string
	portsPanel                string
	portsXrayAPI              string
	portsSingboxAPI           string
	unsupportedLanguage       string
}

var msgZh = messages{
	cliMenuHeader:             "MiGate CLI",
	cliMenuUsage:              "用法:",
	cliMenuCommonCommands:     "常用命令:",
	cliMenuServiceMode:        "服务模式:",
	statusPanelRunning:        "MiGate 面板: 运行中",
	statusPanelStopped:        "MiGate 面板: 已停止",
	statusXrayRunning:         "Xray: 运行中",
	statusXrayStopped:         "Xray: 已停止",
	statusSingboxRunning:      "sing-box: 运行中",
	statusSingboxStopped:      "sing-box: 已停止",
	doctorHeader:              "MiGate 诊断",
	doctorConfigOk:            "配置文件: 正常",
	doctorConfigMissing:       "配置文件: 缺失或不可读",
	doctorDatabaseOk:          "数据库: 正常",
	doctorDatabaseMissing:     "数据库: 缺失",
	doctorDatabaseUnreadable:  "数据库: 不可打开",
	doctorXrayInstalled:       "Xray: 已安装",
	doctorXrayNotInstalled:    "Xray: 未安装",
	doctorSingboxInstalled:    "sing-box: 已安装",
	doctorSingboxNotInstalled: "sing-box: 未安装",
	doctorServiceStatus:       "服务状态",
	doctorCoreConfig:          "核心配置",
	doctorDirectory:           "目录",
	doctorExists:              "存在",
	doctorMissing:             "缺失",
	doctorMemory:              "内存:",
	doctorDisk:                "磁盘:",
	infoHeader:                "MiGate 信息",
	infoVersion:               "版本:",
	infoUsername:              "用户名:",
	infoConfig:                "配置文件:",
	infoDatabase:              "数据库:",
	infoPasswordHidden:        "密码: 隐藏 (使用 mg reset-password)",
	resetPasswordUpdated:      "面板密码已更新:",
	portsHeader:               "MiGate 端口",
	portsPanel:                "面板",
	portsXrayAPI:              "Xray Stats API",
	portsSingboxAPI:           "sing-box Stats API",
	unsupportedLanguage:       "不支持的语言 %q，仅支持: zh, en",
}

var msgEn = messages{
	cliMenuHeader:             "MiGate CLI",
	cliMenuUsage:              "Usage:",
	cliMenuCommonCommands:     "Common commands:",
	cliMenuServiceMode:        "Service mode:",
	statusPanelRunning:        "MiGate Panel: running",
	statusPanelStopped:        "MiGate Panel: stopped",
	statusXrayRunning:         "Xray: running",
	statusXrayStopped:         "Xray: stopped",
	statusSingboxRunning:      "sing-box: running",
	statusSingboxStopped:      "sing-box: stopped",
	doctorHeader:              "MiGate Doctor",
	doctorConfigOk:            "Config: ok",
	doctorConfigMissing:       "Config: missing or unreadable",
	doctorDatabaseOk:          "Database: ok",
	doctorDatabaseMissing:     "Database: missing",
	doctorDatabaseUnreadable:  "Database: unreadable",
	doctorXrayInstalled:       "Xray: installed",
	doctorXrayNotInstalled:    "Xray: not installed",
	doctorSingboxInstalled:    "sing-box: installed",
	doctorSingboxNotInstalled: "sing-box: not installed",
	doctorServiceStatus:       "Service status",
	doctorCoreConfig:          "Core config",
	doctorDirectory:           "Directory",
	doctorExists:              "exists",
	doctorMissing:             "missing",
	doctorMemory:              "Memory:",
	doctorDisk:                "Disk:",
	infoHeader:                "MiGate Info",
	infoVersion:               "Version:",
	infoUsername:              "Username:",
	infoConfig:                "Config:",
	infoDatabase:              "Database:",
	infoPasswordHidden:        "Password: hidden (use mg reset-password)",
	resetPasswordUpdated:      "Panel password updated:",
	portsHeader:               "MiGate Ports",
	portsPanel:                "panel",
	portsXrayAPI:              "Xray Stats API",
	portsSingboxAPI:           "sing-box Stats API",
	unsupportedLanguage:       "unsupported language %q, supported: zh, en",
}

const (
	xrayStatsPort    = 10085
	singboxStatsPort = 10086
)

func msg(l lang) messages {
	if l == langEn {
		return msgEn
	}
	return msgZh
}

type commandMode int

const (
	modeCLI commandMode = iota
	modeServe
)

type commandRunner interface {
	Run(name string, args ...string) (string, error)
}

type osRunner struct{}

func (osRunner) Run(name string, args ...string) (string, error) {
	out, err := runtimecmd.RunOutput(context.Background(), name, args...)
	return string(out), err
}

func main() {
	args := os.Args[1:]
	// Strip --lang before mode detection so it doesn't interfere with serve flags
	_, args = detectLang(args)
	if detectCommandMode(args) == modeCLI {
		// Re-parse with original args to get language
		os.Exit(runCLI(os.Args[1:], os.Stdout, os.Stderr, osRunner{}))
	}
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	os.Exit(runServer(args))
}

func detectCommandMode(args []string) commandMode {
	if len(args) == 0 {
		return modeCLI
	}
	if args[0] == "serve" {
		return modeServe
	}
	// Backward compatibility for systemd units installed before the explicit serve subcommand.
	if strings.HasPrefix(args[0], "-") {
		return modeServe
	}
	return modeCLI
}

func runServer(args []string) int {
	var host string
	var port int
	var configPath string
	fs := flag.NewFlagSet("migate serve", flag.ExitOnError)
	fs.StringVar(&host, "host", "127.0.0.1", "bind host")
	fs.IntVar(&port, "port", 9999, "bind port")
	fs.StringVar(&configPath, "config", "", "panel config path")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	if strings.TrimSpace(configPath) == "" {
		fmt.Fprintln(os.Stderr, "serve mode requires --config with panel credentials")
		return 1
	}

	cfg, err := panelcfg.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read config %s: %v\n", configPath, err)
		return 1
	}
	if cfg.PanelPort > 0 {
		port = cfg.PanelPort
	}
	configuredRouter, cleanup, err := routerFromConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build router from config %s: %v\n", configPath, err)
		return 1
	}
	defer cleanup()

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("MiGate listening on %s", addr)

	srv := &http.Server{Addr: addr, Handler: configuredRouter}

	// Graceful shutdown on SIGINT/SIGTERM
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Println("shutting down gracefully...")
		cleanup()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func runCLI(args []string, stdout, stderr io.Writer, runner commandRunner) int {
	language, args := detectLang(args)
	if !language.valid() {
		fmt.Fprintf(stderr, msgEn.unsupportedLanguage+"\n", language)
		return 2
	}
	m := msg(language)

	if len(args) == 0 {
		printCLIMenu(stdout, m)
		return 0
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "MiGate version: %s\n", Version)
		return 0
	case "status":
		return cliStatus(stdout, stderr, runner, m)
	case "doctor":
		return cliDoctor(stdout, stderr, runner, m)
	case "info":
		return cliInfo(stdout, stderr, m)
	case "reset-password":
		return cliResetPassword(stdout, stderr, runner, m, args[1:])
	case "hash-password":
		return cliHashPassword(stdout, stderr, args[1:])
	case "ensure-management-direct":
		return cliEnsureManagementDirect(stdout, stderr, args[1:])
	case "start", "stop":
		return cliSystemctl(stderr, runner, args[0], paths.PanelService)
	case "restart":
		return cliRestart(stderr, runner, args[1:])
	case "logs":
		return cliLogs(stdout, stderr, runner, args[1:])
	case "url":
		return cliURL(stdout, stderr, runner, args[1:])
	case "update":
		return cliUpdate(stdout, stderr, runner, args[1:])
	case "backup":
		return cliBackup(stdout, stderr, runner, args[1:])
	case "restore":
		return cliRestore(stdout, stderr, runner, args[1:])
	case "ports":
		return cliPorts(stdout, stderr, runner, m)
	case "uninstall":
		out, err := runner.Run(paths.Uninstaller, args[1:]...)
		fmt.Fprint(stdout, out)
		if err != nil {
			fmt.Fprintf(stderr, "uninstall failed: %v\n", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command: %s\n\n", args[0])
		printCLIMenu(stderr, m)
		return 2
	}
}

func cliHashPassword(stdout, stderr io.Writer, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: mg hash-password <password>")
		return 2
	}
	hashed, err := web.HashPanelPassword(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "hash password: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, hashed)
	return 0
}

func cliEnsureManagementDirect(stdout, stderr io.Writer, args []string) int {
	fs := flag.NewFlagSet("mg ensure-management-direct", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := defaultPanelConfigPath
	hosts := multiFlag{}
	ports := multiFlag{}
	fs.StringVar(&configPath, "config", configPath, "panel config path")
	fs.Var(&hosts, "host", "management host or IP to protect")
	fs.Var(&ports, "port", "management port to protect")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(configPath) == "" {
		fmt.Fprintln(stderr, "config path is required")
		return 2
	}
	parsedPorts := []int{}
	for _, raw := range ports {
		var port int
		if _, err := fmt.Sscanf(strings.TrimSpace(raw), "%d", &port); err != nil {
			continue
		}
		parsedPorts = append(parsedPorts, port)
	}
	if _, err := panelcfg.EnsureManagementDirectDefaults(configPath, hosts, parsedPorts); err != nil {
		fmt.Fprintf(stderr, "ensure management direct: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "management direct defaults ensured")
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value != "" {
		*m = append(*m, value)
	}
	return nil
}

func printCLIMenu(w io.Writer, m messages) {
	fmt.Fprintf(w, `%s

%s
  mg <command>
  migate <command>

%s
  mg status          Show service status
  mg doctor          Run local diagnostics
  mg info            Show panel information
  mg url             Show WebUI URL
  mg url --public    Show WebUI URL with detected public IP
  mg reset-password [password]
                     Reset panel password and restart service
  mg start           Start MiGate panel
  mg stop            Stop MiGate panel
  mg restart         Restart MiGate panel
  mg restart all     Restart MiGate panel, Xray, and sing-box
  mg logs            Show recent logs
  mg logs -f         Follow MiGate logs
  mg update          Update to latest release
  mg update vX.Y.Z   Update to a specific release
  mg update --check  Check latest release only
  mg version         Show current version
  mg ports           Show configured/listening ports
  mg backup [file]   Backup config and runtime files
  mg restore <file>  Restore backup and restart service
  mg uninstall       Run MiGate uninstaller

%s
  migate serve --config /etc/migate/panel.json

`, m.cliMenuHeader, m.cliMenuUsage, m.cliMenuCommonCommands, m.cliMenuServiceMode)
}

func cliUpdate(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	updateArgs := []string{"--update"}
	if len(args) > 0 {
		if len(args) == 1 && args[0] == "--check" {
			updateArgs = []string{"--check"}
		} else if len(args) == 1 {
			updateArgs = append(updateArgs, "--version", args[0])
		} else {
			fmt.Fprintln(stderr, "usage: mg update [version|--check]")
			return 2
		}
	}
	out, err := runner.Run(paths.Installer, updateArgs...)
	fmt.Fprint(stdout, out)
	if err != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", err)
		return 1
	}
	return 0
}

func cliStatus(stdout, stderr io.Writer, runner commandRunner, m messages) int {
	code := 0
	services := []struct {
		name    string
		label   string
		running string
		stopped string
	}{
		{name: paths.PanelService, label: "MiGate", running: m.statusPanelRunning, stopped: m.statusPanelStopped},
		{name: paths.XrayService, label: "Xray", running: m.statusXrayRunning, stopped: m.statusXrayStopped},
		{name: paths.SingboxService, label: "sing-box", running: m.statusSingboxRunning, stopped: m.statusSingboxStopped},
	}
	for _, svc := range services {
		out, err := runner.Run("systemctl", "is-active", svc.name)
		status := strings.TrimSpace(out)
		if status == "active" {
			fmt.Fprintln(stdout, svc.running)
		} else {
			fmt.Fprintln(stdout, svc.stopped)
		}
		if err != nil && status == "" {
			fmt.Fprintf(stderr, "%s status check failed: %v\n", svc.name, err)
			code = 1
		}
	}
	return code
}

func cliDoctor(stdout, stderr io.Writer, runner commandRunner, m messages) int {
	healthy := true
	fmt.Fprintln(stdout, m.doctorHeader)
	fmt.Fprintf(stdout, "%s:\n", m.doctorServiceStatus)
	if !printDoctorServiceStatuses(stdout, stderr, runner, m) {
		healthy = false
	}
	cfg, err := panelcfg.Load(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stdout, "%s: %s (%v)\n", defaultPanelConfigPath, m.doctorConfigMissing, err)
		healthy = false
	} else {
		fmt.Fprintf(stdout, "%s: %s\n", defaultPanelConfigPath, m.doctorConfigOk)
		fmt.Fprintf(stdout, "WebUI: %s\n", panelURL(cfg, "SERVER_IP"))
		if !printDatabaseCheck(stdout, cfg.DatabasePath, m) {
			healthy = false
		}
	}
	if !printBinaryStatus(stdout, "Xray", paths.XrayBinary, m) {
		healthy = false
	}
	if !printBinaryStatus(stdout, "sing-box", paths.SingboxBinary, m) {
		healthy = false
	}
	if !printPathStatus(stdout, m.doctorCoreConfig, paths.XrayConfig, m) {
		healthy = false
	}
	if !printPathStatus(stdout, m.doctorCoreConfig, paths.SingboxConfig, m) {
		healthy = false
	}
	for _, dir := range []string{paths.BackupDir, paths.LogDir, paths.RunDir} {
		if !printPathStatus(stdout, m.doctorDirectory, dir, m) {
			healthy = false
		}
	}
	if out, err := runner.Run("ss", "-ltn"); err == nil && cfg.PanelPort > 0 {
		fmt.Fprintf(stdout, "Panel port %d: %s\n", cfg.PanelPort, listeningStatus(out, cfg.PanelPort))
	}
	if out, err := runner.Run("free", "-m"); err == nil {
		fmt.Fprintf(stdout, "%s\n%s", m.doctorMemory, out)
	}
	if out, err := runner.Run("df", "-h", "/"); err == nil {
		fmt.Fprintf(stdout, "%s\n%s", m.doctorDisk, out)
	}
	if !healthy {
		return 1
	}
	return 0
}

func printDoctorServiceStatuses(stdout, stderr io.Writer, runner commandRunner, m messages) bool {
	healthy := true
	services := []struct {
		name    string
		running string
		stopped string
	}{
		{name: paths.PanelService, running: m.statusPanelRunning, stopped: m.statusPanelStopped},
		{name: paths.XrayService, running: m.statusXrayRunning, stopped: m.statusXrayStopped},
		{name: paths.SingboxService, running: m.statusSingboxRunning, stopped: m.statusSingboxStopped},
	}
	for _, svc := range services {
		out, err := runner.Run("systemctl", "is-active", svc.name)
		status := strings.TrimSpace(out)
		if status == "active" {
			fmt.Fprintln(stdout, svc.running)
			continue
		}
		fmt.Fprintln(stdout, svc.stopped)
		healthy = false
		if err != nil && status == "" {
			fmt.Fprintf(stderr, "%s status check failed: %v\n", svc.name, err)
		}
	}
	return healthy
}

func printDatabaseCheck(stdout io.Writer, path string, m messages) bool {
	if strings.TrimSpace(path) == "" {
		return true
	}
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(stdout, "Database: %s (%s)\n", m.doctorDatabaseMissing, path)
		return false
	}
	database, err := sql.Open("sqlite", sqliteReadOnlyDSN(path))
	if err != nil {
		fmt.Fprintf(stdout, "Database: %s (%s: %v)\n", m.doctorDatabaseUnreadable, path, err)
		return false
	}
	defer database.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var schemaVersion int
	if err := database.QueryRowContext(ctx, `PRAGMA schema_version`).Scan(&schemaVersion); err != nil {
		fmt.Fprintf(stdout, "Database: %s (%s: %v)\n", m.doctorDatabaseUnreadable, path, err)
		return false
	}
	fmt.Fprintf(stdout, "%s (%s)\n", m.doctorDatabaseOk, path)
	return true
}

func sqliteReadOnlyDSN(path string) string {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	return u.String()
}

func printPathStatus(stdout io.Writer, label, path string, m messages) bool {
	status := m.doctorExists
	if _, err := os.Stat(path); err != nil {
		status = m.doctorMissing
		fmt.Fprintf(stdout, "%s: %s %s\n", label, path, status)
		return false
	}
	fmt.Fprintf(stdout, "%s: %s %s\n", label, path, status)
	return true
}

func cliInfo(stdout, stderr io.Writer, m messages) int {
	cfg, err := panelcfg.Load(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	fmt.Fprintln(stdout, m.infoHeader)
	fmt.Fprintf(stdout, "%s %s\n", m.infoVersion, Version)
	fmt.Fprintf(stdout, "WebUI: %s\n", panelURL(cfg, "SERVER_IP"))
	if cfg.PanelUsername != "" {
		fmt.Fprintf(stdout, "%s %s\n", m.infoUsername, cfg.PanelUsername)
	}
	fmt.Fprintf(stdout, "%s %s\n", m.infoConfig, defaultPanelConfigPath)
	if cfg.DatabasePath != "" {
		fmt.Fprintf(stdout, "%s %s\n", m.infoDatabase, cfg.DatabasePath)
	}
	fmt.Fprintln(stdout, m.infoPasswordHidden)
	return 0
}

func cliResetPassword(stdout, stderr io.Writer, runner commandRunner, m messages, args []string) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: mg reset-password [password]")
		return 2
	}
	cfg, err := panelcfg.Load(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	password := ""
	if len(args) == 1 {
		password = args[0]
	} else {
		password, err = generatedPassword()
		if err != nil {
			fmt.Fprintf(stderr, "generate password: %v\n", err)
			return 1
		}
	}
	hashed, err := web.HashPanelPassword(password)
	if err != nil {
		fmt.Fprintf(stderr, "hash password: %v\n", err)
		return 1
	}
	cfg.PanelPassword = hashed
	if err := panelcfg.Save(defaultPanelConfigPath, cfg); err != nil {
		fmt.Fprintf(stderr, "write %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	if code := cliSystemctl(stderr, runner, "restart", paths.PanelService); code != 0 {
		return code
	}
	fmt.Fprintf(stdout, "%s %s\n", m.resetPasswordUpdated, password)
	return 0
}

func cliLogs(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	logArgs := []string{"-u", paths.PanelService, "-n", "80"}
	if len(args) == 1 && args[0] == "-f" {
		logArgs = append(logArgs, "-f")
	} else if len(args) == 0 {
		logArgs = append(logArgs, "--no-pager")
	} else {
		fmt.Fprintln(stderr, "usage: mg logs [-f]")
		return 2
	}
	out, err := runner.Run("journalctl", logArgs...)
	fmt.Fprint(stdout, out)
	if err != nil {
		fmt.Fprintf(stderr, "logs failed: %v\n", err)
		return 1
	}
	return 0
}

func cliRestart(stderr io.Writer, runner commandRunner, args []string) int {
	if len(args) == 0 {
		return cliSystemctl(stderr, runner, "restart", paths.PanelService)
	}
	if len(args) == 1 && args[0] == "all" {
		for _, svc := range managedServices() {
			if svc.onlyIfManaged && !cliServiceAvailable(runner, svc.name) {
				continue
			}
			if code := cliSystemctl(stderr, runner, "restart", svc.name); code != 0 {
				return code
			}
		}
		return 0
	}
	fmt.Fprintln(stderr, "usage: mg restart [all]")
	return 2
}

func cliServiceAvailable(runner commandRunner, service string) bool {
	out, err := runner.Run("systemctl", "show", service, "--property=LoadState", "--value")
	state := strings.TrimSpace(out)
	if state == "not-found" {
		return false
	}
	if err != nil && state == "" {
		return false
	}
	return true
}

func cliSystemctl(stderr io.Writer, runner commandRunner, action, service string) int {
	out, err := runner.Run("systemctl", action, service)
	if err != nil {
		if strings.TrimSpace(out) != "" {
			fmt.Fprint(stderr, out)
			if !strings.HasSuffix(out, "\n") {
				fmt.Fprintln(stderr)
			}
		}
		fmt.Fprintf(stderr, "%s %s failed: %v\n", action, service, err)
		return 1
	}
	return 0
}

func cliURL(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	cfg, err := panelcfg.Load(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	host := "SERVER_IP"
	if len(args) == 1 && args[0] == "--public" {
		out, err := runner.Run("curl", "-fsS", "--max-time", "3", "https://api.ipify.org")
		if err != nil {
			fmt.Fprintf(stderr, "detect public IP failed: %v\n", err)
			return 1
		}
		host = strings.TrimSpace(out)
	} else if len(args) > 0 {
		fmt.Fprintln(stderr, "usage: mg url [--public]")
		return 2
	}
	fmt.Fprintf(stdout, "%s\n", panelURL(cfg, host))
	return 0
}

func cliBackup(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	path := defaultBackupPath()
	if len(args) == 1 {
		path = args[0]
	} else if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: mg backup [file]")
		return 2
	}
	files := backupFiles()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fmt.Fprintf(stderr, "create backup dir: %v\n", err)
		return 1
	}
	out, err := runner.Run("tar", append([]string{"-czf", path}, files...)...)
	fmt.Fprint(stdout, out)
	if err != nil {
		fmt.Fprintf(stderr, "backup failed: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Backup saved: %s\n", path)
	return 0
}

func cliRestore(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: mg restore <file>")
		return 2
	}
	out, err := runner.Run("tar", "-xzf", args[0], "-C", "/")
	fmt.Fprint(stdout, out)
	if err != nil {
		fmt.Fprintf(stderr, "restore failed: %v\n", err)
		return 1
	}
	if code := cliSystemctl(stderr, runner, "restart", paths.PanelService); code != 0 {
		return code
	}
	fmt.Fprintln(stdout, "Restore completed")
	return 0
}

func cliPorts(stdout, stderr io.Writer, runner commandRunner, m messages) int {
	cfg, err := panelcfg.Load(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	out, err := runner.Run("ss", "-ltn")
	if err != nil {
		fmt.Fprintf(stderr, "ports failed: %v\n", err)
		return 1
	}
	port := cfg.PanelPort
	if port == 0 {
		port = 9999
	}
	fmt.Fprintln(stdout, m.portsHeader)
	fmt.Fprintf(stdout, "%d %s %s\n", port, m.portsPanel, listeningStatus(out, port))
	fmt.Fprintf(stdout, "%d %s %s\n", xrayStatsPort, m.portsXrayAPI, listeningStatus(out, xrayStatsPort))
	fmt.Fprintf(stdout, "%d %s %s\n", singboxStatsPort, m.portsSingboxAPI, listeningStatus(out, singboxStatsPort))
	return 0
}

func localizedServiceStatus(status string) string {
	switch status {
	case "active":
		return "running"
	case "inactive":
		return "stopped"
	case "failed":
		return "failed"
	case "activating":
		return "starting"
	case "deactivating":
		return "stopping"
	default:
		return "unknown"
	}
}

type managedService struct {
	name          string
	label         string
	onlyIfManaged bool
}

func managedServices() []managedService {
	return []managedService{
		{name: paths.PanelService, label: "MiGate Panel"},
		{name: paths.XrayService, label: "Xray", onlyIfManaged: true},
		{name: paths.SingboxService, label: "sing-box", onlyIfManaged: true},
	}
}

func panelURL(cfg panelcfg.Config, host string) string {
	port := cfg.PanelPort
	if port == 0 {
		port = 9999
	}
	path := cfg.WebPath
	if path == "" || path == "/" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("http://%s:%d%s", host, port, path)
}

func printBinaryStatus(stdout io.Writer, label, path string, m messages) bool {
	exists := false
	if info, err := os.Stat(path); err == nil && !info.IsDir() {
		exists = true
	}
	switch {
	case label == "Xray" && exists:
		fmt.Fprintf(stdout, "%s (%s)\n", m.doctorXrayInstalled, path)
	case label == "Xray":
		fmt.Fprintf(stdout, "%s (%s)\n", m.doctorXrayNotInstalled, path)
	case exists:
		fmt.Fprintf(stdout, "%s (%s)\n", m.doctorSingboxInstalled, path)
	default:
		fmt.Fprintf(stdout, "%s (%s)\n", m.doctorSingboxNotInstalled, path)
	}
	return exists
}

func listeningStatus(ssOutput string, port int) string {
	needle := fmt.Sprintf(":%d", port)
	if strings.Contains(ssOutput, needle) {
		return "listening"
	}
	return "not listening"
}

func generatedPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func defaultBackupPath() string {
	return filepath.Join(paths.BackupDir, "migate-backup-"+time.Now().Format("20060102-150405")+".tar.gz")
}

func backupFiles() []string {
	return []string{paths.ConfigDir, paths.Database, paths.VersionsFile}
}

func routerFromConfig(path string) (http.Handler, func(), error) {
	cfg, err := panelcfg.Load(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(cfg.PanelUsername) == "" || strings.TrimSpace(cfg.PanelPassword) == "" {
		return nil, nil, fmt.Errorf("panel_username and panel_password are required")
	}
	opts := routerOptionsFromConfig(cfg, path)
	if cfg.DatabasePath == "" {
		return web.NewRouter(opts...), func() {}, nil
	}
	store, err := db.Open(context.Background(), cfg.DatabasePath)
	if err != nil {
		return nil, nil, err
	}
	closeStore := func() { _ = store.Close() }

	opts = append(opts, web.WithStore(store))

	// Build Xray controller for shared use.
	xrayCtrl := web.NewRealController(store, paths.XrayConfig, execCmd).WithConfigDir(filepath.Dir(path))
	opts = append(opts, web.WithXrayController(xrayCtrl))
	statsClient := xray.NewResilientStatsClient(
		xray.NewCommandStatsClient(paths.XrayBinary, "127.0.0.1:10085"),
		xray.NewStubStatsClient(),
	)
	var singboxStatsClient singbox.StatsClient
	singboxInbounds, listInboundsErr := store.ListInbounds(context.Background())
	if listInboundsErr != nil {
		log.Printf("traffic sync: failed to inspect sing-box inbounds: %v", listInboundsErr)
	}
	hasSingboxInbound := singbox.HasEnabledSingboxInbound(singboxInbounds)
	if !hasSingboxInbound {
		singboxStatsClient = singbox.NewDisabledStatsClient("not_configured", "")
	} else {
		capability := singbox.DetectCapability(context.Background())
		switch {
		case capability.V2RayAPIStats:
			singboxStatsClient, err = singbox.NewGRPCStatsClient(context.Background(), "127.0.0.1:10086")
			if err != nil {
				err = fmt.Errorf("build sing-box stats client: %w", err)
				log.Printf("traffic sync: sing-box stats unavailable; scheduler will mark singbox unavailable: %v", err)
				singboxStatsClient = singbox.NewUnavailableStatsClient(err)
			}
		case capability.Unsupported:
			singboxStatsClient = singbox.NewDisabledStatsClient("unsupported", singbox.StatsUnsupportedMessage)
		default:
			message := capability.Message
			if message == "" {
				message = "sing-box stats capability check failed"
			}
			singboxStatsClient = singbox.NewUnavailableStatsClient(fmt.Errorf("%s", message))
		}
	}
	opts = append(opts, web.WithStatsClient(statsClient))
	opts = append(opts, web.WithSingboxStatsClient(singboxStatsClient))

	// Create schedulers before building router (needed for options and cleanup wiring)
	// Traffic sync scheduler keeps retrying Xray StatsService because Xray may
	// become available only after the panel starts and applies generated config.
	trafficSched := scheduler.NewTrafficSyncSchedulerWithSingboxConfig(store, statsClient, singboxStatsClient, singboxInbounds, 1*time.Minute)
	outboundSubSched := scheduler.NewOutboundSubscriptionScheduler(store, web.OutboundSubscriptionRefresher{
		Store:   store,
		Options: append(opts, web.WithStore(store)),
	}, 1*time.Minute)
	certService := certsvc.Service{Store: store, CertDir: paths.CertDir}
	certRenewSched := scheduler.NewCertificateRenewScheduler(certService, scheduler.CertificateRenewSchedulerOptions{
		Days:         30,
		Interval:     24 * time.Hour,
		StartDelay:   30 * time.Second,
		Timeout:      10 * time.Minute,
		ApplyRenewed: web.CertificateCoreApplyFunc(append(opts, web.WithStore(store))...),
	})

	router := web.NewRouter(opts...)

	stopSocks5Cache := web.StartSocks5PoolCacheScheduler("")
	stopHTTPProxyCache := web.StartHTTPPoolCacheScheduler("")
	stopHTTPSProxyCache := web.StartHTTPSPoolCacheScheduler("")

	// Start schedulers in background and wait for them during cleanup.
	var schedWG sync.WaitGroup
	trafficStarted := make(chan struct{})
	schedWG.Add(1)
	go func() {
		defer schedWG.Done()
		log.Println("traffic sync scheduler started")
		close(trafficStarted)
		trafficSched.Start()
	}()
	<-trafficStarted
	schedWG.Add(1)
	go func() {
		defer schedWG.Done()
		log.Println("certificate renew scheduler started")
		certRenewSched.Start()
	}()
	schedWG.Add(1)
	go func() {
		defer schedWG.Done()
		log.Println("outbound subscription scheduler started")
		outboundSubSched.Start()
	}()

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			stopSocks5Cache()
			stopHTTPProxyCache()
			stopHTTPSProxyCache()
			trafficSched.Stop()
			outboundSubSched.Stop()
			certRenewSched.Stop()
			schedWG.Wait()
			closeStore()
		})
	}

	return router, cleanup, nil
}

func routerOptionsFromConfig(cfg panelcfg.Config, path string) []web.Option {
	opts := []web.Option{web.WithVersion(Version)}
	if cfg.WebPath != "" {
		opts = append(opts, web.WithBasePath(cfg.WebPath))
	}
	if cfg.PublicHost != "" {
		opts = append(opts, web.WithPublicHost(cfg.PublicHost))
	}
	if cfg.TrustProxy {
		opts = append(opts, web.WithTrustedProxyHeaders(true))
	}
	if cfg.PanelUsername != "" && cfg.PanelPassword != "" {
		opts = append(opts, web.WithAuth(cfg.PanelUsername, cfg.PanelPassword))
	}
	opts = append(opts, web.WithConfigDir(filepath.Dir(path)))
	opts = append(opts, web.WithXrayConfigPath(paths.XrayConfig))
	return opts
}

func execCmd(name string, args ...string) (string, error) {
	out, err := runtimecmd.RunOutput(context.Background(), name, args...)
	return string(out), err
}
