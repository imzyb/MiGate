package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/scheduler"
	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/xray"
)

// Version is set via ldflags at build time.
var Version = "dev"

var defaultPanelConfigPath = "/etc/migate/panel.json"

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
	statusSingboxRunning      string
	statusSingboxStopped      string
	doctorHeader              string
	doctorConfigOk            string
	doctorDatabaseOk          string
	doctorXrayInstalled       string
	doctorXrayNotInstalled    string
	doctorSingboxInstalled    string
	doctorSingboxNotInstalled string
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
	unsupportedLanguage       string
}

var msgZh = messages{
	cliMenuHeader:             "MiGate CLI",
	cliMenuUsage:              "用法:",
	cliMenuCommonCommands:     "常用命令:",
	cliMenuServiceMode:        "服务模式:",
	statusPanelRunning:        "MiGate 面板: 运行中",
	statusPanelStopped:        "MiGate 面板: 已停止",
	statusSingboxRunning:      "sing-box: 运行中",
	statusSingboxStopped:      "sing-box: 已停止",
	doctorHeader:              "MiGate 诊断",
	doctorConfigOk:            "配置文件: 正常",
	doctorDatabaseOk:          "数据库: 正常",
	doctorXrayInstalled:       "Xray: 已安装",
	doctorXrayNotInstalled:    "Xray: 未安装",
	doctorSingboxInstalled:    "sing-box: 已安装",
	doctorSingboxNotInstalled: "sing-box: 未安装",
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
	unsupportedLanguage:       "不支持的语言 %q，仅支持: zh, en",
}

var msgEn = messages{
	cliMenuHeader:             "MiGate CLI",
	cliMenuUsage:              "Usage:",
	cliMenuCommonCommands:     "Common commands:",
	cliMenuServiceMode:        "Service mode:",
	statusPanelRunning:        "MiGate Panel: running",
	statusPanelStopped:        "MiGate Panel: stopped",
	statusSingboxRunning:      "sing-box: running",
	statusSingboxStopped:      "sing-box: stopped",
	doctorHeader:              "MiGate Doctor",
	doctorConfigOk:            "Config: ok",
	doctorDatabaseOk:          "Database: ok",
	doctorXrayInstalled:       "Xray: installed",
	doctorXrayNotInstalled:    "Xray: not installed",
	doctorSingboxInstalled:    "sing-box: installed",
	doctorSingboxNotInstalled: "sing-box: not installed",
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
	unsupportedLanguage:       "unsupported language %q, supported: zh, en",
}

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
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

type panelConfig struct {
	PanelPort      int    `json:"panel_port"`
	PanelUsername  string `json:"panel_username"`
	PanelPassword  string `json:"panel_password"`
	WebPath        string `json:"web_base_path"`
	DatabasePath   string `json:"database_path"`
	XrayConfigPath string `json:"xray_config_path"`
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
	fs.StringVar(&host, "host", "0.0.0.0", "bind host")
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

	cfg, err := readPanelConfig(configPath)
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
	case "start", "stop":
		return cliSystemctl(stderr, runner, args[0], "migate")
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
		out, err := runner.Run("/usr/local/bin/migate-uninstall", args[1:]...)
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
  mg restart all     Restart MiGate panel and sing-box
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
	out, err := runner.Run("/usr/local/bin/migate-install", updateArgs...)
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
		{name: "migate", label: "MiGate", running: m.statusPanelRunning, stopped: m.statusPanelStopped},
		{name: "migate-singbox", label: "sing-box", running: m.statusSingboxRunning, stopped: m.statusSingboxStopped},
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
	fmt.Fprintln(stdout, m.doctorHeader)
	_ = cliStatus(stdout, stderr, runner, m)
	cfg, err := readPanelConfig(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stdout, "Config: missing (%v)\n", err)
	} else {
		fmt.Fprintln(stdout, m.doctorConfigOk)
		fmt.Fprintf(stdout, "WebUI: %s\n", panelURL(cfg, "SERVER_IP"))
		if cfg.DatabasePath != "" {
			if _, err := os.Stat(cfg.DatabasePath); err == nil {
				fmt.Fprintln(stdout, m.doctorDatabaseOk)
			} else {
				fmt.Fprintf(stdout, "Database: missing (%s)\n", cfg.DatabasePath)
			}
		}
	}
	printBinaryStatus(stdout, runner, "Xray", "xray", m)
	printBinaryStatus(stdout, runner, "sing-box", "sing-box", m)
	if out, err := runner.Run("ss", "-ltn"); err == nil && cfg.PanelPort > 0 {
		fmt.Fprintf(stdout, "Panel port %d: %s\n", cfg.PanelPort, listeningStatus(out, cfg.PanelPort))
	}
	if out, err := runner.Run("free", "-m"); err == nil {
		fmt.Fprintf(stdout, "%s\n%s", m.doctorMemory, out)
	}
	if out, err := runner.Run("df", "-h", "/"); err == nil {
		fmt.Fprintf(stdout, "%s\n%s", m.doctorDisk, out)
	}
	return 0
}

func cliInfo(stdout, stderr io.Writer, m messages) int {
	cfg, err := readPanelConfig(defaultPanelConfigPath)
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
	cfg, err := readPanelConfig(defaultPanelConfigPath)
	if err != nil {
		fmt.Fprintf(stderr, "read %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	password := ""
	if len(args) == 1 {
		password = args[0]
	} else {
		password = generatedPassword()
	}
	cfg.PanelPassword = password
	if err := writePanelConfig(defaultPanelConfigPath, cfg); err != nil {
		fmt.Fprintf(stderr, "write %s: %v\n", defaultPanelConfigPath, err)
		return 1
	}
	if code := cliSystemctl(stderr, runner, "restart", "migate"); code != 0 {
		return code
	}
	fmt.Fprintf(stdout, "%s %s\n", m.resetPasswordUpdated, password)
	return 0
}

func cliLogs(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	logArgs := []string{"-u", "migate", "-n", "80"}
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
		return cliSystemctl(stderr, runner, "restart", "migate")
	}
	if len(args) == 1 && args[0] == "all" {
		for _, svc := range managedServices() {
			if code := cliSystemctl(stderr, runner, "restart", svc.name); code != 0 {
				return code
			}
		}
		return 0
	}
	fmt.Fprintln(stderr, "usage: mg restart [all]")
	return 2
}

func cliSystemctl(stderr io.Writer, runner commandRunner, action, service string) int {
	if _, err := runner.Run("systemctl", action, service); err != nil {
		fmt.Fprintf(stderr, "%s %s failed: %v\n", action, service, err)
		return 1
	}
	return 0
}

func cliURL(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	cfg, err := readPanelConfig(defaultPanelConfigPath)
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
	if code := cliSystemctl(stderr, runner, "restart", "migate"); code != 0 {
		return code
	}
	fmt.Fprintln(stdout, "Restore completed")
	return 0
}

func cliPorts(stdout, stderr io.Writer, runner commandRunner, m messages) int {
	cfg, err := readPanelConfig(defaultPanelConfigPath)
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

func managedServices() []struct{ name, label string } {
	return []struct{ name, label string }{{name: "migate", label: "MiGate Panel"}, {name: "migate-singbox", label: "sing-box"}}
}

func panelURL(cfg panelConfig, host string) string {
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

func printBinaryStatus(stdout io.Writer, runner commandRunner, label, command string, m messages) {
	if out, err := runner.Run(command, "version"); err == nil && strings.TrimSpace(out) != "" {
		if label == "Xray" {
			fmt.Fprintln(stdout, m.doctorXrayInstalled)
		} else {
			fmt.Fprintln(stdout, m.doctorSingboxInstalled)
		}
	} else {
		if label == "Xray" {
			fmt.Fprintln(stdout, m.doctorXrayNotInstalled)
		} else {
			fmt.Fprintln(stdout, m.doctorSingboxNotInstalled)
		}
	}
}

func listeningStatus(ssOutput string, port int) string {
	needle := fmt.Sprintf(":%d", port)
	if strings.Contains(ssOutput, needle) {
		return "listening"
	}
	return "not listening"
}

func generatedPassword() string {
	return fmt.Sprintf("migate-%d", time.Now().Unix())
}

func defaultBackupPath() string {
	return "/root/migate-backup-" + time.Now().Format("20060102-150405") + ".tar.gz"
}

func backupFiles() []string {
	files := []string{defaultPanelConfigPath}
	if cfg, err := readPanelConfig(defaultPanelConfigPath); err == nil {
		if cfg.DatabasePath != "" {
			files = append(files, cfg.DatabasePath)
		}
		if cfg.XrayConfigPath != "" {
			files = append(files, cfg.XrayConfigPath)
		}
	}
	files = append(files, "/etc/sing-box/config.json")
	return files
}

func writePanelConfig(path string, cfg panelConfig) error {
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600)
}

func routerFromConfig(path string) (http.Handler, func(), error) {
	cfg, err := readPanelConfig(path)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(cfg.PanelUsername) == "" || strings.TrimSpace(cfg.PanelPassword) == "" {
		return nil, nil, fmt.Errorf("panel_username and panel_password are required")
	}
	if cfg.DatabasePath == "" {
		return web.NewRouter(web.WithAuth(cfg.PanelUsername, cfg.PanelPassword), web.WithVersion(Version), web.WithConfigDir(filepath.Dir(path))), func() {}, nil
	}
	store, err := db.Open(context.Background(), cfg.DatabasePath)
	if err != nil {
		return nil, nil, err
	}
	closeStore := func() { _ = store.Close() }

	opts := []web.Option{web.WithStore(store), web.WithVersion(Version)}
	if cfg.WebPath != "" {
		opts = append(opts, web.WithBasePath(cfg.WebPath))
	}
	if cfg.PanelUsername != "" && cfg.PanelPassword != "" {
		opts = append(opts, web.WithAuth(cfg.PanelUsername, cfg.PanelPassword))
	}
	opts = append(opts, web.WithConfigDir(filepath.Dir(path)))

	// Build Xray controller for shared use
	var xrayCtrl web.XrayController
	if cfg.XrayConfigPath != "" {
		xrayCtrl = web.NewRealController(store, cfg.XrayConfigPath, execCmd)
		opts = append(opts, web.WithXrayController(xrayCtrl))
	}
	statsClient := xray.NewResilientStatsClient(
		xray.NewCommandStatsClient("/usr/local/bin/xray", "127.0.0.1:10085"),
		xray.NewStubStatsClient(),
	)
	opts = append(opts, web.WithStatsClient(statsClient))

	// Create schedulers before building router (needed for options and cleanup wiring)
	// Traffic sync scheduler keeps retrying Xray StatsService because Xray may
	// become available only after the panel starts and applies generated config.
	trafficSched := scheduler.NewTrafficSyncScheduler(store, statsClient, 1*time.Minute)

	router := web.NewRouter(opts...)

	stopSocks5Cache := web.StartSocks5PoolCacheScheduler("")

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

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			stopSocks5Cache()
			trafficSched.Stop()
			schedWG.Wait()
			closeStore()
		})
	}

	return router, cleanup, nil
}

func readPanelConfig(path string) (panelConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return panelConfig{}, err
	}
	var cfg panelConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		return panelConfig{}, err
	}
	return cfg, nil
}

func execCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	return string(out), err
}
