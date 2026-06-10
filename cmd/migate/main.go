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
	if detectCommandMode(args) == modeCLI {
		os.Exit(runCLI(args, os.Stdout, os.Stderr, osRunner{}))
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

	router := web.NewRouter()
	cleanup := func() {}
	if configPath != "" {
		cfg, err := readPanelConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config %s: %v\n", configPath, err)
			return 1
		}
		if cfg.PanelPort > 0 {
			port = cfg.PanelPort
		}
		configuredRouter, configuredCleanup, err := routerFromConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "build router from config %s: %v\n", configPath, err)
			return 1
		}
		router = configuredRouter
		cleanup = configuredCleanup
	}
	defer cleanup()

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("MiGate listening on %s", addr)

	srv := &http.Server{Addr: addr, Handler: router}

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
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		printCLIMenu(stdout)
		return 0
	}
	switch args[0] {
	case "version":
		fmt.Fprintf(stdout, "MiGate version: %s\n", Version)
		return 0
	case "status":
		return cliStatus(stdout, stderr, runner)
	case "start", "stop", "restart":
		return cliSystemctl(stderr, runner, args[0], "migate")
	case "logs":
		out, err := runner.Run("journalctl", "-u", "migate", "-n", "80", "--no-pager")
		fmt.Fprint(stdout, out)
		if err != nil {
			fmt.Fprintf(stderr, "logs failed: %v\n", err)
			return 1
		}
		return 0
	case "url":
		return cliURL(stdout, stderr)
	case "update":
		return cliUpdate(stdout, stderr, runner, args[1:])
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
		printCLIMenu(stderr)
		return 2
	}
}

func printCLIMenu(w io.Writer) {
	fmt.Fprint(w, `MiGate CLI

用法:
  mg <命令>
  migate <命令>

常用命令:
  mg status       查看服务状态
  mg start        启动 MiGate
  mg stop         停止 MiGate
  mg restart      重启 MiGate
  mg logs         查看最近日志
  mg url          显示 WebUI 地址
  mg update       更新到最新版本
  mg update vX.Y.Z 更新到指定版本
  mg version      显示当前版本
  mg uninstall    卸载 MiGate

服务模式:
  migate serve --config /etc/migate/panel.json

`)
}

func cliUpdate(stdout, stderr io.Writer, runner commandRunner, args []string) int {
	updateArgs := []string{"--update"}
	if len(args) > 0 {
		if len(args) > 1 {
			fmt.Fprintln(stderr, "usage: mg update [version]")
			return 2
		}
		updateArgs = append(updateArgs, "--version", args[0])
	}
	out, err := runner.Run("/usr/local/bin/migate-install", updateArgs...)
	fmt.Fprint(stdout, out)
	if err != nil {
		fmt.Fprintf(stderr, "update failed: %v\n", err)
		return 1
	}
	return 0
}

func cliStatus(stdout, stderr io.Writer, runner commandRunner) int {
	code := 0
	services := []struct {
		name  string
		label string
	}{
		{name: "migate", label: "MiGate 面板"},
		{name: "migate-singbox", label: "sing-box"},
	}
	for _, svc := range services {
		out, err := runner.Run("systemctl", "is-active", svc.name)
		status := strings.TrimSpace(out)
		if status == "" {
			status = "unknown"
		}
		fmt.Fprintf(stdout, "%s: %s\n", svc.label, localizedServiceStatus(status))
		if err != nil && status == "unknown" {
			fmt.Fprintf(stderr, "%s status check failed: %v\n", svc.name, err)
			code = 1
		}
	}
	return code
}

func localizedServiceStatus(status string) string {
	switch status {
	case "active":
		return "运行中"
	case "inactive":
		return "未运行"
	case "failed":
		return "异常"
	case "activating":
		return "启动中"
	case "deactivating":
		return "停止中"
	default:
		return "未知"
	}
}

func cliSystemctl(stderr io.Writer, runner commandRunner, action, service string) int {
	if _, err := runner.Run("systemctl", action, service); err != nil {
		fmt.Fprintf(stderr, "%s %s failed: %v\n", action, service, err)
		return 1
	}
	return 0
}

func cliURL(stdout, stderr io.Writer) int {
	cfg, err := readPanelConfig("/etc/migate/panel.json")
	if err != nil {
		fmt.Fprintf(stderr, "read /etc/migate/panel.json: %v\n", err)
		return 1
	}
	port := cfg.PanelPort
	if port == 0 {
		port = 9999
	}
	path := cfg.WebPath
	if path == "" {
		path = "/"
	}
	fmt.Fprintf(stdout, "http://SERVER_IP:%d%s\n", port, path)
	return 0
}

func routerFromConfig(path string) (http.Handler, func(), error) {
	cfg, err := readPanelConfig(path)
	if err != nil {
		return nil, nil, err
	}
	if cfg.DatabasePath == "" {
		return web.NewRouter(), func() {}, nil
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
	// Query real Xray traffic stats through the lightweight xray CLI API when
	// the local Xray StatsService is actually reachable. Local preview/release
	// audit runs often have an xray binary but no StatsService, so fall back to
	// the lightweight stub instead of logging a scheduler error every minute.
	statsClient := usableStatsClient(context.Background(), xray.NewCommandStatsClient("/usr/local/bin/xray", "127.0.0.1:10085"))
	opts = append(opts, web.WithStatsClient(statsClient))

	// Create schedulers before building router (needed for options and cleanup wiring)
	// Traffic sync scheduler — syncs client traffic stats from Xray API when a real stats client is configured.
	var trafficSched *scheduler.TrafficSyncScheduler
	if !xray.StatsClientIsStub(statsClient) {
		trafficSched = scheduler.NewTrafficSyncScheduler(store, statsClient, 1*time.Minute)
	}

	router := web.NewRouter(opts...)

	stopSocks5Cache := web.StartSocks5PoolCacheScheduler("")

	// Start schedulers in background and wait for them during cleanup.
	var schedWG sync.WaitGroup
	trafficStarted := make(chan struct{})
	if trafficSched != nil {
		schedWG.Add(1)
		go func() {
			defer schedWG.Done()
			log.Println("traffic sync scheduler started")
			close(trafficStarted)
			trafficSched.Start()
		}()
	} else {
		close(trafficStarted)
	}
	<-trafficStarted

	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			stopSocks5Cache()
			if trafficSched != nil {
				trafficSched.Stop()
			}
			schedWG.Wait()
			closeStore()
		})
	}

	return router, cleanup, nil
}

func usableStatsClient(ctx context.Context, client xray.StatsClient) xray.StatsClient {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := client.QueryAllStats(probeCtx); err != nil {
		log.Printf("traffic sync: xray stats unavailable, realtime Xray traffic sync disabled: %v", err)
		_ = client.Close()
		return xray.NewStubStatsClient()
	}
	return client
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
