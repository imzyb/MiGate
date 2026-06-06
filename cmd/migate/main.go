package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/scheduler"
	"github.com/imzyb/MiGate/internal/web"
	"github.com/imzyb/MiGate/internal/xray"
)

// Version is set via ldflags at build time.
var Version = "dev"

type panelConfig struct {
	PanelPort      int    `json:"panel_port"`
	PanelUsername  string `json:"panel_username"`
	PanelPassword  string `json:"panel_password"`
	WebPath        string `json:"web_base_path"`
	DatabasePath   string `json:"database_path"`
	XrayConfigPath string `json:"xray_config_path"`
}

func main() {
	var host string
	var port int
	var configPath string
	flag.StringVar(&host, "host", "0.0.0.0", "bind host")
	flag.IntVar(&port, "port", 9999, "bind port")
	flag.StringVar(&configPath, "config", "", "panel config path")
	flag.Parse()

	router := web.NewRouter()
	cleanup := func() {}
	if configPath != "" {
		cfg, err := readPanelConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read config %s: %v\n", configPath, err)
			os.Exit(1)
		}
		if cfg.PanelPort > 0 {
			port = cfg.PanelPort
		}
		configuredRouter, configuredCleanup, err := routerFromConfig(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "build router from config %s: %v\n", configPath, err)
			os.Exit(1)
		}
		router = configuredRouter
		cleanup = configuredCleanup
	}
	defer cleanup()

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("MiGate listening on %s", addr)
	if err := http.ListenAndServe(addr, router); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
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
	if cfg.XrayConfigPath != "" {
		opts = append(opts, web.WithXrayController(
			web.NewRealController(store, cfg.XrayConfigPath, execCmd),
		))
	}
	// Inject stub stats client (lightweight, no gRPC dependency)
	// Real stats can be enabled by swapping with GRPCStatsClient at runtime
	opts = append(opts, web.WithStatsClient(xray.NewStubStatsClient()))

	router := web.NewRouter(opts...)

	// Start traffic sync scheduler in background
	// Uses stub client by default (returns empty stats)
	// When gRPC stats client is available, it will sync real traffic data
	sched := scheduler.NewTrafficSyncScheduler(store, xray.NewStubStatsClient(), 1*time.Minute)
	go func() {
		log.Println("traffic sync scheduler started (stub mode - no real stats)")
		sched.Start()
	}()

	cleanup := func() {
		sched.Stop()
		closeStore()
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
