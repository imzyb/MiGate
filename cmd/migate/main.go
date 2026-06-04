package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/imzyb/MiGate/internal/db"
	"github.com/imzyb/MiGate/internal/web"
)

type panelConfig struct {
	PanelPort    int    `json:"panel_port"`
	WebPath      string `json:"web_base_path"`
	DatabasePath string `json:"database_path"`
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
	return web.NewRouter(web.WithStore(store)), func() { _ = store.Close() }, nil
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
