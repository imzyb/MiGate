package web

import (
	"path/filepath"
	"strings"

	panelcfg "github.com/imzyb/MiGate/internal/config"
	"github.com/imzyb/MiGate/internal/singbox"
	"github.com/imzyb/MiGate/internal/xray"
)

func managementDirectConfigForRouter(cfg *routerConfig) (panelcfg.Config, bool) {
	if cfg == nil || strings.TrimSpace(cfg.configDir) == "" {
		return panelcfg.Config{}, false
	}
	loaded, err := panelcfg.Load(filepath.Join(cfg.configDir, "panel.json"))
	if err != nil {
		return panelcfg.Config{}, false
	}
	return loaded, true
}

func xrayOptionsForRouterConfig(cfg *routerConfig) xray.BuildOptions {
	loaded, ok := managementDirectConfigForRouter(cfg)
	if !ok {
		return xray.BuildOptions{}
	}
	hosts, ports := panelcfg.ManagementDirectTargets(loaded)
	return xray.BuildOptions{ManagementDirect: xray.ManagementDirectOptions{
		Enabled: loaded.ManagementDirectEnabled,
		Hosts:   hosts,
		Ports:   ports,
	}}
}

func singboxOptionsForRouterConfig(cfg *routerConfig) singbox.BuildOptions {
	loaded, ok := managementDirectConfigForRouter(cfg)
	if !ok {
		return singbox.BuildOptions{}
	}
	hosts, ports := panelcfg.ManagementDirectTargets(loaded)
	return singbox.BuildOptions{ManagementDirect: singbox.ManagementDirectOptions{
		Enabled: loaded.ManagementDirectEnabled,
		Hosts:   hosts,
		Ports:   ports,
	}}
}
