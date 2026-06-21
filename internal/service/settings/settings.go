package settings

import (
	"fmt"
	"strings"

	panelcfg "github.com/imzyb/MiGate/internal/config"
)

type PasswordHasher func(string) (string, error)
type PasswordHashChecker func(string) bool

type Service struct {
	ConfigPath     string
	HashPassword   PasswordHasher
	IsPasswordHash PasswordHashChecker
}

type Request struct {
	PanelPort     *int    `json:"panel_port"`
	PanelUsername *string `json:"panel_username"`
	PanelPassword *string `json:"panel_password"`
	WebPath       *string `json:"web_base_path"`
	PublicHost    *string `json:"public_host"`
	TrustProxy    *bool   `json:"trust_proxy"`
	DatabasePath  *string `json:"database_path"`
	CertDomain    *string `json:"cert_domain"`
	CertEmail     *string `json:"cert_email"`

	ManagementDirectEnabled    *bool     `json:"management_direct_enabled"`
	ManagementDirectAutoDetect *bool     `json:"management_direct_auto_detect"`
	ManagementDirectHosts      *[]string `json:"management_direct_hosts"`
	ManagementDirectPorts      *[]int    `json:"management_direct_ports"`
}

type Response struct {
	PanelPort     int    `json:"panel_port"`
	PanelUsername string `json:"panel_username"`
	WebPath       string `json:"web_base_path"`
	PublicHost    string `json:"public_host"`
	TrustProxy    bool   `json:"trust_proxy"`
	DatabasePath  string `json:"database_path"`
	CertDomain    string `json:"cert_domain"`
	CertEmail     string `json:"cert_email"`
	HasPassword   bool   `json:"has_password"`

	ManagementDirectEnabled    bool     `json:"management_direct_enabled"`
	ManagementDirectAutoDetect bool     `json:"management_direct_auto_detect"`
	ManagementDirectHosts      []string `json:"management_direct_hosts"`
	ManagementDirectPorts      []int    `json:"management_direct_ports"`
}

func (s Service) Get() (Response, error) {
	cfg, err := panelcfg.Load(s.ConfigPath)
	if err != nil {
		return Response{}, err
	}
	return responseFromConfig(cfg), nil
}

func (s Service) Update(req Request) error {
	_, err := panelcfg.Update(s.ConfigPath, func(existing panelcfg.Config) (panelcfg.Config, error) {
		return s.apply(existing, req)
	})
	return err
}

func (s Service) SetPasswordHash(hashedPassword string) error {
	if hashedPassword == "" {
		return fmt.Errorf("panel password hash is required")
	}
	_, err := panelcfg.Update(s.ConfigPath, func(cfg panelcfg.Config) (panelcfg.Config, error) {
		cfg.PanelPassword = hashedPassword
		return cfg, nil
	})
	return err
}

func (s Service) SaveCert(domain, email string) error {
	_, err := panelcfg.Update(s.ConfigPath, func(cfg panelcfg.Config) (panelcfg.Config, error) {
		cfg.CertDomain = domain
		cfg.CertEmail = email
		return cfg, nil
	})
	return err
}

func (s Service) apply(cfg panelcfg.Config, req Request) (panelcfg.Config, error) {
	if req.PanelPort != nil {
		cfg.PanelPort = *req.PanelPort
	}
	if req.PanelUsername != nil {
		cfg.PanelUsername = *req.PanelUsername
	}
	if req.WebPath != nil {
		cfg.WebPath = *req.WebPath
	}
	if req.PublicHost != nil {
		cfg.PublicHost = *req.PublicHost
	}
	if req.TrustProxy != nil {
		cfg.TrustProxy = *req.TrustProxy
	}
	if req.DatabasePath != nil {
		cfg.DatabasePath = *req.DatabasePath
	}
	if req.CertDomain != nil {
		cfg.CertDomain = *req.CertDomain
	}
	if req.CertEmail != nil {
		cfg.CertEmail = *req.CertEmail
	}
	if req.ManagementDirectEnabled != nil {
		cfg.SetManagementDirectEnabled(*req.ManagementDirectEnabled)
	}
	if req.ManagementDirectAutoDetect != nil {
		cfg.SetManagementDirectAutoDetect(*req.ManagementDirectAutoDetect)
	}
	if req.ManagementDirectHosts != nil {
		cfg.ManagementDirectHosts = panelcfg.NormalizeManagementDirectHosts(*req.ManagementDirectHosts)
	}
	if req.ManagementDirectPorts != nil {
		cfg.ManagementDirectPorts = panelcfg.NormalizeManagementDirectPorts(*req.ManagementDirectPorts)
	}
	if req.PanelPassword != nil && *req.PanelPassword != "" {
		password := *req.PanelPassword
		if !s.passwordIsHash(password) {
			hashed, err := s.hashPassword(password)
			if err != nil {
				return panelcfg.Config{}, fmt.Errorf("hash password: %w", err)
			}
			password = hashed
		}
		cfg.PanelPassword = password
	} else if cfg.PanelPassword != "" && !s.passwordIsHash(cfg.PanelPassword) {
		hashed, err := s.hashPassword(cfg.PanelPassword)
		if err != nil {
			return panelcfg.Config{}, fmt.Errorf("hash password: %w", err)
		}
		cfg.PanelPassword = hashed
	}
	return cfg, nil
}

func (s Service) hashPassword(password string) (string, error) {
	if s.HashPassword == nil {
		return "", fmt.Errorf("password hasher is not configured")
	}
	return s.HashPassword(password)
}

func (s Service) passwordIsHash(value string) bool {
	if s.IsPasswordHash == nil {
		return strings.HasPrefix(value, "$migate$argon2id$v=19$")
	}
	return s.IsPasswordHash(value)
}

func responseFromConfig(cfg panelcfg.Config) Response {
	return Response{
		PanelPort:     cfg.PanelPort,
		PanelUsername: cfg.PanelUsername,
		WebPath:       cfg.WebPath,
		PublicHost:    cfg.PublicHost,
		TrustProxy:    cfg.TrustProxy,
		DatabasePath:  cfg.DatabasePath,
		CertDomain:    cfg.CertDomain,
		CertEmail:     cfg.CertEmail,
		HasPassword:   cfg.PanelPassword != "",

		ManagementDirectEnabled:    cfg.ManagementDirectEnabled,
		ManagementDirectAutoDetect: cfg.ManagementDirectAutoDetect,
		ManagementDirectHosts:      append([]string(nil), cfg.ManagementDirectHosts...),
		ManagementDirectPorts:      append([]int(nil), cfg.ManagementDirectPorts...),
	}
}
