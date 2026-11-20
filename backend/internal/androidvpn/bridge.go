// SPDX-License-Identifier: MPL-2.0

package androidvpn

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// Config holds parameters supplied by Kotlin ProxyVpnService / JS bridge when starting Android VPN.
type Config struct {
	ProtectPath    string   `json:"protect_path"`
	TunFD          int      `json:"tun_fd,omitempty"`
	MixedPort      int      `json:"mixed_port,omitempty"`
	PerAppMode     string   `json:"per_app_mode,omitempty"` // all | whitelist | blacklist
	PerAppPackages []string `json:"per_app_packages,omitempty"`
	ActiveNodeID   string   `json:"active_node_id,omitempty"`
	ActiveGroupID  string   `json:"active_group_id,omitempty"`
}

// Status reflects the current Android VpnService coordination state.
type Status struct {
	Active         bool     `json:"active"`
	ProtectPath    string   `json:"protect_path,omitempty"`
	TunFD          int      `json:"tun_fd,omitempty"`
	MixedPort      int      `json:"mixed_port,omitempty"`
	PerAppMode     string   `json:"per_app_mode,omitempty"`
	PerAppPackages []string `json:"per_app_packages,omitempty"`
	UpdatedAt      string   `json:"updated_at,omitempty"`
}

// Manager coordinates unrooted Android VpnService socket protection and per-app preferences.
type Manager struct {
	mu     sync.RWMutex
	status Status
}

// NewManager creates an inactive Android VPN state tracker.
func NewManager() *Manager {
	return &Manager{
		status: Status{PerAppMode: "all", PerAppPackages: []string{}},
	}
}

// Start validates and stores active Android VPN coordination parameters.
func (m *Manager) Start(cfg Config) (Status, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.PerAppMode))
	switch mode {
	case "", "all":
		mode = "all"
	case "whitelist", "blacklist":
	default:
		return Status{}, fmt.Errorf("invalid per_app_mode %q (expected all, whitelist, or blacklist)", cfg.PerAppMode)
	}
	if strings.TrimSpace(cfg.ProtectPath) == "" {
		return Status{}, fmt.Errorf("protect_path is required")
	}
	pkgs := make([]string, 0, len(cfg.PerAppPackages))
	for _, p := range cfg.PerAppPackages {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			pkgs = append(pkgs, trimmed)
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = Status{
		Active:         true,
		ProtectPath:    strings.TrimSpace(cfg.ProtectPath),
		TunFD:          cfg.TunFD,
		MixedPort:      cfg.MixedPort,
		PerAppMode:     mode,
		PerAppPackages: pkgs,
		UpdatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	return m.copyStatusLocked(), nil
}

// Stop marks the Android VPN session inactive.
func (m *Manager) Stop() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status.Active = false
	m.status.TunFD = 0
	m.status.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	return m.copyStatusLocked()
}

// Status returns a snapshot of the current Android VPN coordination state.
func (m *Manager) Status() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.copyStatusLocked()
}

func (m *Manager) copyStatusLocked() Status {
	st := m.status
	if m.status.PerAppPackages != nil {
		st.PerAppPackages = append([]string{}, m.status.PerAppPackages...)
	} else {
		st.PerAppPackages = []string{}
	}
	return st
}
