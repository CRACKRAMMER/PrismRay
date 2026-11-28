// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

const (
	tailscaleSettingKey = "tailscale.config"
	tailscaleAuthKeySec = "tailscale.auth_key"
)

// TailscalePeerStatus describes one peer device inside the connected Tailnet.
type TailscalePeerStatus struct {
	StableID       string   `json:"stable_id,omitempty"`
	Hostname       string   `json:"hostname"`
	DNSName        string   `json:"dns_name,omitempty"`
	OS             string   `json:"os,omitempty"`
	IPv4           string   `json:"ipv4,omitempty"`
	IPv6           string   `json:"ipv6,omitempty"`
	TailscaleIPs   []string `json:"tailscale_ips,omitempty"`
	Online         bool     `json:"online"`
	Active         bool     `json:"active,omitempty"`
	ExitNode       bool     `json:"exit_node,omitempty"`
	ExitNodeOption bool     `json:"exit_node_option,omitempty"`
	Expired        bool     `json:"expired,omitempty"`
	LastSeen       int64    `json:"last_seen,omitempty"`
}

// TailscaleRuntimeStatus summarizes the live connection state of sing-box's built-in Tailscale endpoint.
type TailscaleRuntimeStatus struct {
	State              string                `json:"state"` // "disabled" | "stopped" | "connecting" | "needs_auth" | "connected" | "error"
	BackendState       string                `json:"backend_state,omitempty"`
	Online             bool                  `json:"online"`
	Expired            bool                  `json:"expired,omitempty"`
	IPv4               string                `json:"ipv4,omitempty"`
	IPv6               string                `json:"ipv6,omitempty"`
	TailscaleIPs       []string              `json:"tailscale_ips,omitempty"`
	Hostname           string                `json:"hostname,omitempty"`
	DNSName            string                `json:"dns_name,omitempty"`
	NetworkName        string                `json:"network_name,omitempty"`
	MagicDNSSuffix     string                `json:"magic_dns_suffix,omitempty"`
	AuthURL            string                `json:"auth_url,omitempty"`
	PeersOnline        int                   `json:"peers_online,omitempty"`
	PeersTotal         int                   `json:"peers_total,omitempty"`
	Peers              []TailscalePeerStatus `json:"peers,omitempty"`
	ActiveExitNodeID   string                `json:"active_exit_node_id,omitempty"`
	ActiveExitNodeName string                `json:"active_exit_node_name,omitempty"`
	CanShareFiles      bool                  `json:"can_share_files,omitempty"`
	WaitingFileCount   int32                 `json:"waiting_file_count,omitempty"`
	UnreadFileCount    int32                 `json:"unread_file_count,omitempty"`
	ControlAvailable   bool                  `json:"control_available,omitempty"`
	LastError          string                `json:"last_error,omitempty"`
	Source             string                `json:"source,omitempty"` // "live" | "log" | "none"
	UpdatedAt          string                `json:"updated_at,omitempty"`
}

type tailscaleLiveSnapshot struct {
	PID                int                   `json:"pid"`
	InstanceToken      string                `json:"instance_token,omitempty"`
	BackendState       string                `json:"backend_state"`
	Online             bool                  `json:"online"`
	Expired            bool                  `json:"expired,omitempty"`
	AuthURL            string                `json:"auth_url,omitempty"`
	SelfHostname       string                `json:"self_hostname,omitempty"`
	SelfDNSName        string                `json:"self_dns_name,omitempty"`
	TailscaleIPs       []string              `json:"tailscale_ips,omitempty"`
	NetworkName        string                `json:"network_name,omitempty"`
	MagicDNSSuffix     string                `json:"magic_dns_suffix,omitempty"`
	PeersOnline        int                   `json:"peers_online"`
	PeersTotal         int                   `json:"peers_total"`
	Peers              []TailscalePeerStatus `json:"peers,omitempty"`
	ActiveExitNodeID   string                `json:"active_exit_node_id,omitempty"`
	ActiveExitNodeName string                `json:"active_exit_node_name,omitempty"`
	CanShareFiles      bool                  `json:"can_share_files,omitempty"`
	WaitingFileCount   int32                 `json:"waiting_file_count,omitempty"`
	UnreadFileCount    int32                 `json:"unread_file_count,omitempty"`
	ControlAvailable   bool                  `json:"control_available,omitempty"`
	UpdatedAt          string                `json:"updated_at"`
}

func (s *Server) tailscaleStatusPath() string {
	base := ""
	if s.cfg != nil {
		base = strings.TrimSpace(s.cfg.RuntimeDir())
		if base == "" {
			base = strings.TrimSpace(s.cfg.DataDir())
		}
	}
	if base == "" && s.store != nil {
		base = filepath.Dir(s.store.Path())
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "tailscale-status.json")
}

func readTailscaleLiveSnapshot(path string, expectedPID int, expectedToken string) (*tailscaleLiveSnapshot, bool) {
	if strings.TrimSpace(path) == "" {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return nil, false
	}
	var snap tailscaleLiveSnapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, false
	}
	expectedToken = strings.TrimSpace(expectedToken)
	snapToken := strings.TrimSpace(snap.InstanceToken)
	if expectedToken != "" && snapToken != "" {
		if snapToken != expectedToken {
			return nil, false
		}
		return &snap, true
	}
	if expectedPID > 0 && snap.PID > 0 && snap.PID != expectedPID {
		return nil, false
	}
	return &snap, true
}

func (s *Server) tailscaleRuntimeStatus(cfg ruleset.TailscaleConfig, stateInit bool) TailscaleRuntimeStatus {
	out := TailscaleRuntimeStatus{
		State:    "disabled",
		Hostname: strings.TrimSpace(cfg.Hostname),
		Source:   "none",
	}
	if !cfg.Enabled {
		return out
	}

	orch := s.ensureOrchestrator()
	orchSt := orch.Status()
	logAuthURL, logErr, logUpdatedAt := orch.TailscaleLogTelemetry()

	if !orchSt.Running {
		out.State = "stopped"
		if errMsg := firstTailscaleError(logErr, orchSt.LastError); errMsg != "" {
			out.State = "error"
			out.LastError = errMsg
			out.Source = "log"
			if !logUpdatedAt.IsZero() {
				out.UpdatedAt = logUpdatedAt.Format(time.RFC3339)
			}
		}
		return out
	}

	if snap, ok := readTailscaleLiveSnapshot(s.tailscaleStatusPath(), orchSt.SingBoxPID, orch.TailscaleStatusToken()); ok {
		out.Source = "live"
		out.BackendState = strings.TrimSpace(snap.BackendState)
		out.Online = snap.Online
		out.Expired = snap.Expired
		out.NetworkName = strings.TrimSpace(snap.NetworkName)
		out.MagicDNSSuffix = strings.TrimSpace(snap.MagicDNSSuffix)
		out.PeersOnline = snap.PeersOnline
		out.PeersTotal = snap.PeersTotal
		out.ActiveExitNodeID = strings.TrimSpace(snap.ActiveExitNodeID)
		out.ActiveExitNodeName = strings.TrimSpace(snap.ActiveExitNodeName)
		out.CanShareFiles = snap.CanShareFiles
		out.WaitingFileCount = snap.WaitingFileCount
		out.UnreadFileCount = snap.UnreadFileCount
		out.ControlAvailable = snap.ControlAvailable
		if len(snap.Peers) > 0 {
			peers := make([]TailscalePeerStatus, 0, len(snap.Peers))
			for _, p := range snap.Peers {
				p.Hostname = strings.TrimSpace(p.Hostname)
				p.DNSName = strings.TrimSuffix(strings.TrimSpace(p.DNSName), ".")
				p.OS = strings.TrimSpace(p.OS)
				if p.IPv4 == "" || p.IPv6 == "" {
					for _, rawIP := range p.TailscaleIPs {
						clean := strings.TrimSpace(rawIP)
						if clean == "" {
							continue
						}
						if strings.Contains(clean, ":") {
							if p.IPv6 == "" {
								p.IPv6 = clean
							}
						} else if p.IPv4 == "" {
							p.IPv4 = clean
						}
					}
				}
				if p.Hostname == "" && p.DNSName != "" {
					p.Hostname = strings.SplitN(p.DNSName, ".", 2)[0]
				}
				peers = append(peers, p)
			}
			out.Peers = peers
		}
		out.UpdatedAt = strings.TrimSpace(snap.UpdatedAt)
		if snap.SelfHostname != "" {
			out.Hostname = snap.SelfHostname
		}
		out.DNSName = strings.TrimSuffix(strings.TrimSpace(snap.SelfDNSName), ".")
		out.AuthURL = strings.TrimSpace(snap.AuthURL)
		if out.AuthURL == "" && logAuthURL != "" {
			out.AuthURL = logAuthURL
		}
		for _, ip := range snap.TailscaleIPs {
			clean := strings.TrimSpace(ip)
			if clean == "" {
				continue
			}
			out.TailscaleIPs = append(out.TailscaleIPs, clean)
			if strings.Contains(clean, ":") {
				if out.IPv6 == "" {
					out.IPv6 = clean
				}
			} else if out.IPv4 == "" {
				out.IPv4 = clean
			}
		}

		switch out.BackendState {
		case "Running":
			if len(out.TailscaleIPs) > 0 || out.Online {
				out.State = "connected"
				out.AuthURL = ""
			} else {
				out.State = "connecting"
			}
		case "NeedsLogin", "NeedsMachineAuth":
			out.State = "needs_auth"
		case "Stopped":
			out.State = "stopped"
		default:
			if out.AuthURL != "" {
				out.State = "needs_auth"
			} else {
				out.State = "connecting"
			}
		}
		if out.State != "connected" && logErr != "" {
			out.LastError = logErr
			if out.State != "needs_auth" {
				out.State = "error"
			}
		}
		return out
	}

	// Desktop / upstream sing-box fallback: synthesize from live orchestrator log telemetry + state dir.
	out.Source = "log"
	if !logUpdatedAt.IsZero() {
		out.UpdatedAt = logUpdatedAt.Format(time.RFC3339)
	}
	if logAuthURL != "" {
		out.State = "needs_auth"
		out.BackendState = "NeedsLogin"
		out.AuthURL = logAuthURL
		return out
	}
	if logErr != "" {
		out.State = "error"
		out.LastError = logErr
		return out
	}
	if stateInit {
		out.State = "connected"
		out.BackendState = "Running"
		out.Online = true
		return out
	}
	out.State = "connecting"
	out.BackendState = "Starting"
	return out
}

func firstTailscaleError(candidates ...string) string {
	for _, c := range candidates {
		trimmed := strings.TrimSpace(c)
		if trimmed == "" {
			continue
		}
		low := strings.ToLower(trimmed)
		if strings.Contains(low, "tailscale") || strings.Contains(low, "tsnet") {
			return trimmed
		}
	}
	return ""
}

func (s *Server) tailscaleStateDir() string {
	base := ""
	if s.cfg != nil {
		base = strings.TrimSpace(s.cfg.DataDir())
	}
	if base == "" && s.store != nil {
		base = filepath.Dir(s.store.Path())
	}
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "tailscale-state")
}

func (s *Server) tailscaleConfig(includeSecret bool) (ruleset.TailscaleConfig, error) {
	cfg := ruleset.DefaultTailscaleConfig()
	if s.store == nil {
		return cfg, nil
	}
	if found, err := s.store.GetSetting(tailscaleSettingKey, &cfg); err != nil {
		return cfg, err
	} else if !found {
		cfg = ruleset.DefaultTailscaleConfig()
	}
	cfg.Normalize()
	cfg.AuthKey = ""
	cfg.ClearAuthKey = false
	if rawKey, found, err := s.store.GetSecret(tailscaleAuthKeySec); err == nil && found && len(rawKey) > 0 {
		cfg.HasAuthKey = true
		if includeSecret {
			cfg.AuthKey = string(rawKey)
		}
		clear(rawKey)
	} else {
		cfg.HasAuthKey = false
	}
	return cfg, nil
}

func (s *Server) tailscaleStateExists() bool {
	dir := s.tailscaleStateDir()
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

func (s *Server) handleTailscale(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		cfg, err := s.tailscaleConfig(false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		stateInit := s.tailscaleStateExists()
		writeJSON(w, http.StatusOK, map[string]any{
			"config":            cfg,
			"state_initialized": stateInit,
			"status":            s.tailscaleRuntimeStatus(cfg, stateInit),
			"system_tailscale":  sbcfg.DetectSystemTailscale(),
		})
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ruleset.TailscaleConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := req.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.DetourID != "" {
		validDetour := false
		if s.store != nil {
			if s.store.Get(req.DetourID) != nil {
				validDetour = true
			} else if groups, gErr := s.store.ListGroups(); gErr == nil {
				for _, g := range groups {
					if g.ID == req.DetourID {
						if storage.CanonicalGroupStrategy(g.Strategy) == "loadbalance" {
							http.Error(w, "Tailscale 前置中转不支持负载均衡分组，请选择单节点或故障切换/测速/手动分组", http.StatusBadRequest)
							return
						}
						validDetour = true
						break
					}
				}
			}
		}
		if !validDetour {
			http.Error(w, "指定的 Tailscale 前置中转节点或策略组不存在", http.StatusBadRequest)
			return
		}
	}

	s.opMu.Lock()
	prevCfg, _ := s.tailscaleConfig(true)
	if s.store != nil {
		if req.ClearAuthKey {
			_ = s.store.DeleteSetting(tailscaleAuthKeySec)
		} else if req.AuthKey != "" {
			if err := s.store.PutSecret(tailscaleAuthKeySec, []byte(req.AuthKey)); err != nil {
				s.opMu.Unlock()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		toSave := req
		toSave.AuthKey = ""
		toSave.HasAuthKey = false
		toSave.ClearAuthKey = false
		if err := s.store.PutSetting(tailscaleSettingKey, toSave); err != nil {
			s.opMu.Unlock()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Ensure state directory exists with private 0700 permissions when enabled.
	if req.Enabled {
		_ = os.MkdirAll(s.tailscaleStateDir(), 0o700)
	}

	running := s.ensureOrchestrator().Status().Running
	var applyErr error
	if running {
		rs := s.runtimeState()
		_, applyErr = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
		if applyErr != nil && s.store != nil {
			// Roll back persisted config on compile/preflight failure.
			rollback := prevCfg
			rollback.AuthKey = ""
			rollback.HasAuthKey = false
			rollback.ClearAuthKey = false
			_ = s.store.PutSetting(tailscaleSettingKey, rollback)
			if prevCfg.AuthKey != "" {
				_ = s.store.PutSecret(tailscaleAuthKeySec, []byte(prevCfg.AuthKey))
			} else {
				_ = s.store.DeleteSetting(tailscaleAuthKeySec)
			}
		}
	}
	s.opMu.Unlock()

	if applyErr != nil {
		respondError(w, applyErr, http.StatusBadGateway)
		return
	}

	saved, _ := s.tailscaleConfig(false)
	stateInit := s.tailscaleStateExists()
	writeJSON(w, http.StatusOK, map[string]any{
		"config":            saved,
		"state_initialized": stateInit,
		"status":            s.tailscaleRuntimeStatus(saved, stateInit),
	})
}

func (s *Server) handleTailscaleResetState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	dir := s.tailscaleStateDir()
	s.opMu.Lock()
	orch := s.ensureOrchestrator()
	running := orch.Status().Running
	if running {
		// Stop sing-box BEFORE deleting tailscale-state so an exiting tsnet cannot write stale
		// state back into the recreated directory.
		_ = orch.Stop()
	}
	if rmErr := os.RemoveAll(dir); rmErr != nil && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") {
		if sudoPass := s.effectiveSudoPassword(); len(sudoPass) > 0 && filepath.IsAbs(dir) && filepath.Base(dir) == "tailscale-state" {
			buf := make([]byte, len(sudoPass)+1)
			copy(buf, sudoPass)
			buf[len(sudoPass)] = '\n'
			cmd := exec.Command("sudo", "-S", "-p", "", "rm", "-rf", "--", dir)
			cmd.Stdin = bytes.NewReader(buf)
			_ = cmd.Run()
			for i := range buf {
				buf[i] = 0
			}
		}
	}
	if _, statErr := os.Stat(dir); statErr == nil || !os.IsNotExist(statErr) {
		s.opMu.Unlock()
		detail := "directory still exists"
		if statErr != nil {
			detail = statErr.Error()
		}
		http.Error(w, "failed to remove tailscale state directory: "+detail, http.StatusInternalServerError)
		return
	}
	var applyErr error
	if running {
		if tsCfg, err := s.tailscaleConfig(false); err == nil && tsCfg.Enabled {
			_ = os.MkdirAll(dir, 0o700)
		}
		rs := s.runtimeState()
		_, applyErr = s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled)
	}
	s.opMu.Unlock()
	if applyErr != nil {
		respondError(w, applyErr, http.StatusBadGateway)
		return
	}
	cfg, _ := s.tailscaleConfig(false)
	stateInit := s.tailscaleStateExists()
	writeJSON(w, http.StatusOK, map[string]any{
		"reset":             true,
		"state_initialized": stateInit,
		"status":            s.tailscaleRuntimeStatus(cfg, stateInit),
	})
}
