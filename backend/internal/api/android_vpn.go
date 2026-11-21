// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/androiddns"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/androidvpn"
)

func (s *Server) ensureAndroidVPN() *androidvpn.Manager {
	s.androidVPNMu.Lock()
	defer s.androidVPNMu.Unlock()
	if s.androidVPN == nil {
		s.androidVPN = androidvpn.NewManager()
	}
	return s.androidVPN
}

func (s *Server) ensureAndroidTun() *androidvpn.TunBridge {
	s.androidVPNMu.Lock()
	defer s.androidVPNMu.Unlock()
	if s.androidTun == nil {
		s.androidTun = androidvpn.NewTunBridge(nil)
	}
	return s.androidTun
}

func (s *Server) androidSocketDir() string {
	candidates := []string{}
	if s.cfg != nil {
		if rd := strings.TrimSpace(s.cfg.RuntimeDir()); rd != "" && rd != "." {
			candidates = append(candidates, rd)
		}
		if dd := strings.TrimSpace(s.cfg.DataDir()); dd != "" && dd != "." {
			candidates = append(candidates, dd)
		}
	}
	if s.store != nil {
		if sd := strings.TrimSpace(filepath.Dir(s.store.Path())); sd != "" && sd != "." {
			candidates = append(candidates, sd)
		}
	}
	candidates = append(candidates, os.TempDir())
	for _, dir := range candidates {
		if abs, err := filepath.Abs(dir); err == nil && abs != "" {
			return abs
		}
	}
	return os.TempDir()
}

func (s *Server) handleAndroidVPNDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Servers []string `json:"servers"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updated := androiddns.SetSystemServers(req.Servers)
	writeJSON(w, http.StatusOK, map[string]any{
		"system_servers": updated,
		"active_servers": androiddns.ActiveServers(),
	})
}

func (s *Server) handleAndroidVPNStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	vpnStatus := s.ensureAndroidVPN().Status()
	tunBridge := s.ensureAndroidTun()
	st := s.ensureOrchestrator().Status()
	bypassLAN := true
	allowLANBroadcast := false
	ipv6Enabled := false
	profile, err := s.routingProfile()
	if err == nil {
		bypassLAN = profile.BypassLAN
		allowLANBroadcast = profile.BypassLAN && profile.AllowLANBroadcast
		ipv6Enabled = profile.IPv6Enabled()
		if vpnStatus.PerAppMode == "" || vpnStatus.PerAppMode == "all" {
			if profile.PerAppMode != "" {
				vpnStatus.PerAppMode = profile.PerAppMode
			}
		}
		if len(vpnStatus.PerAppPackages) == 0 && len(profile.PerAppPackages) > 0 {
			vpnStatus.PerAppPackages = profile.PerAppPackages
		}
	}
	mixedPort := st.MixedPort
	if mixedPort <= 0 {
		mixedPort = vpnStatus.MixedPort
	}
	if mixedPort <= 0 && s.cfg != nil {
		mixedPort = s.cfg.SingBox.MixedPort
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":              vpnStatus.Active,
		"running":             st.Running,
		"protect_path":        vpnStatus.ProtectPath,
		"owner_path":          vpnStatus.OwnerPath,
		"tun_socket_path":     tunBridge.SocketPath(),
		"tun_active":          tunBridge.Active(),
		"tun_fd":              vpnStatus.TunFD,
		"mixed_port":          mixedPort,
		"per_app_mode":        vpnStatus.PerAppMode,
		"per_app_packages":    vpnStatus.PerAppPackages,
		"bypass_lan":          bypassLAN,
		"allow_lan_broadcast": allowLANBroadcast,
		"ipv6_enabled":        ipv6Enabled,
		"active_node_id":      s.activeNodeID,
		"active_group_id":     s.activeGroupID,
		"updated_at":          vpnStatus.UpdatedAt,
	})
}

func (s *Server) handleAndroidVPNStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var cfg androidvpn.Config
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	sockDir := s.androidSocketDir()
	if strings.TrimSpace(cfg.ProtectPath) == "" {
		cfg.ProtectPath = filepath.Join(sockDir, "protect.sock")
	}
	if strings.TrimSpace(cfg.OwnerPath) == "" {
		cfg.OwnerPath = filepath.Join(sockDir, "owner.sock")
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if cfg.PerAppMode != "" || cfg.PerAppPackages != nil {
		profile, err := s.routingProfile()
		if err == nil {
			if cfg.PerAppMode != "" {
				profile.PerAppMode = cfg.PerAppMode
			}
			if cfg.PerAppPackages != nil {
				profile.PerAppPackages = cfg.PerAppPackages
			}
			_ = s.saveRoutingProfile(profile)
		}
	}

	s.protectPath = strings.TrimSpace(cfg.ProtectPath)
	s.ownerPath = strings.TrimSpace(cfg.OwnerPath)
	nodeID := strings.TrimSpace(cfg.ActiveNodeID)
	groupID := strings.TrimSpace(cfg.ActiveGroupID)
	if nodeID == "" && groupID == "" {
		nodeID = s.activeNodeID
		groupID = s.activeGroupID
	}

	runtimeStatus, err := s.reconcileRuntime(r.Context(), nodeID, groupID, false)
	if err != nil {
		respondError(w, err, http.StatusBadGateway)
		return
	}
	cfg.MixedPort = runtimeStatus.MixedPort
	vpnStatus, err := s.ensureAndroidVPN().Start(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	tunSockPath := filepath.Join(sockDir, "tun.sock")
	if _, listenErr := s.ensureAndroidTun().Listen(tunSockPath, runtimeStatus.MixedPort, 1500); listenErr != nil {
		respondError(w, listenErr, http.StatusInternalServerError)
		return
	}
	s.syncAndroidAppRouting(runtimeStatus)

	bypassLAN := true
	allowLANBroadcast := false
	ipv6Enabled := false
	if currentProfile, pErr := s.routingProfile(); pErr == nil {
		bypassLAN = currentProfile.BypassLAN
		allowLANBroadcast = currentProfile.BypassLAN && currentProfile.AllowLANBroadcast
		ipv6Enabled = currentProfile.IPv6Enabled()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":              vpnStatus.Active,
		"protect_path":        vpnStatus.ProtectPath,
		"owner_path":          vpnStatus.OwnerPath,
		"tun_socket_path":     tunSockPath,
		"tun_fd":              vpnStatus.TunFD,
		"mixed_port":          vpnStatus.MixedPort,
		"per_app_mode":        vpnStatus.PerAppMode,
		"per_app_packages":    vpnStatus.PerAppPackages,
		"bypass_lan":          bypassLAN,
		"allow_lan_broadcast": allowLANBroadcast,
		"ipv6_enabled":        ipv6Enabled,
		"updated_at":          vpnStatus.UpdatedAt,
	})
}

func (s *Server) handleAndroidVPNStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	s.wantRunning = false
	s.protectPath = ""
	s.ownerPath = ""
	s.ensureAndroidTun().ConfigureAppRouting(androidvpn.AppRoutingConfig{})
	s.ensureAndroidTun().Stop()
	if err := s.ensureOrchestrator().Stop(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	vpnStatus := s.ensureAndroidVPN().Stop()
	writeJSON(w, http.StatusOK, vpnStatus)
}

func (s *Server) handleAndroidVPNError(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	msg := strings.TrimSpace(req.Message)
	if msg != "" {
		s.ensureOrchestrator().AppendLog("android-vpn", "error", msg)
	}
	writeJSON(w, http.StatusOK, map[string]any{"recorded": msg != ""})
}
