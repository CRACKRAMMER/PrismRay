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
	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
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

func (s *Server) androidNetIfPath() string {
	return filepath.Join(s.androidSocketDir(), "android-netif.json")
}

func (s *Server) handleAndroidVPNDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Servers    []string        `json:"servers"`
		Interfaces json.RawMessage `json:"interfaces,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updated := androiddns.SetSystemServers(req.Servers)
	if len(req.Interfaces) > 0 {
		var parsed []map[string]any
		if json.Unmarshal(req.Interfaces, &parsed) == nil && len(parsed) > 0 {
			if rawSnap, mErr := json.Marshal(map[string]any{"interfaces": parsed}); mErr == nil {
				_ = fileutil.WritePrivate(s.androidNetIfPath(), rawSnap)
				s.ensureOrchestrator().NotifyAndroidNetworkChanged()
			}
		}
	}
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
	tailscaleEnabled := false
	var tailscaleSubnets []string
	if tsCfg, tsErr := s.tailscaleConfig(false); tsErr == nil && tsCfg.Enabled {
		tailscaleEnabled = true
		tailscaleSubnets = tsCfg.EffectiveSubnets()
	}
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
	tunEngine := "hev"
	if len(st.AppPackages) > 0 {
		tunEngine = "tun2socks"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":              vpnStatus.Active,
		"running":             st.Running,
		"protect_path":        vpnStatus.ProtectPath,
		"owner_path":          vpnStatus.OwnerPath,
		"tun_socket_path":     tunBridge.SocketPath(),
		"tun_engine":          tunEngine,
		"tun_active":          tunBridge.Active(),
		"tun_fd":              vpnStatus.TunFD,
		"mixed_port":          mixedPort,
		"per_app_mode":        vpnStatus.PerAppMode,
		"per_app_packages":    vpnStatus.PerAppPackages,
		"bypass_lan":          bypassLAN,
		"allow_lan_broadcast": allowLANBroadcast,
		"ipv6_enabled":        ipv6Enabled,
		"tailscale_enabled":   tailscaleEnabled,
		"tailscale_subnets":   tailscaleSubnets,
		"active_node_id":      s.runtimeState().activeNodeID,
		"active_group_id":     s.runtimeState().activeGroupID,
		"updated_at":          vpnStatus.UpdatedAt,
	})
}

// handleAndroidVPNTelemetry returns a minimal low-overhead payload for Android VPN notifications
// without serializing the full Clash API /proxies or /connections tables when not needed.
func (s *Server) handleAndroidVPNTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	includeTraffic := r.URL.Query().Get("include_traffic") == "1" || r.URL.Query().Get("include_traffic") == "true"

	orch := s.ensureOrchestrator()
	st := orch.Status()

	rs := s.runtimeState()
	activeNodeID := rs.activeNodeID
	activeGroupID := rs.activeGroupID
	if activeNodeID == "" {
		activeNodeID = st.ActiveNodeID
	}
	if activeGroupID == "" {
		activeGroupID = st.ActiveGroupID
	}

	activeLabel := ""
	if activeGroupID != "" && s.store != nil {
		var groupName, selectedNodeID string
		if groups, err := s.store.ListGroups(); err == nil {
			for _, g := range groups {
				if g.ID == activeGroupID {
					groupName = strings.TrimSpace(g.Name)
					selectedNodeID = strings.TrimSpace(g.SelectedNodeID)
					break
				}
			}
		}
		resolvedName := ""
		if st.Running {
			if leafTag := orch.ResolveLiveGroupSelection(r.Context(), "group-"+activeGroupID); strings.HasPrefix(leafTag, "node-") {
				leafID := strings.TrimPrefix(leafTag, "node-")
				if idx := strings.Index(leafID, "--via-"); idx > 0 {
					leafID = leafID[:idx]
				}
				if n := s.store.Get(leafID); n != nil {
					resolvedName = strings.TrimSpace(n.DisplayName())
				}
			}
		}
		if resolvedName == "" && selectedNodeID != "" {
			if n := s.store.Get(selectedNodeID); n != nil {
				resolvedName = strings.TrimSpace(n.DisplayName())
			}
		}
		switch {
		case groupName != "" && resolvedName != "" && resolvedName != groupName:
			activeLabel = groupName + " → " + resolvedName
		case groupName != "":
			activeLabel = groupName
		case resolvedName != "":
			activeLabel = resolvedName
		}
	} else if activeNodeID != "" && s.store != nil {
		if n := s.store.Get(activeNodeID); n != nil {
			activeLabel = strings.TrimSpace(n.DisplayName())
		}
	}

	var uploadTotal, downloadTotal int64
	var splitRates TrafficRates
	hasSplitRates := false
	if includeTraffic && st.Running {
		rates, upTot, downTot, ok := s.ensureConnectionsHub().TelemetryRates(r.Context(), st.SingBoxPID)
		if ok {
			splitRates = rates
			uploadTotal = upTot
			downloadTotal = downTot
			hasSplitRates = true
		} else if tunBridge := s.ensureAndroidTun(); tunBridge.Active() {
			uploadTotal, downloadTotal = tunBridge.TrafficTotals()
		}
	} else if !st.Running {
		s.androidTrafficMu.Lock()
		if s.androidTrafficTracker != nil {
			s.androidTrafficTracker.Reset()
		}
		s.androidTrafficPID = 0
		s.androidTrafficMu.Unlock()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"running":          st.Running,
		"active_label":     activeLabel,
		"upload_total":     uploadTotal,
		"download_total":   downloadTotal,
		"has_split_rates":  hasSplitRates,
		"up_rate":          splitRates.Up,
		"down_rate":        splitRates.Down,
		"proxy_up_rate":    splitRates.ProxyUp,
		"proxy_down_rate":  splitRates.ProxyDown,
		"direct_up_rate":   splitRates.DirectUp,
		"direct_down_rate": splitRates.DirectDown,
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

	s.setAndroidSocketPaths(cfg.ProtectPath, cfg.OwnerPath)
	nodeID := strings.TrimSpace(cfg.ActiveNodeID)
	groupID := strings.TrimSpace(cfg.ActiveGroupID)
	if nodeID == "" && groupID == "" {
		rs := s.runtimeState()
		nodeID = rs.activeNodeID
		groupID = rs.activeGroupID
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

	const androidTunMTU = 8500
	hevAvailable := cfg.HevAvailable == nil || *cfg.HevAvailable
	tunEngine := "hev"
	tunSockPath := ""
	if !hevAvailable || len(runtimeStatus.AppPackages) > 0 {
		tunEngine = "tun2socks"
		tunSockPath = filepath.Join(sockDir, "tun.sock")
		if _, listenErr := s.ensureAndroidTun().Listen(tunSockPath, runtimeStatus.MixedPort, androidTunMTU); listenErr != nil {
			respondError(w, listenErr, http.StatusInternalServerError)
			return
		}
		s.syncAndroidAppRouting(runtimeStatus)
	} else {
		// Native C/lwIP hev-socks5-tunnel handles the VPN fd directly inside ProxyVpnService;
		// stop any previous Go tun2socks listener and skip owner.sock overhead.
		s.ensureAndroidTun().ConfigureAppRouting(androidvpn.AppRoutingConfig{})
		s.ensureAndroidTun().Stop()
	}

	bypassLAN := true
	allowLANBroadcast := false
	ipv6Enabled := false
	tailscaleEnabled := false
	var tailscaleSubnets []string
	if tsCfg, tsErr := s.tailscaleConfig(false); tsErr == nil && tsCfg.Enabled {
		tailscaleEnabled = true
		tailscaleSubnets = tsCfg.EffectiveSubnets()
	}
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
		"tun_engine":          tunEngine,
		"mtu":                 androidTunMTU,
		"tun_fd":              vpnStatus.TunFD,
		"mixed_port":          vpnStatus.MixedPort,
		"per_app_mode":        vpnStatus.PerAppMode,
		"per_app_packages":    vpnStatus.PerAppPackages,
		"bypass_lan":          bypassLAN,
		"allow_lan_broadcast": allowLANBroadcast,
		"ipv6_enabled":        ipv6Enabled,
		"tailscale_enabled":   tailscaleEnabled,
		"tailscale_subnets":   tailscaleSubnets,
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
	s.persistWantRunning(false)
	s.setAndroidSocketPaths("", "")
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
