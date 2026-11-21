// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
)

func (s *Server) SetSettingsPath(path string) { s.settingsPath = path }

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if s.store != nil {
			var stored appconfig.Config
			if found, err := s.store.GetSetting("app.settings", &stored); err == nil && found {
				writeJSON(w, http.StatusOK, &stored)
				return
			}
		}
		writeJSON(w, http.StatusOK, s.cfg)
		return
	}
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var cfg appconfig.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !isLoopbackHost(cfg.Server.Host) {
		http.Error(w, "API 必须绑定本机回环地址", http.StatusBadRequest)
		return
	}
	if cfg.SingBox.MixedPort <= 0 && cfg.Xray.SocksPort > 0 {
		cfg.SingBox.MixedPort = cfg.Xray.SocksPort
	}
	if cfg.SingBox.MixedPort < 1 || cfg.SingBox.MixedPort > 65535 ||
		cfg.SingBox.ClashAPIPort < 1 || cfg.SingBox.ClashAPIPort > 65535 ||
		cfg.Server.Port < 1 || cfg.Server.Port > 65535 ||
		cfg.Xray.StatsPort < 1 || cfg.Xray.StatsPort > 65535 ||
		cfg.SingBox.MixedPort == cfg.Server.Port ||
		cfg.SingBox.MixedPort == cfg.SingBox.ClashAPIPort ||
		cfg.Server.Port == cfg.SingBox.ClashAPIPort ||
		strings.TrimSpace(cfg.Storage.DatabasePath) == "" {
		http.Error(w, "端口冲突、端口超出范围或路径为空", http.StatusBadRequest)
		return
	}
	if s.settingsPath == "" {
		http.Error(w, "settings path unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := cfg.Save(s.settingsPath); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.store != nil {
		if err := s.store.PutSetting("app.settings", &cfg); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	// Do not mutate live runtime s.cfg ports/addresses until restart.
	writeJSON(w, http.StatusOK, map[string]any{
		"restart_required": true,
		"saved":            cfg,
	})
}

func (s *Server) handleExport(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="prismray-export.json"`)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version":   4,
		"nodes":     s.store.List(),
		"listeners": s.store.ListListeners(),
	})
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var b struct {
		Version   int                    `json:"version"`
		Nodes     []*config.Node         `json:"nodes"`
		Listeners []*config.ListenConfig `json:"listeners"`
	}
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil || (b.Version != 1 && b.Version != 4) {
		http.Error(w, "invalid backup format", http.StatusBadRequest)
		return
	}
	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.ensureOrchestrator().Status().Running {
		http.Error(w, "请先断开连接再恢复备份", http.StatusConflict)
		return
	}
	if err := s.store.Restore(b.Nodes, b.Listeners); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"restored": len(b.Nodes)})
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	st := s.ensureOrchestrator().Status()
	sbPath, _ := s.ensureOrchestrator().ResolveSingBoxBinary()
	xrayPath, _ := s.ensureOrchestrator().ResolveXrayBinary()
	groups, _ := s.store.ListGroups()
	subs, _ := s.subscriptions()
	coreStatus := "stopped"
	if st.Running {
		coreStatus = "running"
	}
	mixedPort := st.MixedPort
	clashPort := st.ClashAPIPort
	if s.cfg != nil {
		if mixedPort == 0 {
			mixedPort = s.cfg.SingBox.MixedPort
		}
		if clashPort == 0 {
			clashPort = s.cfg.SingBox.ClashAPIPort
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":         "1.0.1",
		"os":              runtime.GOOS,
		"arch":            runtime.GOARCH,
		"go":              runtime.Version(),
		"mode":            s.mode,
		"core_status":     coreStatus,
		"singbox_running": st.SingBoxRunning,
		"xray_running":    st.XrayRunning,
		"tun_enabled":     st.TUNEnabled,
		"android_mode":    st.AndroidMode,
		"singbox_binary":  sbPath,
		"xray_binary":     xrayPath,
		"nodes":           len(s.store.List()),
		"groups":          len(groups),
		"subscriptions":   len(subs),
		"listeners":       len(s.store.ListListeners()),
		"mixed_port":      mixedPort,
		"clash_api_port":  clashPort,
		"last_error":      st.LastError,
	})
}
