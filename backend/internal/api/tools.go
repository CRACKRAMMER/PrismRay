// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net"
	"net/http"
	"runtime"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
)

func (s *Server) SetSettingsPath(path string) { s.settingsPath = path }

func isLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "127.0.0.1" || h == "localhost" || h == "::1"
}

func isValidBindHost(host string) bool {
	h := strings.TrimSpace(host)
	if h == "" {
		return false
	}
	if isLoopbackHost(h) || h == "0.0.0.0" || h == "::" {
		return true
	}
	return net.ParseIP(strings.Trim(h, "[]")) != nil
}

func sanitizeSettingsForResponse(in *appconfig.Config) appconfig.Config {
	if in == nil {
		return appconfig.Config{}
	}
	cp := *in
	cp.SingBox.ClashAPISecret = ""
	return cp
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		if s.store != nil {
			var stored appconfig.Config
			if found, err := s.store.GetSetting("app.settings", &stored); err == nil && found {
				writeJSON(w, http.StatusOK, sanitizeSettingsForResponse(&stored))
				return
			}
		}
		writeJSON(w, http.StatusOK, sanitizeSettingsForResponse(s.cfg))
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
	// Preserve server-controlled binary, storage, secret, and origin security fields; never allow
	// client JSON to redirect sing-box/xray paths toward arbitrary binaries or alter CORS origins.
	if s.cfg != nil {
		cfg.SingBox.BinaryPath = s.cfg.SingBox.BinaryPath
		cfg.SingBox.ConfigPath = s.cfg.SingBox.ConfigPath
		cfg.SingBox.RuleSetDir = s.cfg.SingBox.RuleSetDir
		if strings.TrimSpace(cfg.SingBox.ClashAPISecret) == "" {
			cfg.SingBox.ClashAPISecret = s.cfg.SingBox.ClashAPISecret
		}
		cfg.Xray.BinaryPath = s.cfg.Xray.BinaryPath
		cfg.Xray.ConfigPath = s.cfg.Xray.ConfigPath
		cfg.Storage.DatabasePath = s.cfg.Storage.DatabasePath
		cfg.Storage.NodesFile = s.cfg.Storage.NodesFile
		cfg.Server.AllowedOrigins = append([]string(nil), s.cfg.Server.AllowedOrigins...)
	}
	if s.mode == authservice.ModeWeb {
		if !isValidBindHost(cfg.Server.Host) {
			http.Error(w, "无效的监听地址（请使用 0.0.0.0、127.0.0.1 或本机 IP）", http.StatusBadRequest)
			return
		}
	} else if !isLoopbackHost(cfg.Server.Host) {
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
		"saved":            sanitizeSettingsForResponse(&cfg),
	})
}

var redactedConfigKeys = map[string]bool{
	"password":            true,
	"uuid":                true,
	"private_key":         true,
	"auth_key":            true,
	"secret":              true,
	"token":               true,
	"pre_shared_key":      true,
	"obfs_password":       true,
	"short_id":            true,
	"credential":          true,
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"api-key":             true,
}

func redactCompiledJSONValue(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for k, val := range typed {
			if redactedConfigKeys[strings.ToLower(k)] {
				switch vv := val.(type) {
				case string:
					if strings.TrimSpace(vv) != "" {
						out[k] = "***REDACTED***"
						continue
					}
				case []any:
					if len(vv) > 0 {
						redactedArr := make([]any, len(vv))
						for i, item := range vv {
							if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
								redactedArr[i] = "***REDACTED***"
							} else {
								redactedArr[i] = item
							}
						}
						out[k] = redactedArr
						continue
					}
				}
			}
			out[k] = redactCompiledJSONValue(val)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = redactCompiledJSONValue(item)
		}
		return out
	default:
		return v
	}
}

func (s *Server) handleCompiledConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nodes := s.store.List()
	groups, _ := s.store.ListGroups()
	listeners := s.store.ListListeners()
	routing, err := s.routingProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	ruleSets, _ := s.effectiveRuleSets()
	rs := s.runtimeState()
	androidMode, protectPath := s.androidRuntimeSettings()

	mixedPort := 10808
	clashPort := 9090
	if s.cfg != nil {
		if s.cfg.SingBox.MixedPort > 0 {
			mixedPort = s.cfg.SingBox.MixedPort
		}
		if s.cfg.SingBox.ClashAPIPort > 0 {
			clashPort = s.cfg.SingBox.ClashAPIPort
		}
	}
	hs, _ := s.healthSettings()
	xrayBridgePorts := map[string]int{}
	for _, n := range nodes {
		if n != nil && n.ID != "" && n.RequiresXray() {
			xrayBridgePorts[n.ID] = 41000 + len(xrayBridgePorts)
		}
	}
	var tsCfgPtr *ruleset.TailscaleConfig
	tsStateDir := ""
	if tsCfg, tsErr := s.tailscaleConfig(false); tsErr == nil && tsCfg.Enabled {
		tsCfgPtr = &tsCfg
		tsStateDir = s.tailscaleStateDir()
	}
	compiled, err := sbcfg.Compile(sbcfg.CompileInput{
		Nodes:             nodes,
		Groups:            groups,
		Listeners:         listeners,
		Routing:           routing,
		RuleSets:          ruleSets,
		ActiveNodeID:      rs.activeNodeID,
		ActiveGroupID:     rs.activeGroupID,
		MixedPort:         mixedPort,
		ClashAPIPort:      clashPort,
		ClashAPISecret:    "***REDACTED***",
		EnableTUN:         rs.tunEnabled,
		TUNStack:          rs.tunStack,
		AndroidMode:       androidMode,
		ProtectPath:       protectPath,
		XrayBridgePorts:   xrayBridgePorts,
		HighLatencyMS:     hs.HighLatencyMS,
		Tailscale:         tsCfgPtr,
		TailscaleStateDir: tsStateDir,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var parsed any
	if err := json.Unmarshal(compiled.Raw, &parsed); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	redacted := redactCompiledJSONValue(parsed)
	formatted, err := json.MarshalIndent(redacted, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"engine":     "sing-box",
		"active_tag": compiled.ActiveTag,
		"redacted":   true,
		"config":     string(formatted),
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
		"version":         "1.1.0",
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
