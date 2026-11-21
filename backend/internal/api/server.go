// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/androidvpn"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/orchestrator"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/process"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/stats"
)

// Server serves the PrismRay control-plane HTTP and WebSocket API.
type Server struct {
	auth                *authservice.Manager
	web                 http.Handler
	webRoot             *os.Root
	listenerHealth      string
	httpMu              sync.Mutex
	httpServer          *http.Server
	wantRunning         bool
	lastHealth          time.Time
	coreMu              sync.Mutex
	lastCoreCheck       time.Time
	token               string
	desktop             bool
	mode                string
	ipcPath             string
	settingsPath        string
	singBoxBinary       string
	xrayBinary          string
	protectPath         string
	ownerPath           string
	tunStack            string
	opMu                sync.Mutex
	orchMu              sync.Mutex
	orch                *orchestrator.Orchestrator
	androidVPNMu        sync.Mutex
	androidVPN          *androidvpn.Manager
	androidTun          *androidvpn.TunBridge
	activeNodeID        string
	activeGroupID       string
	tunEnabled          bool
	systemProxyWanted   bool
	ksMu                sync.RWMutex
	intendedActiveTag   string
	killSwitchTripped   bool
	killSwitchFailures  int
	killSwitchReason    string
	lastKillSwitchCheck time.Time
	ruleSetSyncMu       sync.Mutex
	autoSyncedRuleSets  atomic.Bool
	failMu              sync.Mutex
	nodeFailTimes       map[string][]time.Time
	nodeFastProbeAt     map[string]time.Time
	pm                  *process.Manager
	store               *storage.Store
	stats               *stats.Client
	cfg                 *appconfig.Config
}

// NewServer constructs an API Server backed by SQLite storage and the dual-core Orchestrator.
func NewServer(pm *process.Manager, store *storage.Store, statsClient *stats.Client, cfg *appconfig.Config) *Server {
	s := &Server{
		pm:              pm,
		store:           store,
		stats:           statsClient,
		cfg:             cfg,
		nodeFailTimes:   map[string][]time.Time{},
		nodeFastProbeAt: map[string]time.Time{},
	}
	if cfg != nil {
		s.singBoxBinary = cfg.SingBox.BinaryPath
		s.xrayBinary = cfg.Xray.BinaryPath
		if store != nil {
			var nodeID, groupID string
			var tunEnabled bool
			if found, err := store.GetSetting("runtime.active_node_id", &nodeID); err == nil && found {
				s.activeNodeID = nodeID
			}
			if found, err := store.GetSetting("runtime.active_group_id", &groupID); err == nil && found {
				s.activeGroupID = groupID
			}
			if found, err := store.GetSetting("runtime.tun_enabled", &tunEnabled); err == nil && found {
				s.tunEnabled = tunEnabled
			}
			var wantRunning, sysProxyWanted bool
			if found, err := store.GetSetting("runtime.want_running", &wantRunning); err == nil && found {
				s.wantRunning = wantRunning
			}
			if found, err := store.GetSetting("runtime.system_proxy_enabled", &sysProxyWanted); err == nil && found {
				s.systemProxyWanted = sysProxyWanted
			}
		}
	}
	s.ensureOrchestrator()
	return s
}

func (s *Server) SetAuth(auth *authservice.Manager) { s.auth = auth }

func corsMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, o := range allowedOrigins {
		allowed[o] = struct{}{}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			if _, ok := allowed[origin]; !ok {
				http.Error(w, "origin not allowed", http.StatusForbidden)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Handler returns the authenticated HTTP multiplexer with CORS protection.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.web != nil {
		mux.Handle("GET /", s.web)
	}
	mux.HandleFunc("GET /api/backup", s.handleBackup)
	mux.HandleFunc("POST /api/backup", s.handleBackup)
	mux.HandleFunc("GET /api/nodes/{id}/uri", func(w http.ResponseWriter, r *http.Request) {
		n := s.store.Get(r.PathValue("id"))
		if n == nil {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"uri": n.URI()})
	})

	// Core binaries and diagnostics
	mux.HandleFunc("GET /api/app/update-check", s.handleAppUpdateCheck)
	mux.HandleFunc("GET /api/cores", s.handleCores)
	mux.HandleFunc("POST /api/cores", s.handleCores)
	mux.HandleFunc("POST /api/cores/ensure", s.handleEnsureCores)
	mux.HandleFunc("GET /api/logs/export", s.handleLogExport)
	mux.HandleFunc("GET /api/tun", s.handleTUN)
	mux.HandleFunc("PUT /api/tun", s.handleTUN)
	mux.HandleFunc("GET /api/tun/privilege", s.handleTUNPrivilege)
	mux.HandleFunc("POST /api/tun/authorize", s.handleTUNAuthorize)
	mux.HandleFunc("GET /api/vpn/android/status", s.handleAndroidVPNStatus)
	mux.HandleFunc("POST /api/vpn/android/start", s.handleAndroidVPNStart)
	mux.HandleFunc("POST /api/vpn/android/stop", s.handleAndroidVPNStop)
	mux.HandleFunc("POST /api/vpn/android/dns", s.handleAndroidVPNDNS)
	mux.HandleFunc("POST /api/vpn/android/error", s.handleAndroidVPNError)
	mux.HandleFunc("GET /api/health-settings", s.handleHealthSettings)
	mux.HandleFunc("PUT /api/health-settings", s.handleHealthSettings)
	mux.HandleFunc("GET /api/system-proxy", s.handleSystemProxy)
	mux.HandleFunc("PUT /api/system-proxy", s.handleSystemProxy)
	mux.HandleFunc("GET /api/autostart", s.handleAutostart)
	mux.HandleFunc("PUT /api/autostart", s.handleAutostart)
	mux.HandleFunc("GET /api/settings", s.handleSettings)
	mux.HandleFunc("PUT /api/settings", s.handleSettings)
	mux.HandleFunc("GET /api/export", s.handleExport)
	mux.HandleFunc("POST /api/restore", s.handleRestore)
	mux.HandleFunc("GET /api/diagnostics", s.handleDiagnostics)

	// Routing, .srs rulesets & legacy preferences bridge
	mux.HandleFunc("GET /api/routing", s.handleRouting)
	mux.HandleFunc("PUT /api/routing", s.handleRouting)
	mux.HandleFunc("POST /api/routing/simulate", s.handleRoutingSimulate)
	mux.HandleFunc("GET /api/rulesets", s.handleRuleSets)
	mux.HandleFunc("POST /api/rulesets", s.handleRuleSets)
	mux.HandleFunc("POST /api/rulesets/sync", s.handleSyncRuleSets)
	mux.HandleFunc("GET /api/preferences", s.handlePreferences)
	mux.HandleFunc("PUT /api/preferences", s.handlePreferences)

	// Process & runtime lifecycle
	mux.HandleFunc("POST /api/process/connect", s.handleConnect)
	mux.HandleFunc("POST /api/process/start", s.handleStart)
	mux.HandleFunc("POST /api/process/stop", s.handleStop)
	mux.HandleFunc("POST /api/process/restart", s.handleRestart)
	mux.HandleFunc("GET /api/process/status", s.handleStatus)

	// Telemetry streams & Clash API connections
	mux.HandleFunc("GET /api/logs", s.handleLogs)
	mux.HandleFunc("GET /api/traffic", s.handleTraffic)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections/{id}", s.handleConnections)

	// Config endpoints
	mux.HandleFunc("POST /api/config/apply", s.handleApplyConfig)
	mux.HandleFunc("GET /api/config/server", s.handleGetServerConfig)

	// Nodes, groups, and latency probes
	mux.HandleFunc("GET /api/nodes", s.handleListNodes)
	mux.HandleFunc("POST /api/nodes", s.handleAddNode)
	mux.HandleFunc("PUT /api/nodes/{id}", s.handleUpdateNode)
	mux.HandleFunc("DELETE /api/nodes/{id}", s.handleDeleteNode)
	mux.HandleFunc("GET /api/nodes/{id}/probe", s.handleHealth)
	mux.HandleFunc("POST /api/nodes/probe", s.handleProbeNodes)
	mux.HandleFunc("POST /api/nodes/{id}/probe", s.handleHealth)
	mux.HandleFunc("POST /api/nodes/{id}/ping", s.handlePing)
	mux.HandleFunc("POST /api/nodes/{id}/health", s.handleHealth)
	mux.HandleFunc("GET /api/node-tabs", s.handleNodeTabs)
	mux.HandleFunc("PUT /api/node-tabs", s.handleNodeTabs)
	mux.HandleFunc("GET /api/groups", s.handleGroups)
	mux.HandleFunc("POST /api/groups", s.handleGroups)
	mux.HandleFunc("PUT /api/groups/reorder", s.handleReorderGroups)
	mux.HandleFunc("PUT /api/groups/{id}", s.handleGroup)
	mux.HandleFunc("DELETE /api/groups/{id}", s.handleGroup)
	mux.HandleFunc("POST /api/groups/{id}/probe", s.handleGroupProbe)
	mux.HandleFunc("PUT /api/groups/{id}/select", s.handleGroupSelect)

	// Subscriptions
	mux.HandleFunc("GET /api/subscriptions", s.handleSubscriptions)
	mux.HandleFunc("POST /api/subscriptions", s.handleSubscriptions)
	mux.HandleFunc("PUT /api/subscriptions/{id}", s.handleUpdateSubscription)
	mux.HandleFunc("DELETE /api/subscriptions/{id}", s.handleSubscriptions)
	mux.HandleFunc("POST /api/subscriptions/{id}/refresh", s.handleRefreshSubscription)
	mux.HandleFunc("POST /api/subscription/import", s.handleImportSubscription)

	// Listeners
	mux.HandleFunc("GET /api/listeners", s.handleListListeners)
	mux.HandleFunc("POST /api/listeners", s.handleAddListener)
	mux.HandleFunc("PUT /api/listeners/{id}", s.handleUpdateListener)
	mux.HandleFunc("DELETE /api/listeners/{id}", s.handleDeleteListener)
	mux.HandleFunc("POST /api/listeners/apply", s.handleApplyListeners)

	// Legacy Xray download endpoint
	mux.HandleFunc("POST /api/xray/download", s.handleDownloadXray)

	// Authentication
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/initialize", s.handleAuthInitialize)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("POST /api/auth/lock", s.handleAuthLock)
	mux.HandleFunc("POST /api/auth/password-lock", s.handlePasswordLock)
	mux.HandleFunc("POST /api/auth/biometric", s.handleBiometricConfig)
	mux.HandleFunc("POST /api/auth/biometric-unlock", s.handleBiometricUnlock)
	mux.HandleFunc("PUT /api/auth/sudo-cache", s.handleSudoCache)
	mux.HandleFunc("DELETE /api/auth/sudo-cache", s.handleSudoCache)

	auth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trustedDesktop := false
		if s.token != "" {
			token := r.Header.Get("Authorization")
			if token == "" && (r.URL.Path == "/api/logs" || r.URL.Path == "/api/traffic" || r.URL.Path == "/api/connections") {
				token = "Bearer " + r.URL.Query().Get("token")
			}
			trustedDesktop = subtle.ConstantTimeCompare([]byte(token), []byte("Bearer "+s.token)) == 1
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") ||
			r.URL.Path == "/api/auth/status" ||
			r.URL.Path == "/api/auth/initialize" ||
			r.URL.Path == "/api/auth/login" ||
			r.URL.Path == "/api/auth/logout" ||
			(r.URL.Path == "/api/auth/biometric-unlock" && (s.token == "" || trustedDesktop)) {
			mux.ServeHTTP(w, r)
			return
		}
		if s.auth != nil {
			initialized, unlocked := s.auth.Status()
			if !initialized {
				http.Error(w, "initialization required", http.StatusPreconditionRequired)
				return
			}
			if !unlocked {
				http.Error(w, "configuration is locked", http.StatusLocked)
				return
			}
			if !trustedDesktop {
				if !s.requestAuthenticated(r) {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
			}
		} else if s.token != "" && !trustedDesktop {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Body != nil && strings.HasPrefix(r.URL.Path, "/api/") {
			var maxBytes int64 = 2 << 20
			switch r.URL.Path {
			case "/api/backup", "/api/restore":
				maxBytes = 16 << 20
			case "/api/subscription/import":
				maxBytes = 4 << 20
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		mux.ServeHTTP(w, r)
	})
	allowedOrigins := []string{}
	if s.cfg != nil {
		allowedOrigins = s.cfg.Server.AllowedOrigins
	}
	return corsMiddleware(auth, allowedOrigins)
}

func safeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return fmt.Errorf("unsupported redirect scheme")
			}
			return nil
		},
	}
}

// Start binds the HTTP server and emits desktop/android IPC discovery metadata if configured.
func (s *Server) Start(addr string) error {
	if addr == "" && s.cfg != nil {
		addr = fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)
	}
	server := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	s.httpMu.Lock()
	s.httpServer = server
	s.httpMu.Unlock()

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if s.desktop {
		payload := map[string]string{
			"url":   "http://" + listener.Addr().String() + "/api",
			"token": s.token,
			"mode":  s.mode,
		}
		if s.ipcPath != "" {
			if raw, marshalErr := json.Marshal(payload); marshalErr == nil {
				_ = fileutil.WritePrivate(s.ipcPath, raw)
			}
		}
		_ = json.NewEncoder(os.Stdout).Encode(payload)
	}
	return server.Serve(listener)
}

// SetDesktopToken enables bearer token authentication for local IPC modes.
func (s *Server) SetDesktopToken(token string) {
	s.token = token
	s.desktop = true
	if s.mode == "" {
		s.mode = authservice.ModeDesktop
	}
}

// SetMode records the backend runtime mode ("web", "desktop", or "android").
func (s *Server) SetMode(mode string) {
	s.mode = mode
	if mode == authservice.ModeDesktop || mode == authservice.ModeAndroid {
		s.desktop = true
	}
}

// SetIPCPath sets the private runtime IPC metadata file written after binding.
func (s *Server) SetIPCPath(path string) { s.ipcPath = path }

// Shutdown gracefully stops HTTP serving and terminates managed proxy cores.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.webRoot != nil {
		defer s.webRoot.Close()
	}
	s.httpMu.Lock()
	server := s.httpServer
	s.httpMu.Unlock()

	var httpErr error
	if server != nil {
		httpErr = server.Shutdown(ctx)
	}
	if s.orch != nil {
		if err := s.orch.Close(); err != nil && httpErr == nil {
			httpErr = err
		}
	}
	return httpErr
}
