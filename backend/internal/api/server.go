// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
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
	auth                  *authservice.Manager
	web                   http.Handler
	webRoot               *os.Root
	stateMu               sync.RWMutex
	listenerHealth        string
	httpMu                sync.Mutex
	httpServer            *http.Server
	wantRunning           bool
	lastHealth            time.Time
	coreMu                sync.Mutex
	lastCoreCheck         time.Time
	token                 string
	desktop               bool
	mode                  string
	ipcPath               string
	settingsPath          string
	singBoxBinary         string
	xrayBinary            string
	protectPath           string
	ownerPath             string
	tunStack              string
	opMu                  sync.Mutex
	orchMu                sync.Mutex
	orch                  *orchestrator.Orchestrator
	androidVPNMu          sync.Mutex
	androidVPN            *androidvpn.Manager
	androidTun            *androidvpn.TunBridge
	androidTrafficMu      sync.Mutex
	androidTrafficPID     int
	androidTrafficTracker *trafficSplitTracker
	connHubMu             sync.Mutex
	connHub               *connectionsHub
	ledgerMu              sync.Mutex
	trafficLedger         *trafficLedger
	activeNodeID          string
	activeGroupID         string
	activeProfileID       string
	tunEnabled            bool
	systemProxyWanted     bool
	cachedRoutingMode     string
	allowLANFetch         atomic.Bool
	ksMu                  sync.RWMutex
	intendedActiveTag     string
	killSwitchTripped     bool
	killSwitchFailures    int
	killSwitchReason      string
	lastKillSwitchCheck   time.Time
	ruleSetSyncMu         sync.Mutex
	lastRuleSetCheck      time.Time
	autoSyncedRuleSets    atomic.Bool
	failMu                sync.Mutex
	nodeFailTimes         map[string][]time.Time
	nodeFastProbeAt       map[string]time.Time
	subBackoffMu          sync.Mutex
	subBackoff            map[string]subRetryState
	bioMu                 sync.Mutex
	bioHMACKey            []byte
	bioChallenges         map[string]time.Time
	pm                    *process.Manager
	store                 *storage.Store
	stats                 *stats.Client
	cfg                   *appconfig.Config
}

type subRetryState struct {
	failures    int
	nextRetryAt time.Time
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
		subBackoff:      map[string]subRetryState{},
		bioChallenges:   map[string]time.Time{},
	}
	if rawHex := strings.TrimSpace(os.Getenv("PRISMRAY_BIOMETRIC_HMAC_KEY")); rawHex != "" {
		// Immediately scrub the process-private HMAC secret from the environment so child
		// sing-box / xray processes can never inherit it via os.Environ().
		_ = os.Unsetenv("PRISMRAY_BIOMETRIC_HMAC_KEY")
		if decoded, err := hex.DecodeString(rawHex); err == nil && len(decoded) >= 32 {
			s.bioHMACKey = decoded
		}
	}
	if store != nil {
		var allowLAN bool
		if found, err := store.GetSetting(securityAllowLANFetchSettingKey, &allowLAN); err == nil && found {
			s.allowLANFetch.Store(allowLAN)
		}
		var activeProf string
		if found, err := store.GetSetting(activeProfileSettingKey, &activeProf); err == nil && found && strings.TrimSpace(activeProf) != "" {
			s.activeProfileID = strings.TrimSpace(activeProf)
		} else {
			s.activeProfileID = defaultProfileID
		}
	} else {
		s.activeProfileID = defaultProfileID
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
			var tunStack string
			if found, err := store.GetSetting("runtime.tun_stack", &tunStack); err == nil && found {
				switch strings.ToLower(strings.TrimSpace(tunStack)) {
				case "system", "gvisor", "mixed":
					s.tunStack = strings.ToLower(strings.TrimSpace(tunStack))
				}
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

// SetBiometricHMACKey configures the process-private HMAC secret shared with the Tauri parent
// for verifying Desktop OS biometric authentication challenges.
func (s *Server) SetBiometricHMACKey(key []byte) {
	s.bioMu.Lock()
	defer s.bioMu.Unlock()
	if len(key) == 0 {
		s.bioHMACKey = nil
		return
	}
	s.bioHMACKey = append([]byte(nil), key...)
}

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
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Backup-Passphrase")
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
	mux.HandleFunc("POST /api/backup/export", s.handleBackupExport)
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
	mux.HandleFunc("GET /api/vpn/android/telemetry", s.handleAndroidVPNTelemetry)
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
	mux.HandleFunc("POST /api/diagnostics/dns", s.handleDiagnosticsDNS)

	// Routing, profiles, .srs rulesets & legacy preferences bridge
	mux.HandleFunc("GET /api/routing", s.handleRouting)
	mux.HandleFunc("PUT /api/routing", s.handleRouting)
	mux.HandleFunc("POST /api/routing/simulate", s.handleRoutingSimulate)
	mux.HandleFunc("GET /api/profiles", s.handleProfiles)
	mux.HandleFunc("POST /api/profiles", s.handleProfiles)
	mux.HandleFunc("PUT /api/profiles/{id}", s.handleProfileItem)
	mux.HandleFunc("DELETE /api/profiles/{id}", s.handleProfileItem)
	mux.HandleFunc("POST /api/profiles/{id}/activate", s.handleActivateProfile)
	mux.HandleFunc("GET /api/tailscale", s.handleTailscale)
	mux.HandleFunc("PUT /api/tailscale", s.handleTailscale)
	mux.HandleFunc("POST /api/tailscale/reset-state", s.handleTailscaleResetState)
	mux.HandleFunc("POST /api/tailscale/exit-node", s.handleTailscaleExitNode)
	mux.HandleFunc("POST /api/tailscale/ping", s.handleTailscalePing)
	mux.HandleFunc("POST /api/tailscale/logout", s.handleTailscaleLogout)
	mux.HandleFunc("GET /api/tailscale/taildrop/inbox", s.handleTaildropInbox)
	mux.HandleFunc("POST /api/tailscale/taildrop/send", s.handleTaildropSend)
	mux.HandleFunc("GET /api/tailscale/taildrop/file/{name}", s.handleTaildropFile)
	mux.HandleFunc("DELETE /api/tailscale/taildrop/file/{name}", s.handleTaildropFile)
	mux.HandleFunc("GET /api/rulesets", s.handleRuleSets)
	mux.HandleFunc("POST /api/rulesets", s.handleRuleSets)
	mux.HandleFunc("DELETE /api/rulesets/{id}", s.handleDeleteRuleSet)
	mux.HandleFunc("POST /api/rulesets/sync", s.handleSyncRuleSets)
	mux.HandleFunc("POST /api/rulesets/restore-builtins", s.handleRestoreBuiltinRuleSets)
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
	mux.HandleFunc("GET /api/traffic/history", s.handleTrafficHistory)
	mux.HandleFunc("DELETE /api/traffic/history", s.handleTrafficHistory)
	mux.HandleFunc("GET /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections", s.handleConnections)
	mux.HandleFunc("DELETE /api/connections/{id}", s.handleConnections)

	// Config endpoints
	mux.HandleFunc("POST /api/config/apply", s.handleApplyConfig)
	mux.HandleFunc("GET /api/config/server", s.handleGetServerConfig)
	mux.HandleFunc("GET /api/config/compiled", s.handleCompiledConfig)

	// Nodes, groups, and latency probes
	mux.HandleFunc("GET /api/nodes", s.handleListNodes)
	mux.HandleFunc("POST /api/nodes", s.handleAddNode)
	mux.HandleFunc("PATCH /api/nodes/batch", s.handleBatchNodes)
	mux.HandleFunc("POST /api/nodes/batch", s.handleBatchNodes)
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
	mux.HandleFunc("POST /api/subscriptions/refresh-all", s.handleRefreshAllSubscriptions)
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

	// Authentication & security policy
	mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	mux.HandleFunc("POST /api/auth/initialize", s.handleAuthInitialize)
	mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	mux.HandleFunc("POST /api/auth/lock", s.handleAuthLock)
	mux.HandleFunc("POST /api/auth/password-lock", s.handlePasswordLock)
	mux.HandleFunc("POST /api/auth/biometric", s.handleBiometricConfig)
	mux.HandleFunc("POST /api/auth/biometric-challenge", s.handleBiometricChallenge)
	mux.HandleFunc("POST /api/auth/biometric-unlock", s.handleBiometricUnlock)
	mux.HandleFunc("PUT /api/auth/sudo-cache", s.handleSudoCache)
	mux.HandleFunc("DELETE /api/auth/sudo-cache", s.handleSudoCache)
	mux.HandleFunc("GET /api/security/policy", s.handleSecurityPolicy)
	mux.HandleFunc("PUT /api/security/policy", s.handleSecurityPolicy)

	auth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		trustedDesktop := false
		if s.token != "" {
			token := r.Header.Get("Authorization")
			if token == "" && (r.URL.Path == "/api/logs" || r.URL.Path == "/api/traffic" || r.URL.Path == "/api/connections") {
				token = "Bearer " + r.URL.Query().Get("token")
			}
			trustedDesktop = subtle.ConstantTimeCompare([]byte(token), []byte("Bearer "+s.token)) == 1
		}
		isLocalIPCMode := s.token != ""
		isPublicAuthRoute := r.URL.Path == "/api/auth/status" ||
			((r.URL.Path == "/api/auth/initialize" ||
				r.URL.Path == "/api/auth/login" ||
				r.URL.Path == "/api/auth/logout" ||
				r.URL.Path == "/api/auth/biometric-challenge" ||
				r.URL.Path == "/api/auth/biometric-unlock") && (!isLocalIPCMode || trustedDesktop))
		if !strings.HasPrefix(r.URL.Path, "/api/") || isPublicAuthRoute {
			if r.Body != nil && strings.HasPrefix(r.URL.Path, "/api/auth/") {
				// Bound unauthenticated/pre-unlock auth request bodies strictly to 64 KiB.
				r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
			}
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
			case "/api/tailscale/taildrop/send":
				maxBytes = 512 << 20
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

const securityAllowLANFetchSettingKey = "security.allow_lan_subscription_fetch"

var (
	safeHTTPAllowLoopbackForTest atomic.Bool
	errSSRFBlocked               = errors.New("blocked SSRF target")
	cgnatPrefix                  = netip.MustParsePrefix("100.64.0.0/10")
	thisNetPrefix                = netip.MustParsePrefix("0.0.0.0/8")
	ulaPrefix                    = netip.MustParsePrefix("fc00::/7")
	fakeIPv4Prefix               = netip.MustParsePrefix("198.18.0.0/15")
	fakeIPv6Prefix               = netip.MustParsePrefix("fc00::/18")
)

type runtimeStateSnapshot struct {
	activeNodeID      string
	activeGroupID     string
	tunEnabled        bool
	tunStack          string
	wantRunning       bool
	systemProxyWanted bool
	listenerHealth    string
	routingMode       string
}

func (s *Server) runtimeState() runtimeStateSnapshot {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return runtimeStateSnapshot{
		activeNodeID:      s.activeNodeID,
		activeGroupID:     s.activeGroupID,
		tunEnabled:        s.tunEnabled,
		tunStack:          s.tunStack,
		wantRunning:       s.wantRunning,
		systemProxyWanted: s.systemProxyWanted,
		listenerHealth:    s.listenerHealth,
		routingMode:       s.cachedRoutingMode,
	}
}

func (s *Server) setActiveNodeID(id string) {
	s.stateMu.Lock()
	s.activeNodeID = id
	s.stateMu.Unlock()
}

func (s *Server) setActiveGroupID(id string) {
	s.stateMu.Lock()
	s.activeGroupID = id
	s.stateMu.Unlock()
}

func (s *Server) setActiveTarget(nodeID, groupID string) {
	s.stateMu.Lock()
	s.activeNodeID = nodeID
	s.activeGroupID = groupID
	s.stateMu.Unlock()
}

func (s *Server) setTunEnabledState(enabled bool) {
	s.stateMu.Lock()
	s.tunEnabled = enabled
	s.stateMu.Unlock()
}

func (s *Server) setTunStackState(stack string) {
	s.stateMu.Lock()
	s.tunStack = stack
	s.stateMu.Unlock()
}

func (s *Server) setWantRunningState(want bool) {
	s.stateMu.Lock()
	s.wantRunning = want
	s.stateMu.Unlock()
}

func (s *Server) setSystemProxyWantedState(want bool) {
	s.stateMu.Lock()
	s.systemProxyWanted = want
	s.stateMu.Unlock()
}

func (s *Server) setListenerHealthState(msg string) {
	s.stateMu.Lock()
	s.listenerHealth = msg
	s.stateMu.Unlock()
}

func (s *Server) setCachedRoutingMode(mode string) {
	s.stateMu.Lock()
	s.cachedRoutingMode = strings.ToLower(strings.TrimSpace(mode))
	s.stateMu.Unlock()
}

func (s *Server) allowLANSubscriptionFetch() bool {
	return s.allowLANFetch.Load()
}

func (s *Server) handleSecurityPolicy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{
			"allow_lan_subscription_fetch": s.allowLANSubscriptionFetch(),
		})
	case http.MethodPut:
		var req struct {
			AllowLANSubscriptionFetch bool `json:"allow_lan_subscription_fetch"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if s.store != nil {
			if err := s.store.PutSetting(securityAllowLANFetchSettingKey, req.AllowLANSubscriptionFetch); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		s.allowLANFetch.Store(req.AllowLANSubscriptionFetch)
		writeJSON(w, http.StatusOK, map[string]any{
			"allow_lan_subscription_fetch": req.AllowLANSubscriptionFetch,
		})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func isBlockedSSRFIpWithPolicy(addr netip.Addr, allowPrivateLAN bool) bool {
	addr = addr.Unmap()
	if addr.IsLoopback() {
		return !safeHTTPAllowLoopbackForTest.Load()
	}
	// Always block link-local (including cloud metadata 169.254.169.254 / fe80::/10),
	// 0.0.0.0/8 ("this" network, treated as loopback by Linux kernels), multicast, and unspecified addresses.
	if addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		thisNetPrefix.Contains(addr) {
		return true
	}
	if !allowPrivateLAN {
		if addr.IsPrivate() || cgnatPrefix.Contains(addr) || ulaPrefix.Contains(addr) {
			return true
		}
	}
	return false
}

func isBlockedSSRFIp(addr netip.Addr) bool {
	return isBlockedSSRFIpWithPolicy(addr, false)
}

func isBlockedSSRFHost(host string, allowPrivateLAN bool) bool {
	h := strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if h == "" {
		return true
	}
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return !safeHTTPAllowLoopbackForTest.Load()
	}
	// Always block cloud metadata hosts even if allowPrivateLAN is enabled.
	if h == "metadata.google.internal" || h == "metadata.goog" || h == "instance-data" || h == "metadata" {
		return true
	}
	if !allowPrivateLAN {
		if !strings.Contains(h, ".") ||
			strings.HasSuffix(h, ".local") ||
			strings.HasSuffix(h, ".internal") ||
			strings.HasSuffix(h, ".lan") ||
			strings.HasSuffix(h, ".home.arpa") ||
			strings.HasSuffix(h, ".ts.net") {
			return true
		}
	}
	return false
}

func validateFetchTargetURL(ctx context.Context, rawURL string, allowPrivateLAN bool) error {
	u, err := url.ParseRequestURI(strings.TrimSpace(rawURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.TrimSpace(u.Hostname()) == "" {
		return fmt.Errorf("%w: invalid http(s) target url", errSSRFBlocked)
	}
	host := strings.TrimSpace(u.Hostname())
	if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
		if isBlockedSSRFIpWithPolicy(ip, allowPrivateLAN) {
			return fmt.Errorf("%w: address %s", errSSRFBlocked, ip.Unmap().String())
		}
		return nil
	}
	if isBlockedSSRFHost(host, allowPrivateLAN) {
		return fmt.Errorf("%w: forbidden host %s", errSSRFBlocked, host)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(lookupCtx, "ip", host)
	if err != nil {
		// Allow proxied fallback only for public-looking external FQDNs when local DNS fails,
		// while internal/metadata/IP targets have already been rejected above.
		return nil
	}
	for _, ip := range ips {
		uip := ip.Unmap()
		if fakeIPv4Prefix.Contains(uip) || fakeIPv6Prefix.Contains(uip) {
			// Skip TUN-synthesized FakeIP answers for already host-validated external domains;
			// direct dialing still re-checks actual resolved/connected IPs in safeSSRFDialContextWithPolicy.
			continue
		}
		if isBlockedSSRFIpWithPolicy(uip, allowPrivateLAN) {
			return fmt.Errorf("%w: resolved address %s for host %s", errSSRFBlocked, uip.String(), host)
		}
	}
	return nil
}

func safeSSRFDialContextWithPolicy(dialer *net.Dialer, allowPrivateLAN bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if ip, parseErr := netip.ParseAddr(host); parseErr == nil {
			if isBlockedSSRFIpWithPolicy(ip, allowPrivateLAN) {
				return nil, fmt.Errorf("%w: address %s", errSSRFBlocked, ip.Unmap().String())
			}
			return dialer.DialContext(ctx, network, addr)
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("no IP addresses resolved for %s", host)
		}
		var allowed []netip.Addr
		for _, ip := range ips {
			if isBlockedSSRFIpWithPolicy(ip, allowPrivateLAN) {
				return nil, fmt.Errorf("%w: resolved address %s for host %s", errSSRFBlocked, ip.Unmap().String(), host)
			}
			allowed = append(allowed, ip)
		}
		var lastErr error
		for _, ip := range allowed {
			conn, dErr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
			if dErr == nil {
				return conn, nil
			}
			lastErr = dErr
		}
		return nil, lastErr
	}
}

func safeSSRFDialContext(dialer *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return safeSSRFDialContextWithPolicy(dialer, false)
}

func safeHTTPClientWithPolicy(timeout time.Duration, allowPrivateLAN bool) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = safeSSRFDialContextWithPolicy(dialer, allowPrivateLAN)
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			if req.URL == nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
				return fmt.Errorf("unsupported redirect scheme")
			}
			return validateFetchTargetURL(req.Context(), req.URL.String(), allowPrivateLAN)
		},
	}
}

func safeHTTPClient(timeout time.Duration) *http.Client {
	return safeHTTPClientWithPolicy(timeout, false)
}

type ssrfGuardTransport struct {
	base            *http.Transport
	allowPrivateLAN bool
}

func (t *ssrfGuardTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("%w: missing request url", errSSRFBlocked)
	}
	if err := validateFetchTargetURL(req.Context(), req.URL.String(), t.allowPrivateLAN); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(req)
}

func (t *ssrfGuardTransport) CloseIdleConnections() {
	if t.base != nil {
		t.base.CloseIdleConnections()
	}
}

func safeProxyHTTPClientWithPolicy(timeout time.Duration, proxyPort int, allowPrivateLAN bool) *http.Client {
	client := safeHTTPClientWithPolicy(timeout, allowPrivateLAN)
	if proxyPort > 0 {
		if proxyURL, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", proxyPort)); err == nil {
			tr := http.DefaultTransport.(*http.Transport).Clone()
			tr.Proxy = http.ProxyURL(proxyURL)
			client.Transport = &ssrfGuardTransport{base: tr, allowPrivateLAN: allowPrivateLAN}
		}
	}
	return client
}

func closeClientIdleConnections(c *http.Client) {
	if c == nil || c.Transport == nil {
		return
	}
	if closer, ok := c.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (s *Server) safeHTTPClient(timeout time.Duration) *http.Client {
	return safeHTTPClientWithPolicy(timeout, s.allowLANSubscriptionFetch())
}

func (s *Server) safeProxyHTTPClient(timeout time.Duration, proxyPort int) *http.Client {
	return safeProxyHTTPClientWithPolicy(timeout, proxyPort, s.allowLANSubscriptionFetch())
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

func (s *Server) isVaultLocked() bool {
	if s.auth == nil {
		return false
	}
	initialized, unlocked := s.auth.Status()
	return !initialized || !unlocked
}

func (s *Server) stopHubAndFlushLedger() {
	s.connHubMu.Lock()
	hub := s.connHub
	s.connHubMu.Unlock()
	if hub != nil {
		hub.Stop()
	}
	s.ledgerMu.Lock()
	ledger := s.trafficLedger
	s.ledgerMu.Unlock()
	if ledger != nil {
		_ = ledger.Flush()
	}
}

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
	s.stopHubAndFlushLedger()
	s.orchMu.Lock()
	orch := s.orch
	s.orchMu.Unlock()
	if orch != nil {
		if err := orch.Close(); err != nil && httpErr == nil {
			httpErr = err
		}
	}
	return httpErr
}
