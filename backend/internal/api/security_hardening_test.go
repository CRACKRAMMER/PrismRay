// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	sbcfg "github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func TestDesktopIPCAuthBlocksUnauthenticatedLoginAndInitialize(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "prismray.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	authMgr, err := authservice.NewWithOptions(store, authservice.Options{
		Mode: authservice.ModeDesktop,
		Keyring: keyring.New(keyring.Options{
			FallbackPath:     filepath.Join(dir, ".device.key"),
			DisableOSKeyring: true,
		}),
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	// Passwordless desktop startup: initialized=true, unlocked=true, passwordLocked=false.
	if init, unlocked := authMgr.Status(); !init || !unlocked || authMgr.PasswordLocked() {
		t.Fatalf("unexpected desktop default auth state: init=%v unlocked=%v locked=%v", init, unlocked, authMgr.PasswordLocked())
	}

	cfg := appconfig.Default()
	cfg.SetRuntimeDir(dir)
	srv := NewServer(nil, store, nil, cfg)
	srv.SetAuth(authMgr)
	srv.SetDesktopToken("secret-ipc-token-12345")
	handler := srv.Handler()

	// 1. Unauthenticated POST /api/auth/login must be rejected with 401 and must NOT mint a session cookie.
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/auth/login returned %d, want 401", rec.Code)
	}
	if len(rec.Result().Cookies()) > 0 {
		t.Fatalf("unauthenticated /api/auth/login unexpectedly issued cookies: %v", rec.Result().Cookies())
	}

	// 2. Unauthenticated POST /api/auth/initialize must NOT hijack/lock the vault.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/initialize", strings.NewReader(`{"password":"attacker-password-123"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /api/auth/initialize returned %d, want 401", rec.Code)
	}
	if authMgr.PasswordLocked() {
		t.Fatalf("unauthenticated /api/auth/initialize unexpectedly enabled password lock")
	}

	// 3. Direct untrusted Manager.Initialize call on already-ready passwordless vault must also fail.
	if err := authMgr.Initialize("attacker-password-123", "", false); err == nil {
		t.Fatalf("expected untrusted Manager.Initialize on ready vault to fail")
	}

	// 4. POST /api/auth/lock in passwordless mode must return 400 and keep vault unlocked.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/lock", nil)
	req.Header.Set("Authorization", "Bearer secret-ipc-token-12345")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("/api/auth/lock in passwordless mode returned %d, want 400", rec.Code)
	}
	if _, unlocked := authMgr.Status(); !unlocked {
		t.Fatalf("passwordless vault was unexpectedly locked")
	}

	// 5. Trusted IPC caller CAN login and enable password lock, revoking prior sessions.
	req = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer secret-ipc-token-12345")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("trusted /api/auth/login returned %d, want 200", rec.Code)
	}
	oldCookies := rec.Result().Cookies()
	if len(oldCookies) == 0 {
		t.Fatalf("expected session cookie on trusted login")
	}
	oldToken := oldCookies[0].Value

	if err := authMgr.EnablePasswordLock("strong-password-123"); err != nil {
		t.Fatalf("EnablePasswordLock: %v", err)
	}
	if authMgr.Valid(oldToken) {
		t.Fatalf("expected old session token to be revoked after EnablePasswordLock")
	}
}

func TestSSRFPolicyAndToggle(t *testing.T) {
	// Default strict policy: blocks loopback, link-local/metadata, RFC1918 private, and Tailscale CGNAT.
	blockedDefault := []string{
		"127.0.0.1",
		"::1",
		"169.254.169.254",
		"fe80::1",
		"10.0.0.5",
		"172.16.1.10",
		"192.168.1.100",
		"100.64.0.10",
		"fd7a:115c:a1e0::1",
	}
	for _, raw := range blockedDefault {
		ip := netip.MustParseAddr(raw)
		if !isBlockedSSRFIpWithPolicy(ip, false) {
			t.Fatalf("expected %s to be blocked under default strict SSRF policy", raw)
		}
	}
	if isBlockedSSRFIpWithPolicy(netip.MustParseAddr("1.1.1.1"), false) {
		t.Fatalf("public IP 1.1.1.1 should not be blocked")
	}

	// When allowPrivateLAN=true, RFC1918 & Tailscale CGNAT are permitted,
	// while loopback and cloud metadata 169.254.169.254 remain strictly blocked.
	for _, allowedLAN := range []string{"192.168.1.50", "10.0.0.2", "100.64.10.20", "fd7a:115c:a1e0::1"} {
		ip := netip.MustParseAddr(allowedLAN)
		if isBlockedSSRFIpWithPolicy(ip, true) {
			t.Fatalf("expected %s to be allowed when allowPrivateLAN=true", allowedLAN)
		}
	}
	for _, alwaysBlocked := range []string{"127.0.0.1", "::1", "169.254.169.254", "fe80::1"} {
		ip := netip.MustParseAddr(alwaysBlocked)
		if !isBlockedSSRFIpWithPolicy(ip, true) {
			t.Fatalf("expected %s to ALWAYS be blocked even when allowPrivateLAN=true", alwaysBlocked)
		}
	}

	// validateFetchTargetURL returns errSSRFBlocked so callers never fall back to local proxy.
	if err := validateFetchTargetURL(context.Background(), "http://169.254.169.254/latest/meta-data/", true); !errors.Is(err, errSSRFBlocked) {
		t.Fatalf("expected errSSRFBlocked for metadata IP, got %v", err)
	}
	if err := validateFetchTargetURL(context.Background(), "http://192.168.1.10/sub", false); !errors.Is(err, errSSRFBlocked) {
		t.Fatalf("expected errSSRFBlocked for LAN IP by default, got %v", err)
	}
	if err := validateFetchTargetURL(context.Background(), "http://192.168.1.10/sub", true); err != nil {
		t.Fatalf("expected LAN IP allowed when policy enabled, got %v", err)
	}
}

func TestProductionCORSAndBiometricEnvScrub(t *testing.T) {
	t.Setenv("PRISMRAY_DEV_CORS", "")
	cfg := appconfig.Default()
	if slices.Contains(cfg.Server.AllowedOrigins, "http://127.0.0.1:1420") ||
		slices.Contains(cfg.Server.AllowedOrigins, "http://localhost:1420") {
		t.Fatalf("production CORS should not include :1420 dev origins, got %v", cfg.Server.AllowedOrigins)
	}

	t.Setenv("PRISMRAY_DEV_CORS", "1")
	devCfg := appconfig.Default()
	if !slices.Contains(devCfg.Server.AllowedOrigins, "http://127.0.0.1:1420") {
		t.Fatalf("expected dev CORS origin when PRISMRAY_DEV_CORS=1")
	}

	t.Setenv("PRISMRAY_BIOMETRIC_HMAC_KEY", strings.Repeat("ab", 32))
	_ = NewServer(nil, nil, nil, cfg)
	if got := os.Getenv("PRISMRAY_BIOMETRIC_HMAC_KEY"); got != "" {
		t.Fatalf("expected PRISMRAY_BIOMETRIC_HMAC_KEY to be scrubbed from environment, got %q", got)
	}
}

func TestDesktopTUNIPv6CaptureAndTailscaleBeforeDirect(t *testing.T) {
	routing := ruleset.DefaultRoutingProfile()
	routing.DomainStrategy = "prefer_ipv4"
	out, err := sbcfg.Compile(sbcfg.CompileInput{
		EnableTUN: true,
		Routing:   routing,
		Tailscale: &ruleset.TailscaleConfig{
			Enabled:  true,
			MagicDNS: true,
		},
	})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatalf("unmarshal compiled config: %v", err)
	}

	// Verify Desktop TUN always binds IPv6 ULA so auto_route captures ::/0 for 2000::/3 -> reject.
	inbounds, _ := doc["inbounds"].([]any)
	foundIPv6TUN := false
	for _, raw := range inbounds {
		m, _ := raw.(map[string]any)
		if m["tag"] == "tun-in" {
			addrs, _ := m["address"].([]any)
			for _, a := range addrs {
				if s, _ := a.(string); strings.Contains(s, ":") {
					foundIPv6TUN = true
				}
			}
		}
	}
	if !foundIPv6TUN {
		t.Fatalf("expected Desktop tun-in to bind IPv6 ULA even under prefer_ipv4")
	}

	// Verify Tailscale route rule precedes clash_mode=Direct rule.
	routeObj, _ := doc["route"].(map[string]any)
	rules, _ := routeObj["rules"].([]any)
	tsIdx, directIdx := -1, -1
	for idx, raw := range rules {
		m, _ := raw.(map[string]any)
		if m["outbound"] == ruleset.TailscaleEndpointTag && tsIdx < 0 {
			tsIdx = idx
		}
		if m["clash_mode"] == "Direct" && directIdx < 0 {
			directIdx = idx
		}
	}
	if tsIdx < 0 || directIdx < 0 || tsIdx > directIdx {
		t.Fatalf("expected Tailscale rule (%d) before clash_mode Direct (%d)", tsIdx, directIdx)
	}
}

func TestSecurityPolicyEndpointPersistence(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "prismray.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	cfg := appconfig.Default()
	cfg.SetRuntimeDir(dir)
	srv := NewServer(nil, store, nil, cfg)
	handler := srv.Handler()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/security/policy", bytes.NewBufferString(`{"allow_lan_subscription_fetch":true}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/security/policy returned %d: %s", rec.Code, rec.Body.String())
	}
	if !srv.allowLANSubscriptionFetch() {
		t.Fatalf("expected allowLANSubscriptionFetch() == true after PUT")
	}
}

func TestRound2SecurityAndBatchHardening(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "prismray.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	cfg := appconfig.Default()
	cfg.SetRuntimeDir(dir)
	cfg.SingBox.ClashAPISecret = "super-secret-clash-token"
	srv := NewServer(nil, store, nil, cfg)
	handler := srv.Handler()

	// 1. H1: isManagedSingBoxPath permits RuntimeDir & /usr/lib/prismray, rejects arbitrary /tmp binary.
	stagedBin := filepath.Join(dir, "sing-box")
	if !srv.isManagedSingBoxPath(stagedBin) {
		t.Fatalf("expected RuntimeDir binary %s to be managed", stagedBin)
	}
	if !srv.isManagedSingBoxPath("/usr/lib/prismray/sing-box") {
		t.Fatalf("expected /usr/lib/prismray/sing-box to be managed")
	}
	if srv.isManagedSingBoxPath("/tmp/untrusted-evil-sing-box") {
		t.Fatalf("expected arbitrary /tmp binary to be rejected")
	}

	// 2. M1: Cloud metadata & loopback hosts ALWAYS blocked even when allowPrivateLAN=true;
	// LAN / Tailscale hostnames blocked under default strict policy (allowPrivateLAN=false).
	for _, u := range []string{
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://169.254.169.254/latest/meta-data/",
		"http://localhost:8080/sub",
	} {
		if err := validateFetchTargetURL(context.Background(), u, true); !errors.Is(err, errSSRFBlocked) {
			t.Fatalf("expected %s to be always blocked with errSSRFBlocked, got %v", u, err)
		}
	}
	for _, u := range []string{
		"http://service.local/sub",
		"http://nas.ts.net/sub",
		"http://corp.internal/sub",
	} {
		if err := validateFetchTargetURL(context.Background(), u, false); !errors.Is(err, errSSRFBlocked) {
			t.Fatalf("expected %s to be blocked under default SSRF policy, got %v", u, err)
		}
	}

	// 3. M4: HTTP CONNECT CRLF injection rejected before dialing.
	if _, err := dialViaLocalHTTPProxy(context.Background(), &net.Dialer{}, 10808, "1.1.1.1:443\r\nX-Injected: 1"); err == nil {
		t.Fatalf("expected CRLF target in dialViaLocalHTTPProxy to fail")
	}

	// 4. M4: GET /api/settings redacts ClashAPISecret.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/settings", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/settings returned %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "super-secret-clash-token") {
		t.Fatalf("GET /api/settings leaked ClashAPISecret: %s", rec.Body.String())
	}

	// 5. F3: GET /api/config/compiled returns valid JSON with secrets redacted.
	n1 := &config.Node{
		ID:       "node-a",
		Name:     "Alpha",
		Protocol: config.ProtocolVLESS,
		Address:  "198.51.100.1",
		Port:     443,
		UUID:     "11111111-2222-3333-4444-555555555555",
		Password: "node-secret-password",
	}
	n2 := &config.Node{
		ID:       "node-b",
		Name:     "Beta",
		Protocol: config.ProtocolTrojan,
		Address:  "198.51.100.2",
		Port:     443,
		Password: "trojan-secret-password",
		Group:    "LegacyTag",
		Tags:     []string{"LegacyTag"},
	}
	if err := store.Add(n1); err != nil {
		t.Fatalf("add n1: %v", err)
	}
	if err := store.Add(n2); err != nil {
		t.Fatalf("add n2: %v", err)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/config/compiled", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config/compiled returned %d: %s", rec.Code, rec.Body.String())
	}
	var compiledResp struct {
		Redacted bool   `json:"redacted"`
		Config   string `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &compiledResp); err != nil {
		t.Fatalf("decode compiled config response: %v", err)
	}
	if !compiledResp.Redacted {
		t.Fatalf("expected redacted=true")
	}
	for _, secret := range []string{"super-secret-clash-token", "11111111-2222-3333-4444-555555555555", "trojan-secret-password"} {
		if strings.Contains(compiledResp.Config, secret) {
			t.Fatalf("compiled config leaked secret %q", secret)
		}
	}
	if !strings.Contains(compiledResp.Config, "***REDACTED***") {
		t.Fatalf("expected ***REDACTED*** marker in compiled config")
	}

	// 6. F2/M2: PATCH /api/nodes/batch supports tag rename (incl. legacy group) and batch delete.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/api/nodes/batch",
		strings.NewReader(`{"action":"update","ids":["node-b"],"remove_tag":"LegacyTag","add_tag":"RenamedTag"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH /api/nodes/batch update returned %d: %s", rec.Code, rec.Body.String())
	}
	updatedB := store.Get("node-b")
	if updatedB == nil || updatedB.Group != "RenamedTag" || !slices.Contains(updatedB.Tags, "RenamedTag") || slices.Contains(updatedB.Tags, "LegacyTag") {
		t.Fatalf("unexpected node-b after batch tag rename: %+v", updatedB)
	}
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPatch, "/api/nodes/batch",
		strings.NewReader(`{"action":"delete","ids":["node-a"]}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH /api/nodes/batch delete returned %d: %s", rec.Code, rec.Body.String())
	}
	if store.Get("node-a") != nil {
		t.Fatalf("expected node-a to be deleted by batch endpoint")
	}

	// 7. H4: Deterministic subscription node IDs survive head insertion & deletion.
	subNodesA := []*config.Node{
		{Name: "HK-1", Protocol: config.ProtocolVLESS, Address: "hk1.example.com", Port: 443, UUID: "aaaa"},
		{Name: "JP-1", Protocol: config.ProtocolVLESS, Address: "jp1.example.com", Port: 443, UUID: "bbbb"},
	}
	assignDeterministicSubscriptionNodeIDs("sub-1", subNodesA)
	hkIDBefore, jpIDBefore := subNodesA[0].ID, subNodesA[1].ID

	subNodesB := []*config.Node{
		{Name: "US-NewHead", Protocol: config.ProtocolVLESS, Address: "us0.example.com", Port: 443, UUID: "0000"},
		{Name: "HK-1", Protocol: config.ProtocolVLESS, Address: "hk1.example.com", Port: 443, UUID: "aaaa"},
		{Name: "JP-1", Protocol: config.ProtocolVLESS, Address: "jp1.example.com", Port: 443, UUID: "bbbb"},
	}
	assignDeterministicSubscriptionNodeIDs("sub-1", subNodesB)
	if subNodesB[1].ID != hkIDBefore || subNodesB[2].ID != jpIDBefore {
		t.Fatalf("subscription node IDs shifted on head insertion: before=(%s,%s) after=(%s,%s)",
			hkIDBefore, jpIDBefore, subNodesB[1].ID, subNodesB[2].ID)
	}

	// 8. M2: Subscription refresh exponential backoff (5m -> 15m -> 1h -> 6h) & reset on success.
	srv.recordSubscriptionRefreshResult("sub-1", errors.New("timeout 1"))
	if !srv.shouldSkipSubscriptionAutoUpdate("sub-1", time.Now()) {
		t.Fatalf("expected sub-1 to be backed off after 1st error")
	}
	srv.recordSubscriptionRefreshResult("sub-1", errors.New("timeout 2"))
	srv.recordSubscriptionRefreshResult("sub-1", errors.New("timeout 3"))
	srv.recordSubscriptionRefreshResult("sub-1", errors.New("timeout 4"))
	srv.subBackoffMu.Lock()
	st := srv.subBackoff["sub-1"]
	srv.subBackoffMu.Unlock()
	if st.failures != 4 || time.Until(st.nextRetryAt) < 5*time.Hour {
		t.Fatalf("expected 4th failure to schedule ~6h backoff, got %+v", st)
	}
	srv.recordSubscriptionRefreshResult("sub-1", nil)
	if srv.shouldSkipSubscriptionAutoUpdate("sub-1", time.Now()) {
		t.Fatalf("expected backoff cleared after successful refresh")
	}
}

func TestRound3APIHardeningRegressions(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "prismray.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	cfg := appconfig.Default()
	cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
	cfg.SingBox.MixedPort = 10808
	cfg.SingBox.ClashAPIPort = 9090
	cfg.SingBox.ClashAPISecret = "clash-secret"
	srv := NewServer(nil, store, nil, cfg)
	srv.SetMode(authservice.ModeDesktop)
	srv.SetDesktopToken("round3-tok")

	request := func(method, target string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer round3-tok")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		return w
	}

	// 1. Batch invalid action returns 400.
	if w := request(http.MethodPatch, "/api/nodes/batch", `{"action":"drop_db","ids":["x"]}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid batch action, got %d (%s)", w.Code, w.Body.String())
	}

	// 2. Xray node in handleCompiledConfig gets synthetic bridge port & redacts auth/cookie headers.
	xhttpNode := &config.Node{
		ID:       "xhttp-1",
		Name:     "XHTTP-Node",
		Protocol: config.ProtocolVLESS,
		Address:  "198.51.100.20",
		Port:     443,
		UUID:     "22222222-3333-4444-5555-666666666666",
		Network:  "xhttp",
		Host:     "cdn.example.com",
		Path:     "/xhttp",
	}
	wsHeaderNode := &config.Node{
		ID:        "ws-hdr",
		Name:      "WS-Header",
		Protocol:  config.ProtocolVLESS,
		Address:   "198.51.100.21",
		Port:      443,
		UUID:      "33333333-3333-4444-5555-666666666666",
		Network:   "ws",
		Host:      "ws.example.com",
		Path:      "/ws",
		WSHeaders: map[string]string{"Authorization": "Bearer secret-ws-token", "Cookie": "session=secret-cookie"},
	}
	if err := store.Add(xhttpNode); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(wsHeaderNode); err != nil {
		t.Fatal(err)
	}
	wConf := request(http.MethodGet, "/api/config/compiled", "")
	if wConf.Code != http.StatusOK {
		t.Fatalf("expected compiled config with xhttp node to succeed, got %d: %s", wConf.Code, wConf.Body.String())
	}
	if strings.Contains(wConf.Body.String(), "secret-ws-token") || strings.Contains(wConf.Body.String(), "secret-cookie") {
		t.Fatalf("compiled config leaked WS Authorization/Cookie header: %s", wConf.Body.String())
	}

	// 3. handleGroupSelect on inactive group never steals activeNodeID.
	if err := store.SaveGroup(storage.Group{ID: "g-inactive", Name: "Inactive", Strategy: "selector", NodeIDs: []string{"ws-hdr"}}); err != nil {
		t.Fatal(err)
	}
	srv.setActiveTarget("xhttp-1", "")
	if wSel := request(http.MethodPut, "/api/groups/g-inactive/select", `{"node_id":"ws-hdr"}`); wSel.Code != http.StatusOK {
		t.Fatalf("handleGroupSelect failed: %d (%s)", wSel.Code, wSel.Body.String())
	}
	if rs := srv.runtimeState(); rs.activeNodeID != "xhttp-1" || rs.activeGroupID != "" {
		t.Fatalf("inactive group selection hijacked active target: %+v", rs)
	}

	// 4. Partial backup restore without "groups" preserves surviving group memberships.
	if err := store.SaveGroup(storage.Group{ID: "g-keep", Name: "Keep", Strategy: "selector", SelectedNodeID: "xhttp-1", NodeIDs: []string{"xhttp-1", "ws-hdr"}}); err != nil {
		t.Fatal(err)
	}
	partialPayload, _ := json.Marshal(FullBackup{
		Version: 4,
		Nodes:   []*config.Node{xhttpNode},
	})
	if wBkp := request(http.MethodPost, "/api/backup?include=nodes", string(partialPayload)); wBkp.Code != http.StatusOK {
		t.Fatalf("partial backup restore failed: %d (%s)", wBkp.Code, wBkp.Body.String())
	}
	afterGroups, err := store.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	var keptGroup *storage.Group
	for i := range afterGroups {
		if afterGroups[i].ID == "g-keep" {
			keptGroup = &afterGroups[i]
		}
	}
	if keptGroup == nil || len(keptGroup.NodeIDs) != 1 || keptGroup.NodeIDs[0] != "xhttp-1" {
		t.Fatalf("expected surviving g-keep member [xhttp-1] preserved after node-only restore, got %+v", keptGroup)
	}

	// 5. /usr/lib/prismray-server/sing-box recognized as managed binary path.
	if !srv.isManagedSingBoxPath("/usr/lib/prismray-server/sing-box") {
		t.Fatalf("expected /usr/lib/prismray-server/sing-box to be allowed")
	}

	// 6. SSRF blocks 0.0.0.0/8 & fc00::/7 when allowPrivateLAN=false, and FakeIP host checks still hold.
	if !isBlockedSSRFIpWithPolicy(netip.MustParseAddr("0.1.2.3"), true) {
		t.Fatalf("expected 0.1.2.3 in 0.0.0.0/8 to always be blocked")
	}
	if !isBlockedSSRFIpWithPolicy(netip.MustParseAddr("fd12::1"), false) {
		t.Fatalf("expected ULA fd12::1 blocked under strict SSRF policy")
	}
	if err := validateFetchTargetURL(context.Background(), "http://[fc00::1]/sub", false); !errors.Is(err, errSSRFBlocked) {
		t.Fatalf("expected literal FakeIP-like fc00::1 URL blocked when allowPrivateLAN=false, got %v", err)
	}
	if err := validateFetchTargetURL(context.Background(), "http://internal-host.internal/sub", false); !errors.Is(err, errSSRFBlocked) {
		t.Fatalf("expected .internal host blocked with errSSRFBlocked, got %v", err)
	}

	// 7. Legacy subscription refresh preserves group_members & DetourID across ID migration.
	legacyRelay := &config.Node{ID: "manual-relay", Name: "Relay", Protocol: config.ProtocolSocks, Address: "198.51.100.99", Port: 1080}
	if err := store.Add(legacyRelay); err != nil {
		t.Fatal(err)
	}
	legacyNode := &config.Node{
		ID:       "subm-1",
		SubID:    "subm",
		Name:     "LegacySubNode",
		Protocol: config.ProtocolVLESS,
		Address:  "203.0.113.10",
		Port:     443,
		UUID:     "44444444-3333-4444-5555-666666666666",
		Network:  "tcp",
		Security: "none",
		DetourID: "manual-relay",
	}
	if err := store.Add(legacyNode); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveGroup(storage.Group{ID: "g-sub", Name: "SubGroup", Strategy: "selector", SelectedNodeID: "subm-1", NodeIDs: []string{"subm-1"}}); err != nil {
		t.Fatal(err)
	}
	feedBody := "vless://44444444-3333-4444-5555-666666666666@203.0.113.10:443?security=none#LegacySubNode\n"
	safeHTTPAllowLoopbackForTest.Store(true)
	defer safeHTTPAllowLoopbackForTest.Store(false)
	_ = store.PutSetting(securityAllowLANFetchSettingKey, true)
	srv.allowLANFetch.Store(true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(feedBody))
	}))
	defer ts.Close()
	subRec := Subscription{ID: "subm", Name: "SubM", URL: ts.URL}
	if err := store.SaveSubscription(subRec); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.refreshSubscriptionWithDiff(context.Background(), &subRec, false); err != nil {
		t.Fatalf("refreshSubscriptionWithDiff failed: %v", err)
	}
	migratedNodes := store.ListBySubscription("subm")
	if len(migratedNodes) != 1 || migratedNodes[0].DetourID != "manual-relay" {
		t.Fatalf("expected migrated subscription node to keep DetourID=manual-relay, got %+v", migratedNodes)
	}
	newID := migratedNodes[0].ID
	postGroups, _ := store.ListGroups()
	var subGrp *storage.Group
	for i := range postGroups {
		if postGroups[i].ID == "g-sub" {
			subGrp = &postGroups[i]
		}
	}
	if subGrp == nil || subGrp.SelectedNodeID != newID || len(subGrp.NodeIDs) != 1 || subGrp.NodeIDs[0] != newID {
		t.Fatalf("expected legacy group_members & SelectedNodeID migrated to %s, got %+v", newID, subGrp)
	}
}
