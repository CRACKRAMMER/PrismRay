// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func TestGroupManualPinAutoRevertAndLoadBalanceReject(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	// One reachable TCP listener, one closed port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	_ = s.store.Add(&config.Node{ID: "n-ok", Name: "OK", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: openPort, Security: "none"})
	_ = s.store.Add(&config.Node{ID: "n-bad", Name: "BAD", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: closedPort, Security: "none"})

	for _, body := range []string{
		`{"id":"g-lb","name":"LB","strategy":"loadbalance","node_ids":["n-ok","n-bad"]}`,
		`{"id":"g-url","name":"URLTest","strategy":"urltest","node_ids":["n-ok","n-bad"]}`,
		`{"id":"g-fail","name":"Failover","strategy":"failover","node_ids":["n-ok","n-bad"]}`,
	} {
		if w := request(s, http.MethodPost, "/api/groups", body); w.Code != http.StatusOK {
			t.Fatalf("create group failed: %d %s", w.Code, w.Body.String())
		}
	}

	// 1. Loadbalance rejects manual selection with 400.
	if w := request(s, http.MethodPut, "/api/groups/g-lb/select", `{"node_id":"n-ok"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when manually selecting loadbalance node, got %d %s", w.Code, w.Body.String())
	}

	// 2. Manual selection on urltest/failover sets manual_pin=true.
	wPin := request(s, http.MethodPut, "/api/groups/g-url/select", `{"node_id":"n-bad"}`)
	if wPin.Code != http.StatusOK {
		t.Fatalf("pin g-url failed: %d %s", wPin.Code, wPin.Body.String())
	}
	var pinResp struct {
		GroupID   string `json:"group_id"`
		NodeID    string `json:"node_id"`
		ManualPin bool   `json:"manual_pin"`
	}
	_ = json.Unmarshal(wPin.Body.Bytes(), &pinResp)
	if !pinResp.ManualPin || pinResp.NodeID != "n-bad" {
		t.Fatalf("expected manual_pin=true node_id=n-bad, got %+v", pinResp)
	}

	// 3. Explicit restore to auto mode via auto=true / empty node_id.
	wAuto := request(s, http.MethodPut, "/api/groups/g-url/select", `{"node_id":"","auto":true}`)
	if wAuto.Code != http.StatusOK {
		t.Fatalf("restore auto g-url failed: %d %s", wAuto.Code, wAuto.Body.String())
	}
	_ = json.Unmarshal(wAuto.Body.Bytes(), &pinResp)
	if pinResp.ManualPin || pinResp.NodeID != "" {
		t.Fatalf("expected manual_pin=false node_id='', got %+v", pinResp)
	}

	// 4. Pin g-url to unreachable n-bad, then probe: must auto-revert to auto mode!
	if w := request(s, http.MethodPut, "/api/groups/g-url/select", `{"node_id":"n-bad"}`); w.Code != http.StatusOK {
		t.Fatalf("re-pin g-url failed: %d", w.Code)
	}
	hs := HealthSettings{URL: defaultProbeURL, IntervalSeconds: 120, ToleranceMS: 50, HighLatencyMS: 800, PriorityRule: "latency_first", Failover: true}
	revertedGrp, _, switched, err := s.probeAndReorderGroup(context.Background(), "g-url", "ping", "", hs, false)
	if err != nil {
		t.Fatalf("probeAndReorderGroup(g-url) failed: %v", err)
	}
	if !switched || revertedGrp.ManualPin || revertedGrp.SelectedNodeID != "" {
		t.Fatalf("expected pinned unreachable node in g-url to auto-revert, switched=%v group=%+v", switched, revertedGrp)
	}

	// 5. Pin g-fail to reachable n-ok, then probe: must stay manually pinned when healthy & under HighLatencyMS.
	if w := request(s, http.MethodPut, "/api/groups/g-fail/select", `{"node_id":"n-ok"}`); w.Code != http.StatusOK {
		t.Fatalf("pin g-fail failed: %d", w.Code)
	}
	keptGrp, _, switched, err := s.probeAndReorderGroup(context.Background(), "g-fail", "ping", "", hs, false)
	if err != nil {
		t.Fatalf("probeAndReorderGroup(g-fail) failed: %v", err)
	}
	if switched || !keptGrp.ManualPin || keptGrp.SelectedNodeID != "n-ok" {
		t.Fatalf("expected healthy pinned node in g-fail to stay pinned, switched=%v group=%+v", switched, keptGrp)
	}
}

func TestHealthSettingsHighLatencyThreshold(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	// Default high_latency_ms is 800.
	wGet := request(s, http.MethodGet, "/api/health-settings", "")
	if wGet.Code != http.StatusOK {
		t.Fatalf("GET /api/health-settings failed: %d", wGet.Code)
	}
	var hs HealthSettings
	_ = json.Unmarshal(wGet.Body.Bytes(), &hs)
	if hs.HighLatencyMS != 800 {
		t.Fatalf("expected default high_latency_ms=800, got %d", hs.HighLatencyMS)
	}

	// Lower bound clamp (50 -> 100).
	wLow := request(s, http.MethodPut, "/api/health-settings", `{"url":"https://www.gstatic.com/generate_204","interval_seconds":120,"high_latency_ms":50}`)
	if wLow.Code != http.StatusOK {
		t.Fatalf("PUT low high_latency_ms failed: %d %s", wLow.Code, wLow.Body.String())
	}
	_ = json.Unmarshal(wLow.Body.Bytes(), &hs)
	if hs.HighLatencyMS != 100 {
		t.Fatalf("expected high_latency_ms clamped to 100, got %d", hs.HighLatencyMS)
	}

	// Upper bound clamp (50000 -> 10000).
	wHigh := request(s, http.MethodPut, "/api/health-settings", `{"url":"https://www.gstatic.com/generate_204","interval_seconds":120,"high_latency_ms":50000}`)
	if wHigh.Code != http.StatusOK {
		t.Fatalf("PUT high high_latency_ms failed: %d %s", wHigh.Code, wHigh.Body.String())
	}
	_ = json.Unmarshal(wHigh.Body.Bytes(), &hs)
	if hs.HighLatencyMS != 10000 {
		t.Fatalf("expected high_latency_ms clamped to 10000, got %d", hs.HighLatencyMS)
	}

	// Custom value persistence (550).
	wCustom := request(s, http.MethodPut, "/api/health-settings", `{"url":"https://www.gstatic.com/generate_204","interval_seconds":120,"high_latency_ms":550}`)
	if wCustom.Code != http.StatusOK {
		t.Fatalf("PUT custom high_latency_ms failed: %d %s", wCustom.Code, wCustom.Body.String())
	}
	wGet2 := request(s, http.MethodGet, "/api/health-settings", "")
	_ = json.Unmarshal(wGet2.Body.Bytes(), &hs)
	if hs.HighLatencyMS != 550 {
		t.Fatalf("expected persisted high_latency_ms=550, got %d", hs.HighLatencyMS)
	}
}

func TestLegacyRemoteDNSOneTimeMigration(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	// Seed untouched legacy routing profile with dns.google.
	legacy := ruleset.DefaultRoutingProfile()
	legacy.RemoteDNS = "https://dns.google/dns-query"
	if err := s.saveRoutingProfile(legacy); err != nil {
		t.Fatal(err)
	}

	// First GET /api/routing must migrate once to 1.1.1.1.
	w1 := request(s, http.MethodGet, "/api/routing", "")
	if w1.Code != http.StatusOK {
		t.Fatalf("GET /api/routing failed: %d", w1.Code)
	}
	var got ruleset.RoutingProfile
	_ = json.Unmarshal(w1.Body.Bytes(), &got)
	if got.RemoteDNS != "https://1.1.1.1/dns-query" {
		t.Fatalf("expected legacy dns.google migrated to 1.1.1.1, got %q", got.RemoteDNS)
	}

	// Explicit user change back to dns.google must NOT be overwritten on subsequent reads.
	got.RemoteDNS = "https://dns.google/dns-query"
	raw, _ := json.Marshal(got)
	wPut := request(s, http.MethodPut, "/api/routing", string(raw))
	if wPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/routing failed: %d %s", wPut.Code, wPut.Body.String())
	}
	w2 := request(s, http.MethodGet, "/api/routing", "")
	var got2 ruleset.RoutingProfile
	_ = json.Unmarshal(w2.Body.Bytes(), &got2)
	if got2.RemoteDNS != "https://dns.google/dns-query" {
		t.Fatalf("expected subsequent user edit to dns.google preserved, got %q", got2.RemoteDNS)
	}
}

func TestReactiveOutboundFailureRevertsManualPin(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	// Local HTTP 204 test server so probe fails fast on closed SOCKS port without touching external internet.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts.Close()
	_ = s.store.PutSetting("health.settings", HealthSettings{
		URL:             ts.URL,
		IntervalSeconds: 120,
		ToleranceMS:     50,
		HighLatencyMS:   800,
		PriorityRule:    "latency_first",
		Failover:        true,
	})

	closedLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := closedLn.Addr().(*net.TCPAddr).Port
	_ = closedLn.Close()

	_ = s.store.Add(&config.Node{ID: "n-closed", Name: "Closed", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: closedPort, Security: "none", Latency: 120})
	_ = s.store.Add(&config.Node{ID: "n-backup", Name: "Backup", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: closedPort + 1, Security: "none"})
	_ = s.store.SaveGroup(storage.Group{
		ID:             "g-react",
		Name:           "Reactive Failover",
		Strategy:       "failover",
		NodeIDs:        []string{"n-closed", "n-backup"},
		SelectedNodeID: "n-closed",
		ManualPin:      true,
	})

	// 1st failure alone must NOT trigger probe/revert.
	s.handleOutboundFailureEvent("node-n-closed", "dial tcp: i/o timeout")
	if n := s.store.Get("n-closed"); n == nil || n.Latency != 120 {
		t.Fatalf("single failure should not probe or mark node unavailable yet, got %+v", n)
	}

	// 2nd failure within 10s triggers single-node fast probe, marks latency -1, and reverts manual_pin!
	s.handleOutboundFailureEvent("node-n-closed", "dial tcp: i/o timeout")
	n := s.store.Get("n-closed")
	if n == nil || n.Latency != -1 {
		t.Fatalf("expected confirmed failing node marked -1 (red), got %+v", n)
	}
	groups, err := s.store.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	var found *storage.Group
	for i := range groups {
		if groups[i].ID == "g-react" {
			found = &groups[i]
			break
		}
	}
	if found == nil || found.ManualPin || found.SelectedNodeID != "" {
		t.Fatalf("expected reactive failure handler to revert g-react manual_pin to auto, got %+v", found)
	}
}

func TestUpdateNodePreservesSubscriptionOriginSubID(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	if err := s.store.Add(&config.Node{
		ID:       "sub-node-1",
		SubID:    "sub-origin-1",
		Name:     "Airport HK",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.10",
		Port:     1080,
		Security: "none",
		Tags:     []string{"HK"},
	}); err != nil {
		t.Fatal(err)
	}

	// Attempt to clear sub_id while updating custom tags: sub_id MUST remain locked to "sub-origin-1".
	w := request(s, http.MethodPut, "/api/nodes/sub-node-1", `{
		"id":"sub-node-1",
		"sub_id":"",
		"name":"Airport HK",
		"protocol":"socks",
		"address":"198.51.100.10",
		"port":1080,
		"security":"none",
		"tags":["Streaming","Gaming"]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /api/nodes/sub-node-1 failed: %d %s", w.Code, w.Body.String())
	}
	updated := s.store.Get("sub-node-1")
	if updated == nil || updated.SubID != "sub-origin-1" {
		t.Fatalf("expected subscription node sub_id preserved as sub-origin-1, got %+v", updated)
	}
	if len(updated.Tags) != 2 || updated.Tags[0] != "Streaming" || updated.Tags[1] != "Gaming" {
		t.Fatalf("expected custom tags updated freely, got %+v", updated.Tags)
	}
}

func TestAndroidPowerMigrationTelemetryAndEngineSelection(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)
	s.mode = authservice.ModeAndroid

	// Seed legacy default info log level -> one-time Android migration upgrades it to warn.
	legacy := ruleset.DefaultRoutingProfile()
	legacy.LogLevel = "info"
	if err := s.saveRoutingProfile(legacy); err != nil {
		t.Fatal(err)
	}

	got, err := s.routingProfile()
	if err != nil {
		t.Fatal(err)
	}
	if got.LogLevel != "warn" {
		t.Fatalf("expected Android one-time migration to lower default log_level to warn, got %q", got.LogLevel)
	}

	// Explicit user override back to debug must NOT be overwritten by migration.
	got.LogLevel = "debug"
	if err := s.saveRoutingProfile(got); err != nil {
		t.Fatal(err)
	}
	gotAgain, err := s.routingProfile()
	if err != nil {
		t.Fatal(err)
	}
	if gotAgain.LogLevel != "debug" {
		t.Fatalf("expected explicit log_level=debug preserved after migration, got %q", gotAgain.LogLevel)
	}

	// Lightweight Android telemetry endpoint responds cleanly even when stopped.
	if err := s.store.Add(&config.Node{
		ID:       "n-mob-1",
		Name:     "Tokyo Node",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.20",
		Port:     1080,
		Security: "none",
	}); err != nil {
		t.Fatal(err)
	}
	s.activeNodeID = "n-mob-1"
	telW := request(s, http.MethodGet, "/api/vpn/android/telemetry?include_traffic=0", "")
	if telW.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/android/telemetry failed: %d %s", telW.Code, telW.Body.String())
	}
	var tel map[string]any
	if err := json.Unmarshal(telW.Body.Bytes(), &tel); err != nil {
		t.Fatal(err)
	}
	if tel["active_label"] != "Tokyo Node" {
		t.Fatalf("expected telemetry active_label=Tokyo Node, got %+v", tel)
	}

	// Status reports hev by default when no per-app custom package_name rules are active.
	stW := request(s, http.MethodGet, "/api/vpn/android/status", "")
	if stW.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/android/status failed: %d %s", stW.Code, stW.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(stW.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["tun_engine"] != "hev" {
		t.Fatalf("expected default Android tun_engine=hev, got %+v", st)
	}
}

func TestAndroidPassiveKillSwitchSkipsHealthyPolling(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)
	s.mode = authservice.ModeAndroid
	s.wantRunning = true

	// Simulate healthy running state with no failures and Kill Switch untripped:
	// maintainKillSwitch must not advance lastKillSwitchCheck (0 active polling wakeups).
	if err := s.store.Add(&config.Node{
		ID:       "n-ks-mob",
		Name:     "KS Mobile",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.30",
		Port:     1080,
		Security: "none",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.reconcileRuntime(context.Background(), "n-ks-mob", "", false); err != nil {
		t.Fatalf("reconcileRuntime failed: %v", err)
	}
	defer func() { _ = s.ensureOrchestrator().Stop() }()

	s.ksMu.Lock()
	s.lastKillSwitchCheck = s.lastKillSwitchCheck.Truncate(0)
	s.ksMu.Unlock()

	s.maintainKillSwitch(context.Background())

	s.ksMu.RLock()
	checked := !s.lastKillSwitchCheck.IsZero()
	s.ksMu.RUnlock()
	if checked {
		t.Fatal("expected Android passive Kill Switch to skip active periodic probing while running and healthy")
	}
}

func TestAndroidNoHeadlessRestoreAndRealTUNState(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)
	s.mode = authservice.ModeAndroid

	if err := s.store.Add(&config.Node{
		ID:       "n-cold-1",
		Name:     "Cold Boot Node",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.41",
		Port:     1080,
		Security: "none",
	}); err != nil {
		t.Fatal(err)
	}
	s.activeNodeID = "n-cold-1"
	s.persistWantRunning(true)

	// Android cold start must never silently launch bare sing-box without ProxyVpnService.
	s.RestoreLastSession(context.Background())
	if s.ensureOrchestrator().Status().Running {
		t.Fatal("expected RestoreLastSession to skip headless sing-box start on Android")
	}

	stW := request(s, http.MethodGet, "/api/process/status", "")
	if stW.Code != http.StatusOK {
		t.Fatalf("GET /api/process/status failed: %d", stW.Code)
	}
	var statusBody map[string]any
	if err := json.Unmarshal(stW.Body.Bytes(), &statusBody); err != nil {
		t.Fatal(err)
	}
	if statusBody["running"] != false || statusBody["android_vpn_active"] != false {
		t.Fatalf("expected stopped Android status with android_vpn_active=false, got %+v", statusBody)
	}

	// POST /api/vpn/android/stop must persist runtime.want_running=false in SQLite.
	stopW := request(s, http.MethodPost, "/api/vpn/android/stop", "{}")
	if stopW.Code != http.StatusOK {
		t.Fatalf("POST /api/vpn/android/stop failed: %d %s", stopW.Code, stopW.Body.String())
	}
	var wantPersisted bool
	if found, err := s.store.GetSetting("runtime.want_running", &wantPersisted); err != nil || !found || wantPersisted {
		t.Fatalf("expected runtime.want_running persisted as false after android VPN stop, found=%v val=%v err=%v", found, wantPersisted, err)
	}

	// Desktop GET /api/tun must report enabled=false when core is stopped even if TUN preference is saved.
	s.mode = authservice.ModeDesktop
	s.tunEnabled = true
	tunW := request(s, http.MethodGet, "/api/tun", "")
	if tunW.Code != http.StatusOK {
		t.Fatalf("GET /api/tun failed: %d %s", tunW.Code, tunW.Body.String())
	}
	var tunBody map[string]any
	if err := json.Unmarshal(tunW.Body.Bytes(), &tunBody); err != nil {
		t.Fatal(err)
	}
	if tunBody["enabled"] != false || tunBody["running"] != false || tunBody["preferred"] != true {
		t.Fatalf("expected stopped PC GET /api/tun to return enabled=false running=false preferred=true, got %+v", tunBody)
	}
}

func TestCustomRulesMasterToggleSimulateAndGooglePlayExempt(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	profile := ruleset.DefaultRoutingProfile()
	profile.BypassCN = true
	profile.BlockAds = true
	profile.CustomRulesEnabled = ruleset.BoolPtr(false)
	profile.CustomRules = []ruleset.RoutingRule{
		{
			ID:           "r-custom-direct",
			Name:         "Custom Direct",
			Enabled:      true,
			DomainSuffix: []string{"custom-rule.example"},
			Outbound:     "direct",
		},
	}
	body, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	putW := request(s, http.MethodPut, "/api/routing", string(body))
	if putW.Code != http.StatusOK {
		t.Fatalf("PUT /api/routing failed: %d %s", putW.Code, putW.Body.String())
	}

	// With master switch OFF, custom rule is skipped -> falls back to route.final (proxy).
	simOff := request(s, http.MethodPost, "/api/routing/simulate", `{"domain":"custom-rule.example"}`)
	if simOff.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/simulate failed: %d", simOff.Code)
	}
	var resOff ruleset.SimulationResult
	if err := json.Unmarshal(simOff.Body.Bytes(), &resOff); err != nil {
		t.Fatal(err)
	}
	if resOff.Outbound != "proxy" || resOff.MatchedRule != "route.final" {
		t.Fatalf("expected custom rule skipped when custom_rules_enabled=false, got %+v", resOff)
	}

	// Google Play CN/CDN domains (e.g. services.googleapis.cn) must NOT be diverted to CN direct.
	simPlay := request(s, http.MethodPost, "/api/routing/simulate", `{"domain":"services.googleapis.cn"}`)
	if simPlay.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/simulate(play) failed: %d", simPlay.Code)
	}
	var resPlay ruleset.SimulationResult
	if err := json.Unmarshal(simPlay.Body.Bytes(), &resPlay); err != nil {
		t.Fatal(err)
	}
	if resPlay.Outbound != "proxy" {
		t.Fatalf("expected Google Play services.googleapis.cn to route via proxy despite BypassCN, got %+v", resPlay)
	}

	// Turn master switch back ON -> custom rule takes effect again without losing its config.
	profile.CustomRulesEnabled = ruleset.BoolPtr(true)
	bodyOn, _ := json.Marshal(profile)
	putOn := request(s, http.MethodPut, "/api/routing", string(bodyOn))
	if putOn.Code != http.StatusOK {
		t.Fatalf("PUT /api/routing (enable) failed: %d %s", putOn.Code, putOn.Body.String())
	}
	simOn := request(s, http.MethodPost, "/api/routing/simulate", `{"domain":"custom-rule.example"}`)
	var resOn ruleset.SimulationResult
	if err := json.Unmarshal(simOn.Body.Bytes(), &resOn); err != nil {
		t.Fatal(err)
	}
	if resOn.Outbound != "direct" || resOn.MatchedRule != "Custom Direct" {
		t.Fatalf("expected custom rule active when custom_rules_enabled=true, got %+v", resOn)
	}
}

func TestFailoverTriggerAndAutoFailoverConflictElimination(t *testing.T) {
	s := testServer(t, "")
	_ = s.store.Add(&config.Node{ID: "n1", Name: "N1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none"})
	_ = s.store.Add(&config.Node{ID: "n2", Name: "N2", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Security: "none"})

	// Creating a failover group with auto_failover=false must clear auto_failover (no conflict)
	// and persist failover_trigger + high_latency_ms.
	w := request(s, http.MethodPost, "/api/groups", `{
		"id":"g-fo",
		"name":"FO",
		"strategy":"failover",
		"auto_failover":false,
		"failover_trigger":"unavailable_only",
		"high_latency_ms":550,
		"node_ids":["n1","n2"]
	}`)
	if w.Code != http.StatusOK {
		t.Fatalf("create failover group failed: %d %s", w.Code, w.Body.String())
	}
	var created storage.Group
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.AutoFailover != nil {
		t.Fatalf("expected failover group auto_failover cleared to nil, got %v", *created.AutoFailover)
	}
	if created.FailoverTrigger != "unavailable_only" || created.HighLatencyMS != 550 {
		t.Fatalf("expected failover_trigger=unavailable_only high_latency_ms=550, got %+v", created)
	}

	// Reject invalid failover_trigger values.
	bad := request(s, http.MethodPost, "/api/groups", `{
		"id":"g-bad",
		"name":"Bad",
		"strategy":"failover",
		"failover_trigger":"invalid_mode",
		"node_ids":["n1"]
	}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid failover_trigger, got %d %s", bad.Code, bad.Body.String())
	}
}

func TestTailscaleAPIConfigMaskingAndValidation(t *testing.T) {
	s := testServer(t, "")
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err := s.store.Unlock(key); err != nil {
		t.Fatalf("unlock test store: %v", err)
	}

	put := request(s, http.MethodPut, "/api/tailscale", `{
		"enabled": true,
		"control_url": "https://headscale.example.com",
		"auth_key": "tskey-auth-super-secret",
		"hostname": "prismray-lab",
		"accept_routes": true,
		"magic_dns": true,
		"extra_subnets": ["10.99.0.0/16"],
		"extra_domains": ["corp.internal"]
	}`)
	if put.Code != http.StatusOK {
		t.Fatalf("PUT /api/tailscale failed: %d %s", put.Code, put.Body.String())
	}
	if strings.Contains(put.Body.String(), "tskey-auth-super-secret") {
		t.Fatalf("auth_key leaked in PUT /api/tailscale response: %s", put.Body.String())
	}

	get := request(s, http.MethodGet, "/api/tailscale", "")
	if get.Code != http.StatusOK {
		t.Fatalf("GET /api/tailscale failed: %d %s", get.Code, get.Body.String())
	}
	if strings.Contains(get.Body.String(), "tskey-auth-super-secret") {
		t.Fatalf("auth_key leaked in GET /api/tailscale response: %s", get.Body.String())
	}
	var resp struct {
		Config ruleset.TailscaleConfig `json:"config"`
	}
	if err := json.Unmarshal(get.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !resp.Config.HasAuthKey || resp.Config.AuthKey != "" || resp.Config.ControlURL != "https://headscale.example.com" {
		t.Fatalf("unexpected masked tailscale config: %+v", resp.Config)
	}

	// Updating without resending auth_key preserves stored secret.
	putKeep := request(s, http.MethodPut, "/api/tailscale", `{
		"enabled": true,
		"control_url": "https://headscale.example.com",
		"hostname": "prismray-lab-2",
		"accept_routes": true,
		"magic_dns": true
	}`)
	if putKeep.Code != http.StatusOK {
		t.Fatalf("PUT /api/tailscale (keep key) failed: %d %s", putKeep.Code, putKeep.Body.String())
	}
	internalCfg, err := s.tailscaleConfig(true)
	if err != nil || internalCfg.AuthKey != "tskey-auth-super-secret" {
		t.Fatalf("expected stored auth_key preserved, got %q (%v)", internalCfg.AuthKey, err)
	}

	// Invalid CIDR / non-HTTP control_url rejected with 400.
	bad := request(s, http.MethodPut, "/api/tailscale", `{"enabled":true,"control_url":"file:///etc/passwd"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-http control_url, got %d %s", bad.Code, bad.Body.String())
	}
	badCIDR := request(s, http.MethodPut, "/api/tailscale", `{"enabled":true,"extra_subnets":["not-a-cidr"]}`)
	if badCIDR.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid CIDR, got %d %s", badCIDR.Code, badCIDR.Body.String())
	}

	// Reset state endpoint succeeds cleanly.
	reset := request(s, http.MethodPost, "/api/tailscale/reset-state", "")
	if reset.Code != http.StatusOK {
		t.Fatalf("POST /api/tailscale/reset-state failed: %d %s", reset.Code, reset.Body.String())
	}
}

func TestSecurityHardeningSettingsBackupAuthAndSSRF(t *testing.T) {
	s := testServer(t, "")
	s.SetSettingsPath(filepath.Join(t.TempDir(), "settings.json"))
	origSingBox := s.cfg.SingBox.BinaryPath
	origOrigins := append([]string(nil), s.cfg.Server.AllowedOrigins...)

	// 1. PUT /api/settings must reject non-loopback host AND must NOT allow modifying sing_box.binary_path or server.allowed_origins.
	badHost := request(s, http.MethodPut, "/api/settings", `{
		"server":{"host":"0.0.0.0","port":9999}
	}`)
	if badHost.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for non-loopback API host, got %d %s", badHost.Code, badHost.Body.String())
	}
	putSettings := request(s, http.MethodPut, "/api/settings", `{
		"server":{"host":"127.0.0.1","port":2178,"allowed_origins":["https://evil.example"]},
		"sing_box":{"binary_path":"/tmp/pwn.sh","config_path":"/etc/passwd","mixed_port":10809,"clash_api_port":9091,"rule_set_dir":"/tmp/evil","auto_update":false},
		"xray":{"binary_path":"/tmp/pwn-xray","config_path":"/etc/shadow","socks_port":10811,"stats_port":10086,"auto_update":false},
		"storage":{"database_path":"/tmp/evil.db"}
	}`)
	if putSettings.Code != http.StatusOK {
		t.Fatalf("PUT /api/settings failed: %d %s", putSettings.Code, putSettings.Body.String())
	}
	var settingsResp struct {
		Saved struct {
			Server struct {
				AllowedOrigins []string `json:"allowed_origins"`
			} `json:"server"`
			SingBox struct {
				BinaryPath string `json:"binary_path"`
				MixedPort  int    `json:"mixed_port"`
			} `json:"sing_box"`
		} `json:"saved"`
	}
	if err := json.Unmarshal(putSettings.Body.Bytes(), &settingsResp); err != nil {
		t.Fatal(err)
	}
	if settingsResp.Saved.SingBox.BinaryPath != origSingBox {
		t.Fatalf("PUT /api/settings mutated sing_box.binary_path to %q", settingsResp.Saved.SingBox.BinaryPath)
	}
	if len(settingsResp.Saved.Server.AllowedOrigins) != len(origOrigins) || (len(origOrigins) > 0 && settingsResp.Saved.Server.AllowedOrigins[0] != origOrigins[0]) {
		t.Fatalf("PUT /api/settings mutated allowed_origins to %v", settingsResp.Saved.Server.AllowedOrigins)
	}
	if settingsResp.Saved.SingBox.MixedPort != 10809 {
		t.Fatalf("expected safe port update applied in saved config, got %d", settingsResp.Saved.SingBox.MixedPort)
	}

	// 2. POST /api/backup?mode=merge must reject path traversal in rule_sets.local_path and non-HTTP URLs.
	badMergePath := request(s, http.MethodPost, "/api/backup?mode=merge", `{
		"rule_sets":[{"id":"evil","tag":"evil","source_type":"local","local_path":"../../etc/passwd","enabled":true}]
	}`)
	if badMergePath.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for merge backup path traversal, got %d %s", badMergePath.Code, badMergePath.Body.String())
	}
	badMergeURL := request(s, http.MethodPost, "/api/backup?mode=merge", `{
		"rule_sets":[{"id":"evil2","tag":"evil2","source_type":"remote","url":"file:///etc/passwd","enabled":true}]
	}`)
	if badMergeURL.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for merge backup non-http url, got %d %s", badMergeURL.Code, badMergeURL.Body.String())
	}

	// 3. safeHTTPClient SSRF dialer blocks loopback and cloud metadata IPs.
	client := safeHTTPClient(2 * 1e9)
	for _, target := range []string{"http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/"} {
		resp, err := client.Get(target)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err == nil || !strings.Contains(err.Error(), "blocked") {
			t.Fatalf("expected safeHTTPClient to block SSRF target %s, got err=%v", target, err)
		}
	}

	// 4. Desktop biometric HMAC challenge-response + auth body size limit.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "auth-sec.db")
	st, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kr := keyring.New(keyring.Options{FallbackPath: filepath.Join(dir, ".device.key"), DisableOSKeyring: true})
	am, err := authservice.NewWithOptions(st, authservice.Options{Mode: authservice.ModeDesktop, Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	if err := am.EnablePasswordLock("StrongPass123!"); err != nil {
		t.Fatal(err)
	}
	if err := am.SetBiometricUnlock(true, "StrongPass123!"); err != nil {
		t.Fatal(err)
	}
	am.Lock()

	secSrv := NewServer(nil, st, nil, nil)
	secSrv.SetAuth(am)
	secSrv.SetMode(authservice.ModeDesktop)
	secSrv.SetDesktopToken("desktop-test-token")
	hmacKey := make([]byte, 32)
	for i := range hmacKey {
		hmacKey[i] = byte(i + 7)
	}
	secSrv.SetBiometricHMACKey(hmacKey)
	handler := secSrv.Handler()

	// Oversized (>64KiB) /api/auth/login body must be rejected before Argon2.
	hugeBody := `{"password":"` + strings.Repeat("a", 70*1024) + `"}`
	reqHuge := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(hugeBody))
	reqHuge.Header.Set("Authorization", "Bearer desktop-test-token")
	recHuge := httptest.NewRecorder()
	handler.ServeHTTP(recHuge, reqHuge)
	if recHuge.Code != http.StatusBadRequest && recHuge.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected oversized auth body rejected, got %d", recHuge.Code)
	}

	// Empty biometric unlock without challenge/signature must return 401.
	reqBadBio := httptest.NewRequest(http.MethodPost, "/api/auth/biometric-unlock", strings.NewReader(`{}`))
	reqBadBio.Header.Set("Authorization", "Bearer desktop-test-token")
	recBadBio := httptest.NewRecorder()
	handler.ServeHTTP(recBadBio, reqBadBio)
	if recBadBio.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for biometric unlock without HMAC proof, got %d %s", recBadBio.Code, recBadBio.Body.String())
	}

	// Valid challenge -> HMAC signature unlocks once, and replay fails with 401.
	reqChal := httptest.NewRequest(http.MethodPost, "/api/auth/biometric-challenge", nil)
	reqChal.Header.Set("Authorization", "Bearer desktop-test-token")
	recChal := httptest.NewRecorder()
	handler.ServeHTTP(recChal, reqChal)
	if recChal.Code != http.StatusOK {
		t.Fatalf("biometric challenge failed: %d %s", recChal.Code, recChal.Body.String())
	}
	var chalResp struct {
		Challenge string `json:"challenge"`
	}
	if err := json.Unmarshal(recChal.Body.Bytes(), &chalResp); err != nil || chalResp.Challenge == "" {
		t.Fatalf("invalid challenge payload: %s", recChal.Body.String())
	}
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(chalResp.Challenge))
	sig := hex.EncodeToString(mac.Sum(nil))

	proofPayload, _ := json.Marshal(map[string]string{"challenge": chalResp.Challenge, "signature": sig})
	reqGoodBio := httptest.NewRequest(http.MethodPost, "/api/auth/biometric-unlock", strings.NewReader(string(proofPayload)))
	reqGoodBio.Header.Set("Authorization", "Bearer desktop-test-token")
	recGoodBio := httptest.NewRecorder()
	handler.ServeHTTP(recGoodBio, reqGoodBio)
	if recGoodBio.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid HMAC biometric proof, got %d %s", recGoodBio.Code, recGoodBio.Body.String())
	}
	// Replay of the same one-time challenge must fail.
	am.Lock()
	reqReplay := httptest.NewRequest(http.MethodPost, "/api/auth/biometric-unlock", strings.NewReader(string(proofPayload)))
	reqReplay.Header.Set("Authorization", "Bearer desktop-test-token")
	recReplay := httptest.NewRecorder()
	handler.ServeHTTP(recReplay, reqReplay)
	if recReplay.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on biometric challenge replay, got %d", recReplay.Code)
	}

	// 5. Android hardware biometric KEK endpoint must not create plaintext .device.key.biometric.
	andDir := t.TempDir()
	andStore, err := storage.NewStore(filepath.Join(andDir, "android.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer andStore.Close()
	andKR := keyring.New(keyring.Options{FallbackPath: filepath.Join(andDir, ".device.key"), DisableOSKeyring: true})
	andAuth, err := authservice.NewWithOptions(andStore, authservice.Options{Mode: authservice.ModeAndroid, Keyring: andKR})
	if err != nil {
		t.Fatal(err)
	}
	if err := andAuth.EnablePasswordLock("AndroidPass123!"); err != nil {
		t.Fatal(err)
	}
	andSrv := NewServer(nil, andStore, nil, nil)
	andSrv.SetAuth(andAuth)
	andSrv.SetMode(authservice.ModeAndroid)
	andSrv.SetDesktopToken("android-test-token")
	andHandler := andSrv.Handler()

	reqEnroll := httptest.NewRequest(http.MethodPost, "/api/auth/biometric", strings.NewReader(`{"enabled":true,"current_password":"AndroidPass123!","hardware_wrap":true}`))
	reqEnroll.Header.Set("Authorization", "Bearer android-test-token")
	recEnroll := httptest.NewRecorder()
	andHandler.ServeHTTP(recEnroll, reqEnroll)
	if recEnroll.Code != http.StatusOK {
		t.Fatalf("android biometric enroll failed: %d %s", recEnroll.Code, recEnroll.Body.String())
	}
	var enrollResp struct {
		BiometricKEK string `json:"biometric_kek"`
		HardwareWrap bool   `json:"hardware_wrap"`
	}
	if err := json.Unmarshal(recEnroll.Body.Bytes(), &enrollResp); err != nil || !enrollResp.HardwareWrap || enrollResp.BiometricKEK == "" {
		t.Fatalf("expected hardware_wrap + biometric_kek, got %s", recEnroll.Body.String())
	}
	if _, statErr := os.Stat(filepath.Join(andDir, ".device.key.biometric")); !os.IsNotExist(statErr) {
		t.Fatalf("legacy plaintext .device.key.biometric must not exist on Android")
	}

	andAuth.Lock()
	reqAndBad := httptest.NewRequest(http.MethodPost, "/api/auth/biometric-unlock", strings.NewReader(`{}`))
	reqAndBad.Header.Set("Authorization", "Bearer android-test-token")
	recAndBad := httptest.NewRecorder()
	andHandler.ServeHTTP(recAndBad, reqAndBad)
	if recAndBad.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when Android biometric_kek omitted, got %d", recAndBad.Code)
	}

	goodKEKBody, _ := json.Marshal(map[string]string{"biometric_kek": enrollResp.BiometricKEK})
	reqAndGood := httptest.NewRequest(http.MethodPost, "/api/auth/biometric-unlock", strings.NewReader(string(goodKEKBody)))
	reqAndGood.Header.Set("Authorization", "Bearer android-test-token")
	recAndGood := httptest.NewRecorder()
	andHandler.ServeHTTP(recAndGood, reqAndGood)
	if recAndGood.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid Android biometric_kek unlock, got %d %s", recAndGood.Code, recAndGood.Body.String())
	}
}
