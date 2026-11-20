// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/autostart"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func TestRoutingProfileAndSimulatorAPI(t *testing.T) {
	s := testServer(t, "")

	w := request(s, http.MethodGet, "/api/routing", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/routing failed: %d", w.Code)
	}
	var profile ruleset.RoutingProfile
	if err := json.Unmarshal(w.Body.Bytes(), &profile); err != nil {
		t.Fatal(err)
	}
	profile.BlockAds = true
	profile.BypassCN = true
	profile.CustomRules = []ruleset.RoutingRule{
		{ID: "r1", Name: "Corporate", Enabled: true, DomainSuffix: []string{"corp.internal"}, Outbound: "direct"},
	}
	raw, _ := json.Marshal(profile)
	if w := request(s, http.MethodPut, "/api/routing", string(raw)); w.Code != http.StatusOK {
		t.Fatalf("PUT /api/routing failed: %d %s", w.Code, w.Body.String())
	}

	sim := request(s, http.MethodPost, "/api/routing/simulate", `{"domain":"git.corp.internal"}`)
	if sim.Code != http.StatusOK {
		t.Fatalf("POST /api/routing/simulate failed: %d", sim.Code)
	}
	var simRes ruleset.SimulationResult
	_ = json.Unmarshal(sim.Body.Bytes(), &simRes)
	if simRes.Outbound != "direct" {
		t.Fatalf("expected direct match for custom rule, got %+v", simRes)
	}

	rs := request(s, http.MethodGet, "/api/rulesets", "")
	if rs.Code != http.StatusOK {
		t.Fatalf("GET /api/rulesets failed: %d", rs.Code)
	}
}

func TestGroupsHotSwitchAndConnectionsAPI(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	for _, n := range []*config.Node{
		{ID: "n1", Name: "HK-1", Protocol: config.ProtocolVLESS, Address: "198.51.100.1", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Security: "tls", Sni: "a.example"},
		{ID: "n2", Name: "JP-2", Protocol: config.ProtocolTrojan, Address: "198.51.100.2", Port: 443, Password: "pw", Security: "tls", Sni: "b.example"},
	} {
		if err := s.store.Add(n); err != nil {
			t.Fatal(err)
		}
	}

	w := request(s, http.MethodPost, "/api/groups", `{"id":"auto-sel","name":"Auto Select","strategy":"selector","selected_node_id":"n1","node_ids":["n1","n2"]}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST /api/groups failed: %d %s", w.Code, w.Body.String())
	}

	c := request(s, http.MethodPost, "/api/process/connect", `{"group_id":"auto-sel"}`)
	if c.Code != http.StatusOK {
		t.Fatalf("connect group failed: %d %s", c.Code, c.Body.String())
	}

	sel := request(s, http.MethodPut, "/api/groups/auto-sel/select", `{"node_id":"n2"}`)
	if sel.Code != http.StatusOK {
		t.Fatalf("hot switch PUT /api/groups/auto-sel/select failed: %d %s", sel.Code, sel.Body.String())
	}

	groups, _ := s.store.ListGroups()
	if len(groups) != 1 || groups[0].SelectedNodeID != "n2" {
		t.Fatalf("expected persisted selected_node_id=n2, got %+v", groups)
	}

	conns := request(s, http.MethodGet, "/api/connections", "")
	if conns.Code != http.StatusOK {
		t.Fatalf("GET /api/connections failed: %d %s", conns.Code, conns.Body.String())
	}
}

func TestTUNPrivilegeAndFullBackupV4RoundTrip(t *testing.T) {
	s := testServer(t, "")
	priv := request(s, http.MethodGet, "/api/tun/privilege", "")
	if priv.Code != http.StatusOK {
		t.Fatalf("GET /api/tun/privilege failed: %d", priv.Code)
	}

	_ = s.store.Add(&config.Node{
		ID:            "hy2",
		Name:          "Hy2",
		Protocol:      config.ProtocolHysteria2,
		Address:       "198.51.100.3",
		Port:          443,
		Password:      "secret",
		AllowInsecure: true,
	})
	_ = s.store.SaveGroup(storage.Group{ID: "g1", Name: "G1", Strategy: "selector", NodeIDs: []string{"hy2"}, SelectedNodeID: "hy2"})
	_ = s.store.SaveSubscription(Subscription{ID: "s1", Name: "Sub", URL: "https://sub.example/list", ImportedCount: 1, Warnings: []string{}})
	_ = s.saveRoutingProfile(ruleset.RoutingProfile{Mode: "rule", BlockAds: true, BypassCN: true, BypassLAN: true})

	bak := request(s, http.MethodGet, "/api/backup", "")
	if bak.Code != http.StatusOK {
		t.Fatalf("GET /api/backup failed: %d", bak.Code)
	}
	var payload FullBackup
	if err := json.Unmarshal(bak.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != 4 || len(payload.Nodes) != 1 || len(payload.Groups) != 1 || len(payload.Subscriptions) != 1 || !payload.RoutingProfile.BlockAds {
		t.Fatalf("unexpected v4 backup payload: %+v", payload)
	}

	s2 := testServer(t, "")
	restore := request(s2, http.MethodPost, "/api/backup", bak.Body.String())
	if restore.Code != http.StatusOK {
		t.Fatalf("POST /api/backup restore failed: %d %s", restore.Code, restore.Body.String())
	}
	if len(s2.store.List()) != 1 {
		t.Fatalf("expected restored node in s2")
	}
	restoredProfile, err := s2.routingProfile()
	if err != nil || !restoredProfile.BlockAds {
		t.Fatalf("expected restored routing profile, got %+v (%v)", restoredProfile, err)
	}
}

func TestAndroidVPNRoutesLifecycle(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)
	_ = s.store.Add(&config.Node{
		ID:       "n1",
		Name:     "Android Edge",
		Protocol: config.ProtocolTrojan,
		Address:  "198.51.100.4",
		Port:     443,
		Password: "pw",
		Security: "tls",
		Sni:      "android.example",
	})

	start := request(s, http.MethodPost, "/api/vpn/android/start", `{"tun_fd":77,"per_app_mode":"whitelist","per_app_packages":["com.example.browser"],"active_node_id":"n1"}`)
	if start.Code != http.StatusOK {
		t.Fatalf("POST /api/vpn/android/start failed: %d %s", start.Code, start.Body.String())
	}
	var startBody map[string]any
	_ = json.Unmarshal(start.Body.Bytes(), &startBody)
	tunSock, _ := startBody["tun_socket_path"].(string)
	if !filepath.IsAbs(tunSock) {
		t.Fatalf("expected absolute tun_socket_path, got %q", tunSock)
	}
	if _, err := os.Stat(tunSock); err != nil {
		t.Fatalf("expected tun_socket_path to exist at %q: %v", tunSock, err)
	}
	status := request(s, http.MethodGet, "/api/vpn/android/status", "")
	if status.Code != http.StatusOK {
		t.Fatalf("GET /api/vpn/android/status failed: %d", status.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(status.Body.Bytes(), &body)
	if body["active"] != true || body["running"] != true || body["per_app_mode"] != "whitelist" {
		t.Fatalf("unexpected android vpn status: %v", body)
	}

	stop := request(s, http.MethodPost, "/api/vpn/android/stop", "")
	if stop.Code != http.StatusOK {
		t.Fatalf("POST /api/vpn/android/stop failed: %d", stop.Code)
	}
}

func TestMergeBackupPreservesExistingAndAcceptsStandaloneRouting(t *testing.T) {
	s := testServer(t, "")
	if err := s.store.Add(&config.Node{
		ID:       "existing-3p",
		Name:     "Existing 3P Node",
		Protocol: config.ProtocolSocks,
		Address:  "127.0.0.1",
		Port:     1080,
		Security: "none",
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.saveRoutingProfile(ruleset.RoutingProfile{
		Mode:      "rule",
		BlockAds:  true,
		BypassLAN: true,
		BypassCN:  true,
		CustomRules: []ruleset.RoutingRule{
			{ID: "user-old-rule", Name: "Old Rule", Enabled: true, Domains: []string{"old.example.com"}, Outbound: "direct"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	mergePayload := `{
		"version": 4,
		"nodes": [
			{
				"id": "us-gcp-vless",
				"name": "US GCP Node",
				"protocol": "vless",
				"address": "free.200107089.xyz",
				"port": 443,
				"uuid": "1a2e150a-fcfa-46ff-9526-166e7bca1b39",
				"flow": "xtls-rprx-vision",
				"security": "reality",
				"sni": "www.apple.com",
				"fingerprint": "chrome",
				"public_key": "9FC7JObgyM8O5pMX2woUqdcppsZjywwcDXnHpQwq3Eo",
				"short_id": "6baad067",
				"network": "tcp"
			}
		],
		"groups": [
			{
				"id": "us-gcp",
				"name": "US GCP",
				"strategy": "selector",
				"selected_node_id": "us-gcp-vless",
				"sort_order": 1,
				"node_ids": ["us-gcp-vless"]
			}
		],
		"routing_profile": {
			"mode": "rule",
			"block_ads": false,
			"custom_rules": [
				{"id": "p1", "name": "Play CDN", "enabled": true, "domain_suffix": ["gvt1.com"], "outbound": "proxy"},
				{"id": "p2", "name": "Google Core", "enabled": true, "domains": ["accounts.google.com"], "outbound": "us-gcp"}
			]
		}
	}`

	res := request(s, http.MethodPost, "/api/backup?mode=merge", mergePayload)
	if res.Code != http.StatusOK {
		t.Fatalf("POST /api/backup?mode=merge failed: %d %s", res.Code, res.Body.String())
	}

	if len(s.store.List()) != 2 {
		t.Fatalf("expected 2 nodes preserved+merged, got %d", len(s.store.List()))
	}
	groups, err := s.store.ListGroups()
	if err != nil || len(groups) != 1 || groups[0].ID != "us-gcp" {
		t.Fatalf("expected us-gcp group saved, got %+v (%v)", groups, err)
	}
	profile, err := s.routingProfile()
	if err != nil {
		t.Fatal(err)
	}
	if profile.BlockAds {
		t.Fatalf("expected explicit block_ads=false in merge payload to take effect")
	}
	if len(profile.CustomRules) != 3 || profile.CustomRules[0].ID != "p1" || profile.CustomRules[2].ID != "user-old-rule" {
		t.Fatalf("expected incoming rules prepended before existing non-colliding rules, got %+v", profile.CustomRules)
	}

	// Verify standalone RoutingProfile JSON also merges cleanly and deduplicates repeated rule IDs.
	standaloneRes := request(s, http.MethodPost, "/api/backup?mode=merge", `{"custom_rules":[{"id":"p1","name":"Play CDN","enabled":true,"domain_suffix":["gvt1.com","gvt2.com"],"outbound":"proxy"}]}`)
	if standaloneRes.Code != http.StatusOK {
		t.Fatalf("standalone routing merge failed: %d %s", standaloneRes.Code, standaloneRes.Body.String())
	}
	profileAfter, _ := s.routingProfile()
	if len(profileAfter.CustomRules) != 3 ||
		len(profileAfter.CustomRules[0].DomainSuffix) != 2 ||
		profileAfter.CustomRules[1].ID != "p2" ||
		profileAfter.CustomRules[2].ID != "user-old-rule" {
		t.Fatalf("expected standalone routing profile merge + dedup (len=3), got %+v", profileAfter.CustomRules)
	}
	if !profileAfter.KillSwitchEnabled() {
		t.Fatalf("expected KillSwitch to remain enabled after standalone routing merge")
	}
}

func TestKillSwitchWatchdogTripsAndRecovers(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	if err := s.store.Add(&config.Node{
		ID:       "ks-n1",
		Name:     "KS Node",
		Protocol: config.ProtocolVLESS,
		Address:  "198.51.100.9",
		Port:     443,
		UUID:     "11111111-1111-1111-1111-111111111111",
		Security: "tls",
		Sni:      "ks.example",
	}); err != nil {
		t.Fatal(err)
	}

	c := request(s, http.MethodPost, "/api/process/connect", `{"node_id":"ks-n1"}`)
	if c.Code != http.StatusOK {
		t.Fatalf("connect failed: %d %s", c.Code, c.Body.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	failProbe := func(context.Context, string, string, int) (int, error) {
		return 0, errors.New("dial tcp timeout")
	}
	okProbe := func(context.Context, string, string, int) (int, error) {
		return 42, nil
	}

	// First failure does not trip immediately (grace threshold = 2 consecutive failures).
	s.evaluateKillSwitchOnce(ctx, failProbe)
	if tripped, _, _ := s.killSwitchSnapshot(); tripped {
		t.Fatal("did not expect KillSwitch to trip on a single transient failure")
	}

	// Second consecutive failure trips Kill Switch and switches "proxy" -> "block-out".
	s.evaluateKillSwitchOnce(ctx, failProbe)
	tripped, reason, intended := s.killSwitchSnapshot()
	if !tripped || reason == "" || intended != "node-ks-n1" {
		t.Fatalf("expected KillSwitch tripped for node-ks-n1, got tripped=%v reason=%q intended=%q", tripped, reason, intended)
	}
	if got := s.ensureOrchestrator().Status().ActiveTag; got != "block-out" {
		t.Fatalf("expected orchestrator active_tag=block-out while tripped, got %q", got)
	}

	// Process status API surfaces Kill Switch telemetry to the UI.
	stRes := request(s, http.MethodGet, "/api/process/status", "")
	if stRes.Code != http.StatusOK {
		t.Fatalf("GET /api/process/status failed: %d", stRes.Code)
	}
	var stBody map[string]any
	_ = json.Unmarshal(stRes.Body.Bytes(), &stBody)
	if stBody["kill_switch_enabled"] != true || stBody["kill_switch_tripped"] != true {
		t.Fatalf("expected kill_switch flags true in status payload, got %v", stBody)
	}

	// Once probe recovers, Kill Switch restores "proxy" -> "node-ks-n1".
	s.evaluateKillSwitchOnce(ctx, okProbe)
	trippedAfter, _, _ := s.killSwitchSnapshot()
	if trippedAfter {
		t.Fatal("expected KillSwitch to auto-recover once probe succeeded")
	}
	if got := s.ensureOrchestrator().Status().ActiveTag; got != "node-ks-n1" {
		t.Fatalf("expected orchestrator active_tag restored to node-ks-n1, got %q", got)
	}
}

func TestAutostartAPI(t *testing.T) {
	s := testServer(t, "")

	// Web/non-desktop mode reports unsupported on GET and 400 on PUT.
	resWeb := request(s, http.MethodGet, "/api/autostart", "")
	if resWeb.Code != http.StatusOK {
		t.Fatalf("GET /api/autostart in web mode failed: %d", resWeb.Code)
	}
	var stWeb autostart.Status
	_ = json.Unmarshal(resWeb.Body.Bytes(), &stWeb)
	if stWeb.Supported {
		t.Fatalf("expected supported=false in web mode, got %+v", stWeb)
	}
	if putWeb := request(s, http.MethodPut, "/api/autostart", `{"enabled":true}`); putWeb.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on PUT /api/autostart in web mode, got %d", putWeb.Code)
	}

	if runtime.GOOS != "linux" {
		return
	}

	s.SetMode(authservice.ModeDesktop)
	cfgHome := t.TempDir()
	mockAppImage := filepath.Join(t.TempDir(), "PrismRay.AppImage")
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	t.Setenv("APPIMAGE", mockAppImage)

	resGet := request(s, http.MethodGet, "/api/autostart", "")
	if resGet.Code != http.StatusOK {
		t.Fatalf("GET /api/autostart failed: %d %s", resGet.Code, resGet.Body.String())
	}
	var st autostart.Status
	if err := json.Unmarshal(resGet.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Supported || st.Enabled || st.Executable != mockAppImage {
		t.Fatalf("unexpected initial desktop autostart status: %+v", st)
	}

	resPut := request(s, http.MethodPut, "/api/autostart", `{"enabled":true,"minimized":true}`)
	if resPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/autostart enable failed: %d %s", resPut.Code, resPut.Body.String())
	}
	var stOn autostart.Status
	_ = json.Unmarshal(resPut.Body.Bytes(), &stOn)
	if !stOn.Enabled || !stOn.Minimized {
		t.Fatalf("expected enabled=true minimized=true, got %+v", stOn)
	}
	desktopRaw, err := os.ReadFile(filepath.Join(cfgHome, "autostart", "prismray.desktop"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(desktopRaw), mockAppImage) || !strings.Contains(string(desktopRaw), "--minimized") {
		t.Fatalf("unexpected autostart .desktop file contents:\n%s", string(desktopRaw))
	}

	resOff := request(s, http.MethodPut, "/api/autostart", `{"enabled":false}`)
	if resOff.Code != http.StatusOK {
		t.Fatalf("PUT /api/autostart disable failed: %d %s", resOff.Code, resOff.Body.String())
	}
	var stOff autostart.Status
	_ = json.Unmarshal(resOff.Body.Bytes(), &stOff)
	if stOff.Enabled {
		t.Fatalf("expected enabled=false after disable, got %+v", stOff)
	}
}

func TestShutdownCleanupPreservesSessionAndRestoresRuntime(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	if err := s.store.Add(&config.Node{
		ID:       "restore-n1",
		Name:     "Restore Node",
		Protocol: config.ProtocolSocks,
		Address:  "127.0.0.1",
		Port:     10809,
		Security: "none",
	}); err != nil {
		t.Fatal(err)
	}

	c := request(s, http.MethodPost, "/api/process/connect", `{"node_id":"restore-n1"}`)
	if c.Code != http.StatusOK {
		t.Fatalf("connect failed: %d %s", c.Code, c.Body.String())
	}
	// Persist remembered TUN & system proxy intent in store (simulating active preferences before exit).
	s.persistRuntimeSelection("restore-n1", "", true)
	s.persistSystemProxyWanted(true)

	// Graceful shutdown must clean runtime without erasing remembered flags.
	if err := s.ShutdownCleanup(context.Background()); err != nil {
		t.Fatalf("ShutdownCleanup failed: %v", err)
	}

	// Simulate fresh backend boot on the same store/config.
	s2 := NewServer(nil, s.store, nil, s.cfg)
	if !s2.wantRunning || !s2.tunEnabled || !s2.systemProxyWanted {
		t.Fatalf("expected session flags preserved across ShutdownCleanup: want=%v tun=%v sys=%v",
			s2.wantRunning, s2.tunEnabled, s2.systemProxyWanted)
	}

	// Disable TUN in s2 to test non-privileged restore cleanly without invoking host sudo/tun.
	s2.persistRuntimeSelection("restore-n1", "", false)
	s2.persistSystemProxyWanted(false)
	s2.RestoreLastSession(context.Background())
	if !s2.ensureOrchestrator().Status().Running {
		t.Fatal("expected RestoreLastSession to automatically reconnect on boot")
	}
	_ = s2.ShutdownCleanup(context.Background())
}

func TestV5GroupReorderPerGroupFailoverAndLoadBalanceSimulator(t *testing.T) {
	s := testServer(t, "")

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
	tcpAddr := ln.Addr().(*net.TCPAddr)

	if err := s.store.Add(&config.Node{
		ID: "lb-n1", Name: "Slow-DL", Protocol: config.ProtocolSocks,
		Address: "127.0.0.1", Port: tcpAddr.Port, Security: "none",
		Latency: 15, DownSpeedMbps: 10, UpSpeedMbps: 5,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Add(&config.Node{
		ID: "lb-n2", Name: "Fast-DL", Protocol: config.ProtocolSocks,
		Address: "127.0.0.1", Port: tcpAddr.Port, Security: "none",
		Latency: 25, DownSpeedMbps: 300, UpSpeedMbps: 80,
	}); err != nil {
		t.Fatal(err)
	}

	// 1. Create two groups + reorder via PUT /api/groups/reorder.
	w1 := request(s, http.MethodPost, "/api/groups", `{
		"id":"g-sel-pin","name":"Pinned Selector","strategy":"selector",
		"node_ids":["lb-n1","lb-n2"],"selected_node_id":"lb-n1",
		"priority_rule":"speed_first","auto_failover":false
	}`)
	if w1.Code != http.StatusOK {
		t.Fatalf("create g-sel-pin failed: %d %s", w1.Code, w1.Body.String())
	}
	w2 := request(s, http.MethodPost, "/api/groups", `{
		"id":"g-lb","name":"Domain Hash LB","strategy":"loadbalance",
		"node_ids":["lb-n1","lb-n2"],
		"priority_rule":"speed_first","auto_failover":true
	}`)
	if w2.Code != http.StatusOK {
		t.Fatalf("create g-lb failed: %d %s", w2.Code, w2.Body.String())
	}

	wReorder := request(s, http.MethodPut, "/api/groups/reorder", `{"group_ids":["g-lb","g-sel-pin"]}`)
	if wReorder.Code != http.StatusOK {
		t.Fatalf("PUT /api/groups/reorder failed: %d %s", wReorder.Code, wReorder.Body.String())
	}
	groups, err := s.store.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}
	if len(groups) != 2 || groups[0].ID != "g-lb" || groups[1].ID != "g-sel-pin" {
		t.Fatalf("expected reordered groups [g-lb, g-sel-pin], got %+v", groups)
	}

	// 2. Per-group auto_failover vs global Failover=false:
	//    - g-sel-pin has auto_failover=false: reorders node_ids by speed_first, preserves selected_node_id="lb-n1".
	//    - g-lb has auto_failover=true: overrides global Failover=false and promotes "lb-n2".
	hs := HealthSettings{URL: defaultProbeURL, IntervalSeconds: 120, ToleranceMS: 50, PriorityRule: "latency_first", Failover: false}
	gPin, _, _, err := s.probeAndReorderGroup(context.Background(), "g-sel-pin", "ping", "", hs, false)
	if err != nil {
		t.Fatalf("probeAndReorderGroup(g-sel-pin) failed: %v", err)
	}
	gLB, _, _, err := s.probeAndReorderGroup(context.Background(), "g-lb", "ping", "", hs, false)
	if err != nil {
		t.Fatalf("probeAndReorderGroup(g-lb) failed: %v", err)
	}

	if gPin.NodeIDs[0] != "lb-n2" {
		t.Fatalf("expected speed_first to rank lb-n2 first in g-sel-pin, got %v", gPin.NodeIDs)
	}
	if gPin.SelectedNodeID != "lb-n1" {
		t.Fatalf("expected auto_failover=false on g-sel-pin to keep lb-n1 selected, got %q", gPin.SelectedNodeID)
	}
	if gLB.SelectedNodeID != "lb-n2" {
		t.Fatalf("expected auto_failover=true on g-lb to override global failover=false and promote lb-n2, got %q", gLB.SelectedNodeID)
	}

	// 3. Simulate routing against active loadbalance group: github.com and api.github.com must share the same shard.
	s.persistRuntimeSelection("", "g-lb", false)
	wSimRoot := request(s, http.MethodPost, "/api/routing/simulate", `{"domain":"github.com","port":443,"network":"tcp"}`)
	wSimSub := request(s, http.MethodPost, "/api/routing/simulate", `{"domain":"api.github.com","port":443,"network":"tcp"}`)
	if wSimRoot.Code != http.StatusOK || wSimSub.Code != http.StatusOK {
		t.Fatalf("simulate failed: root=%d sub=%d", wSimRoot.Code, wSimSub.Code)
	}
	var simRoot, simSub ruleset.SimulationResult
	_ = json.Unmarshal(wSimRoot.Body.Bytes(), &simRoot)
	_ = json.Unmarshal(wSimSub.Body.Bytes(), &simSub)
	if !strings.Contains(simRoot.MatchedRule, "-> shard#") {
		t.Fatalf("expected shard annotation for loadbalance group, got %q", simRoot.MatchedRule)
	}
	if simRoot.MatchedRule != simSub.MatchedRule {
		t.Fatalf("expected root domain (%q) and subdomain (%q) to hit same loadbalance shard", simRoot.MatchedRule, simSub.MatchedRule)
	}
}

func TestNodeTabsMultiModePingGroupPriorityAndSubscriptionZero(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	// 1. Custom node tabs persistence & deduplication
	resPutTabs := request(s, http.MethodPut, "/api/node-tabs", `{"tabs":["流媒体","游戏","流媒体","  "]}`)
	if resPutTabs.Code != http.StatusOK {
		t.Fatalf("PUT /api/node-tabs failed: %d %s", resPutTabs.Code, resPutTabs.Body.String())
	}
	var tabResp struct {
		Tabs []string `json:"tabs"`
	}
	_ = json.Unmarshal(resPutTabs.Body.Bytes(), &tabResp)
	if len(tabResp.Tabs) != 2 || tabResp.Tabs[0] != "流媒体" || tabResp.Tabs[1] != "游戏" {
		t.Fatalf("unexpected custom tabs: %+v", tabResp.Tabs)
	}

	// 2. TCP Ping probe + Group auto-priority reordering
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

	_ = s.store.Add(&config.Node{ID: "n-bad", Name: "Closed", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: closedPort, Security: "none"})
	_ = s.store.Add(&config.Node{ID: "n-ok", Name: "Open", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: openPort, Security: "none"})

	grpBody := `{"id":"grp-prio","name":"AutoPrio","strategy":"urltest","node_ids":["n-bad","n-ok"]}`
	if cg := request(s, http.MethodPost, "/api/groups", grpBody); cg.Code != http.StatusOK {
		t.Fatalf("create group failed: %d %s", cg.Code, cg.Body.String())
	}

	probeGrpRes := request(s, http.MethodPost, "/api/groups/grp-prio/probe", `{"mode":"ping","priority_rule":"latency_first"}`)
	if probeGrpRes.Code != http.StatusOK {
		t.Fatalf("POST /api/groups/grp-prio/probe failed: %d %s", probeGrpRes.Code, probeGrpRes.Body.String())
	}
	var pg struct {
		Group storage.Group `json:"group"`
	}
	_ = json.Unmarshal(probeGrpRes.Body.Bytes(), &pg)
	if len(pg.Group.NodeIDs) != 2 || pg.Group.NodeIDs[0] != "n-ok" || pg.Group.SelectedNodeID != "n-ok" {
		t.Fatalf("expected n-ok promoted to priority #1 & selected, got %+v", pg.Group)
	}
	okNode := s.store.Get("n-ok")
	if okNode == nil || okNode.PingMS <= 0 {
		t.Fatalf("expected persisted ping_ms > 0 on n-ok, got %+v", okNode)
	}

	// 3. Subscriptions default 0 (manual only) + PUT update
	subAdd := request(s, http.MethodPost, "/api/subscriptions", `{"id":"sub-z","name":"ManualSub","url":"https://example.com/sub","auto_update_hours":0}`)
	if subAdd.Code != http.StatusOK {
		t.Fatalf("POST /api/subscriptions failed: %d %s", subAdd.Code, subAdd.Body.String())
	}
	if !strings.Contains(subAdd.Body.String(), `"auto_update_hours":0`) {
		t.Fatalf("expected auto_update_hours=0 in response: %s", subAdd.Body.String())
	}
	subEdit := request(s, http.MethodPut, "/api/subscriptions/sub-z", `{"name":"ManualSubUpdated","auto_update_hours":6}`)
	if subEdit.Code != http.StatusOK || !strings.Contains(subEdit.Body.String(), `"auto_update_hours":6`) {
		t.Fatalf("PUT /api/subscriptions/sub-z failed: %d %s", subEdit.Code, subEdit.Body.String())
	}

	// 4. HealthSettings expanded fields round-trip
	hsPut := request(s, http.MethodPut, "/api/health-settings", `{"url":"https://www.gstatic.com/generate_204","speed_down_url":"https://speed.cloudflare.com/__down?bytes=10000000","speed_up_url":"https://speed.cloudflare.com/__up","interval_seconds":90,"tolerance_ms":80,"priority_rule":"hybrid_score","failover":true}`)
	if hsPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/health-settings failed: %d %s", hsPut.Code, hsPut.Body.String())
	}
	if !strings.Contains(hsPut.Body.String(), `"priority_rule":"hybrid_score"`) || !strings.Contains(hsPut.Body.String(), `"tolerance_ms":80`) {
		t.Fatalf("unexpected health settings payload: %s", hsPut.Body.String())
	}

	// Ensure string port import helper stays satisfied cleanly.
	_ = strconv.Itoa(openPort)
}

func TestSecurityAndDetourAPIGuards(t *testing.T) {
	s := testServer(t, "")

	// 1. Subscription DELETE /api/subscriptions/{id} returns 200 and removes the subscription.
	subCreate := request(s, http.MethodPost, "/api/subscriptions", `{"id":"sub-del-1","name":"DeleteMe","url":"https://example.com/sub","auto_update_hours":0}`)
	if subCreate.Code != http.StatusOK {
		t.Fatalf("POST /api/subscriptions failed: %d %s", subCreate.Code, subCreate.Body.String())
	}
	subDel := request(s, http.MethodDelete, "/api/subscriptions/sub-del-1", "")
	if subDel.Code != http.StatusOK {
		t.Fatalf("DELETE /api/subscriptions/sub-del-1 expected 200, got %d %s", subDel.Code, subDel.Body.String())
	}
	if strings.Contains(subDel.Body.String(), "sub-del-1") {
		t.Fatalf("expected sub-del-1 removed after delete, got %s", subDel.Body.String())
	}
	subDelMissing := request(s, http.MethodDelete, "/api/subscriptions/sub-del-1", "")
	if subDelMissing.Code != http.StatusNotFound {
		t.Fatalf("DELETE missing subscription expected 404, got %d", subDelMissing.Code)
	}

	// 2. RuleSet path traversal and non-http URL rejection.
	rsTraversal := request(s, http.MethodPost, "/api/rulesets", `{"id":"evil","tag":"evil","source_type":"remote","url":"https://example.com/a.srs","local_path":"/tmp/pwned.srs"}`)
	if rsTraversal.Code != http.StatusBadRequest {
		t.Fatalf("expected absolute path outside ruleSetDir to be rejected (400), got %d %s", rsTraversal.Code, rsTraversal.Body.String())
	}
	rsDotDot := request(s, http.MethodPost, "/api/rulesets", `{"id":"evil2","tag":"evil2","source_type":"remote","url":"https://example.com/a.srs","local_path":"../../escape.srs"}`)
	if rsDotDot.Code != http.StatusBadRequest {
		t.Fatalf("expected '..' traversal path to be rejected (400), got %d %s", rsDotDot.Code, rsDotDot.Body.String())
	}
	rsBadScheme := request(s, http.MethodPost, "/api/rulesets", `{"id":"evil3","tag":"evil3","source_type":"remote","url":"file:///etc/passwd"}`)
	if rsBadScheme.Code != http.StatusBadRequest {
		t.Fatalf("expected file:// URL to be rejected (400), got %d %s", rsBadScheme.Code, rsBadScheme.Body.String())
	}
	rsValid := request(s, http.MethodPost, "/api/rulesets", `{"id":"custom-good","tag":"custom-good","format":"binary","source_type":"remote","url":"https://example.com/good.srs","enabled":true}`)
	if rsValid.Code != http.StatusOK {
		t.Fatalf("expected valid ruleset to succeed (200), got %d %s", rsValid.Code, rsValid.Body.String())
	}

	// 3. Node detour_id validation, cycle rejection, and dangling reference cleanup on delete.
	n1Res := request(s, http.MethodPost, "/api/nodes", `{"id":"n-relay","name":"HK Relay","protocol":"vless","address":"hk.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","network":"tcp","security":"tls"}`)
	if n1Res.Code != http.StatusOK && n1Res.Code != http.StatusCreated {
		t.Fatalf("create relay node failed: %d %s", n1Res.Code, n1Res.Body.String())
	}
	grpRes := request(s, http.MethodPost, "/api/groups", `{"id":"g-fast","name":"Fast","strategy":"urltest","node_ids":["n-relay"]}`)
	if grpRes.Code != http.StatusOK {
		t.Fatalf("create group failed: %d %s", grpRes.Code, grpRes.Body.String())
	}
	n2Res := request(s, http.MethodPost, "/api/nodes", `{"id":"n-gcp","name":"GCP US","protocol":"vless","address":"198.51.100.10","port":443,"uuid":"22222222-2222-2222-2222-222222222222","network":"tcp","security":"tls","detour_id":"g-fast"}`)
	if n2Res.Code != http.StatusOK && n2Res.Code != http.StatusCreated {
		t.Fatalf("create landing node with group detour failed: %d %s", n2Res.Code, n2Res.Body.String())
	}
	// Attempting to make n-relay detour through n-gcp must fail (cycle via g-fast).
	cycleRes := request(s, http.MethodPut, "/api/nodes/n-relay", `{"id":"n-relay","name":"HK Relay","protocol":"vless","address":"hk.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","network":"tcp","security":"tls","detour_id":"n-gcp"}`)
	if cycleRes.Code != http.StatusBadRequest {
		t.Fatalf("expected cycle detour update to fail (400), got %d %s", cycleRes.Code, cycleRes.Body.String())
	}
	// Deleting g-fast must clear n-gcp's detour_id cleanly.
	delGrpRes := request(s, http.MethodDelete, "/api/groups/g-fast", "")
	if delGrpRes.Code != http.StatusOK && delGrpRes.Code != http.StatusNoContent {
		t.Fatalf("delete group failed: %d %s", delGrpRes.Code, delGrpRes.Body.String())
	}
	if updated := s.store.Get("n-gcp"); updated == nil || updated.DetourID != "" {
		t.Fatalf("expected n-gcp detour_id cleared after group deletion, got %+v", updated)
	}
}

func TestGroupDetourSelectiveBackupAndBiometricAPI(t *testing.T) {
	s := testServer(t, "")

	// 1. Group Detour + bad interval validation + 3-hop cycle rejection.
	for _, body := range []string{
		`{"id":"n-entry","name":"Entry","protocol":"vless","address":"entry.example.com","port":443,"uuid":"11111111-1111-1111-1111-111111111111","network":"tcp","security":"tls"}`,
		`{"id":"n-mid","name":"Mid","protocol":"vless","address":"mid.example.com","port":443,"uuid":"22222222-2222-2222-2222-222222222222","network":"tcp","security":"tls"}`,
		`{"id":"n-land","name":"Land","protocol":"vless","address":"198.51.100.20","port":443,"uuid":"33333333-3333-3333-3333-333333333333","network":"tcp","security":"tls","detour_id":"n-mid"}`,
	} {
		if res := request(s, http.MethodPost, "/api/nodes", body); res.Code != http.StatusOK {
			t.Fatalf("seed node failed: %d %s", res.Code, res.Body.String())
		}
	}
	if badIv := request(s, http.MethodPost, "/api/groups", `{"id":"g-bad","name":"BadInterval","strategy":"urltest","interval":"300","node_ids":["n-entry"]}`); badIv.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid group interval rejected (400), got %d %s", badIv.Code, badIv.Body.String())
	}
	if gEntry := request(s, http.MethodPost, "/api/groups", `{"id":"g-entry","name":"EntryAuto","strategy":"urltest","interval":"1h","node_ids":["n-entry"]}`); gEntry.Code != http.StatusOK {
		t.Fatalf("create g-entry failed: %d %s", gEntry.Code, gEntry.Body.String())
	}
	if gLand := request(s, http.MethodPost, "/api/groups", `{"id":"g-land","name":"LandPool","strategy":"selector","detour_id":"g-entry","node_ids":["n-land"]}`); gLand.Code != http.StatusOK {
		t.Fatalf("create g-land with detour failed: %d %s", gLand.Code, gLand.Body.String())
	}
	// Attempting to make g-entry detour back to g-land must fail (400).
	if gCycle := request(s, http.MethodPut, "/api/groups/g-entry", `{"name":"EntryAuto","strategy":"urltest","interval":"1h","detour_id":"g-land","node_ids":["n-entry"]}`); gCycle.Code != http.StatusBadRequest {
		t.Fatalf("expected group cycle rejected (400), got %d %s", gCycle.Code, gCycle.Body.String())
	}

	// 2. Selective backup export (?include=nodes,subscriptions,routing).
	if subRes := request(s, http.MethodPost, "/api/subscriptions", `{"id":"sub-bak-1","name":"SubBak","url":"https://example.com/sub","auto_update_hours":0}`); subRes.Code != http.StatusOK {
		t.Fatalf("create sub failed: %d %s", subRes.Code, subRes.Body.String())
	}
	selBak := request(s, http.MethodGet, "/api/backup?include=nodes,subscriptions,routing", "")
	if selBak.Code != http.StatusOK {
		t.Fatalf("GET selective backup failed: %d %s", selBak.Code, selBak.Body.String())
	}
	var parsed FullBackup
	if err := json.Unmarshal(selBak.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Nodes) != 3 || len(parsed.Subscriptions) != 1 || parsed.RoutingProfile.Mode == "" {
		t.Fatalf("expected nodes+subscriptions+routing in selective backup, got %+v", parsed)
	}
	if len(parsed.Groups) != 0 || parsed.Preferences != nil {
		t.Fatalf("expected groups & preferences excluded when not requested, got groups=%d prefs=%v", len(parsed.Groups), parsed.Preferences)
	}
}
