// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
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
