// SPDX-License-Identifier: MPL-2.0

package ruleset

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestSimulateRoutingRules(t *testing.T) {
	p := DefaultRoutingProfile()
	p.CustomRules = []RoutingRule{
		{ID: "r1", Name: "Work SSH", Enabled: true, DomainSuffix: []string{"corp.internal"}, Port: []int{22}, Outbound: "direct"},
		{ID: "r2", Name: "Block Telemetry", Enabled: true, ProcessName: []string{"telemetryd"}, Outbound: "block"},
	}

	if res := Simulate(p, SimulationInput{IP: "192.168.1.50"}); res.Outbound != "direct" || res.MatchedRule != "builtin:ip_is_private" {
		t.Fatalf("expected private IP direct, got %+v", res)
	}
	if res := Simulate(p, SimulationInput{Domain: "ads.doubleclick.net"}); res.Outbound != "block" || res.Action != "reject" {
		t.Fatalf("expected ad domain blocked, got %+v", res)
	}
	if res := Simulate(p, SimulationInput{Domain: "git.corp.internal", Port: 22}); res.Outbound != "direct" || res.MatchedRule != "Work SSH" {
		t.Fatalf("expected custom rule direct, got %+v", res)
	}
	if res := Simulate(p, SimulationInput{ProcessName: "telemetryd", Domain: "example.com"}); res.Outbound != "block" || res.MatchedRule != "Block Telemetry" {
		t.Fatalf("expected process rule block, got %+v", res)
	}
	if res := Simulate(p, SimulationInput{Domain: "www.baidu.com"}); res.Outbound != "direct" {
		t.Fatalf("expected CN domain direct, got %+v", res)
	}
	if res := Simulate(p, SimulationInput{Domain: "openai.com"}); res.Outbound != "proxy" {
		t.Fatalf("expected foreign domain via proxy, got %+v", res)
	}
}

func TestSyncRuleSetDownloadsAndTracksSize(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("SRS-BINARY-PAYLOAD"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	spec := BuiltinRuleSets(dir)[0]
	spec.URL = srv.URL + "/geosite-cn.srs"
	synced, err := SyncRuleSet(context.Background(), srv.Client(), spec)
	if err != nil {
		t.Fatalf("SyncRuleSet failed: %v", err)
	}
	if !synced.Synced || synced.SizeBytes != 18 || filepath.Dir(synced.LocalPath) != dir {
		t.Fatalf("unexpected synced metadata: %+v", synced)
	}
}

func TestAllowLANBroadcastDefaultsAndLinksWithBypassLAN(t *testing.T) {
	def := DefaultRoutingProfile()
	if !def.BypassLAN {
		t.Fatal("expected DefaultRoutingProfile BypassLAN to default to true")
	}
	if def.AllowLANBroadcast {
		t.Fatal("expected DefaultRoutingProfile AllowLANBroadcast to default to false")
	}

	p := RoutingProfile{BypassLAN: false, AllowLANBroadcast: true}
	p.Normalize()
	if p.AllowLANBroadcast {
		t.Fatal("expected Normalize to clear AllowLANBroadcast when BypassLAN is false")
	}

	p2 := RoutingProfile{BypassLAN: true, AllowLANBroadcast: true}
	p2.Normalize()
	if !p2.AllowLANBroadcast {
		t.Fatal("expected Normalize to keep AllowLANBroadcast when BypassLAN is true")
	}
}

func TestDefaultRemoteDNSAndMirrorURLs(t *testing.T) {
	def := DefaultRoutingProfile()
	if def.RemoteDNS != "https://1.1.1.1/dns-query" {
		t.Fatalf("expected default RemoteDNS to be https://1.1.1.1/dns-query, got %q", def.RemoteDNS)
	}
	mirrors := MirrorURLs("https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs")
	if len(mirrors) != 1 || mirrors[0] != "https://cdn.jsdelivr.net/gh/SagerNet/sing-geosite@rule-set/geosite-cn.srs" {
		t.Fatalf("unexpected jsDelivr mirror URLs: %+v", mirrors)
	}
	if len(MirrorURLs("https://example.com/custom.srs")) != 0 {
		t.Fatal("expected no mirrors for non-GitHub custom URL")
	}
}
