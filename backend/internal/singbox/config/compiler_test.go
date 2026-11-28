// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func testSingBoxNodes() []*config.Node {
	return []*config.Node{
		{
			ID: "vless-1", Name: "VLESS Reality", Protocol: config.ProtocolVLESS,
			Address: "example.com", Port: 443, UUID: "11111111-1111-4111-8111-111111111111",
			Flow: "xtls-rprx-vision", Security: "reality", Sni: "www.microsoft.com",
			PublicKey: "zwWqEjRwDWQ2NM5x0PXxuTQxgDEUMBQwoRFBV34QrwU", ShortID: "01ab",
			Fingerprint: "chrome", Network: "tcp",
		},
		{
			ID: "vmess-1", Name: "VMess WS", Protocol: config.ProtocolVMess,
			Address: "vm.example.com", Port: 443, UUID: "11111111-1111-4111-8111-111111111111",
			Cipher: "auto", Security: "tls", Sni: "vm.example.com", Network: "ws", Path: "/ws", Host: "vm.example.com",
		},
		{
			ID: "trojan-1", Name: "Trojan gRPC", Protocol: config.ProtocolTrojan,
			Address: "tr.example.com", Port: 443, Password: "pass", Security: "tls",
			Sni: "tr.example.com", Network: "grpc", ServiceName: "grpc-svc",
		},
		{
			ID: "ss-1", Name: "SS2022", Protocol: config.ProtocolShadowsocks,
			Address: "ss.example.com", Port: 8388, Method: "aes-256-gcm", Password: "secret", UoT: true,
		},
		{
			ID: "hy2-1", Name: "Hysteria2", Protocol: config.ProtocolHysteria2,
			Address: "hy2.example.com", Port: 443, Password: "hy2", Security: "tls",
			Sni: "hy2.example.com", ObfsType: "salamander", ObfsPassword: "obfs", UpMbps: 50, DownMbps: 200,
		},
		{
			ID: "tuic-1", Name: "TUICv5", Protocol: config.ProtocolTUIC,
			Address: "tuic.example.com", Port: 443, UUID: "11111111-1111-4111-8111-111111111111",
			Password: "tpass", Security: "tls", Sni: "tuic.example.com", CongestionControl: "bbr", UDPRelayMode: "native",
		},
		{
			ID: "anytls-1", Name: "AnyTLS", Protocol: config.ProtocolAnyTLS,
			Address: "any.example.com", Port: 443, Password: "any", Security: "tls", Sni: "any.example.com",
		},
		{
			ID: "wg-1", Name: "WireGuard", Protocol: config.ProtocolWireGuard,
			Address: "1.2.3.4", Port: 51820,
			PrivateKey:     "YJv1sR7n8pYJv1sR7n8pYJv1sR7n8pYJv1sR7n8pYGo=",
			PeerPublicKey:  "zwWqEjRwDWQ2NM5x0PXxuTQxgDEUMBQwoRFBV34QrwU=",
			LocalAddresses: []string{"10.0.0.2/32"}, MTU: 1408, Reserved: []uint8{1, 2, 3},
		},
		{
			ID: "xhttp-1", Name: "Xray Bridge XHTTP", Protocol: config.ProtocolVLESS,
			Address: "xhttp.example.com", Port: 443, UUID: "11111111-1111-4111-8111-111111111111",
			Network: "xhttp", Security: "reality", PublicKey: "zwWqEjRwDWQ2NM5x0PXxuTQxgDEUMBQwoRFBV34QrwU",
		},
		{
			ID: "naive-1", Name: "NaiveProxy", Protocol: config.ProtocolNaive,
			Address: "naive.example.com", Port: 443, Username: "u", Password: "p", Security: "tls",
		},
	}
}

func TestCompileAndCheckWithRealSingBox(t *testing.T) {
	nodes := testSingBoxNodes()
	in := CompileInput{
		Nodes: nodes,
		Groups: []storage.Group{
			{ID: "g-auto", Name: "Auto", Strategy: "urltest", ToleranceMS: 50, Interval: "5m", NodeIDs: []string{"vless-1", "hy2-1", "xhttp-1", "wg-1"}},
			{ID: "g-sel", Name: "Manual", Strategy: "selector", SelectedNodeID: "tuic-1", NodeIDs: []string{"tuic-1", "anytls-1"}},
		},
		Listeners: []*config.ListenConfig{
			{ID: "l-mixed", Name: "LAN Mixed", Protocol: "mixed", Address: "127.0.0.1", Port: 10810, AllowLAN: true, TargetGroupID: "g-auto", Enabled: true},
		},
		Routing: ruleset.RoutingProfile{
			Mode:           "rule",
			BlockAds:       true,
			BypassLAN:      true,
			BypassCN:       true,
			LocalDNS:       "223.5.5.5",
			RemoteDNS:      "https://1.1.1.1/dns-query",
			DomainStrategy: "prefer_ipv4",
			LogLevel:       "info",
			CustomRules: []ruleset.RoutingRule{
				{ID: "cr1", Name: "Block example", Enabled: true, DomainSuffix: []string{"bad.example.com"}, Outbound: "block"},
			},
		},
		RuleSets:        ruleset.BuiltinRuleSets(""),
		ActiveGroupID:   "g-auto",
		MixedPort:       10808,
		ClashAPIPort:    9090,
		ClashAPISecret:  "test-clash-secret",
		EnableTUN:       true,
		XrayBridgePorts: map[string]int{"xhttp-1": 18081},
		IncludeNaive:    false,
	}

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if len(out.SkippedNaive) != 1 || out.SkippedNaive[0] != "naive-1" {
		t.Fatalf("expected unreferenced naive node skipped safely without libcronet, got %+v", out.SkippedNaive)
	}
	if strings.Contains(string(out.Raw), `"type": "naive"`) {
		t.Fatal("naive outbound emitted when IncludeNaive=false")
	}

	var compiledDoc struct {
		DNS struct {
			Rules []map[string]any `json:"rules"`
		} `json:"dns"`
		Inbounds []map[string]any `json:"inbounds"`
		Route    struct {
			DefaultMark string           `json:"default_mark"`
			Rules       []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.Raw, &compiledDoc); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "linux" && compiledDoc.Route.DefaultMark != "" {
		t.Fatalf("expected route.default_mark omitted when tun.auto_redirect is enabled on Linux, got %q", compiledDoc.Route.DefaultMark)
	}
	foundTUN := false
	for _, ib := range compiledDoc.Inbounds {
		if ib["type"] == "tun" {
			foundTUN = true
			if mtu, _ := ib["mtu"].(float64); mtu != 1500 {
				t.Fatalf("expected TUN mtu=1500, got %v", ib["mtu"])
			}
			addrs, _ := ib["address"].([]any)
			if len(addrs) != 2 || addrs[0] != "172.19.0.1/30" || addrs[1] != "fdfe:dcba:9876::1/126" {
				t.Fatalf("expected dual-stack TUN address under prefer_ipv4 for IPv6 leak capture, got %v", ib["address"])
			}
			excl, _ := ib["route_exclude_address"].([]any)
			if len(excl) != 2 || excl[0] != "127.0.0.0/8" || excl[1] != "::1/128" {
				t.Fatalf("expected dual-stack loopback route_exclude_address under prefer_ipv4, got %v", ib["route_exclude_address"])
			}
			if runtime.GOOS == "linux" {
				if ar, _ := ib["auto_redirect"].(bool); !ar {
					t.Fatalf("expected Linux TUN auto_redirect=true, got %v", ib["auto_redirect"])
				}
				if om, _ := ib["auto_redirect_output_mark"].(string); om != "0x21782" {
					t.Fatalf("expected Linux TUN auto_redirect_output_mark=0x21782, got %v", ib["auto_redirect_output_mark"])
				}
				if nfq, _ := ib["auto_redirect_nfqueue"].(float64); nfq != 2178 {
					t.Fatalf("expected Linux TUN auto_redirect_nfqueue=2178, got %v", ib["auto_redirect_nfqueue"])
				}
			}
		}
	}
	if !foundTUN {
		t.Fatal("expected tun inbound in compiled config")
	}
	foundIPv6Suppress := false
	for _, r := range compiledDoc.DNS.Rules {
		if r["action"] == "predefined" && r["rcode"] == "NOERROR" {
			if qtypes, ok := r["query_type"].([]any); ok && len(qtypes) == 2 && qtypes[0] == "AAAA" && qtypes[1] == "HTTPS" {
				foundIPv6Suppress = true
				break
			}
		}
	}
	if !foundIPv6Suppress {
		t.Fatalf("expected DNS predefined NOERROR rule for AAAA/HTTPS under prefer_ipv4, got %+v", compiledDoc.DNS.Rules)
	}
	foundPort53Hijack := false
	for _, r := range compiledDoc.Route.Rules {
		if p, ok := r["port"].(float64); ok && p == 53 && r["action"] == "hijack-dns" {
			foundPort53Hijack = true
			break
		}
	}
	if !foundPort53Hijack {
		t.Fatal("expected route port 53 hijack-dns rule")
	}

	binary := os.Getenv("SINGBOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SINGBOX_TEST_BINARY for real sing-box check verification")
	}

	// Test Desktop TUN + Mixed + Groups + WireGuard Endpoint + Xray Socks Bridge
	cfgPath := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(cfgPath, out.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed for PC TUN config: %v\n%s\n%s", err, output, string(out.Raw))
	}

	// Test Android protect_path + override_android_vpn config
	in.EnableTUN = false
	in.AndroidMode = true
	in.ProtectPath = "/tmp/prismray-protect.sock"
	in.Routing.Mode = "global"
	androidOut, err := Compile(in)
	if err != nil {
		t.Fatalf("Android Compile failed: %v", err)
	}
	androidCfgPath := filepath.Join(t.TempDir(), "sing-box-android.json")
	if err := os.WriteFile(androidCfgPath, androidOut.Raw, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(binary, "check", "-c", androidCfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check failed for Android config: %v\n%s\n%s", err, output, string(androidOut.Raw))
	}
}

func TestCompileCustomRuleOutboundAndNameFallback(t *testing.T) {
	in := CompileInput{
		Nodes: []*config.Node{
			{ID: "main-3p", Name: "Fast Node", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: 1080, Security: "none"},
			{
				ID: "us-gcp-vless", Name: "US Node", Protocol: config.ProtocolVLESS,
				Address: "free.200107089.xyz", Port: 443, UUID: "1a2e150a-fcfa-46ff-9526-166e7bca1b39",
				Flow: "xtls-rprx-vision", Security: "reality", Sni: "www.apple.com",
				PublicKey: "9FC7JObgyM8O5pMX2woUqdcppsZjywwcDXnHpQwq3Eo", ShortID: "6baad067", Fingerprint: "chrome", Network: "tcp",
			},
		},
		Groups: []storage.Group{
			{ID: "us-gcp", Name: "美区 GCP 节点", Strategy: "selector", SelectedNodeID: "us-gcp-vless", NodeIDs: []string{"us-gcp-vless"}},
		},
		Routing: ruleset.RoutingProfile{
			Mode:      "rule",
			BlockAds:  false,
			BypassLAN: true,
			BypassCN:  true,
			CustomRules: []ruleset.RoutingRule{
				{ID: "r1", Enabled: true, DomainSuffix: []string{"gvt1.com"}, Outbound: "proxy"},
				{ID: "r2", Enabled: true, Domains: []string{"accounts.google.com"}, Outbound: "us-gcp"},
				{ID: "r3", Enabled: true, Domains: []string{"policies.google.com"}, Outbound: "美区 GCP 节点"},
			},
		},
		ActiveNodeID: "main-3p",
		MixedPort:    10808,
		ClashAPIPort: 9090,
		EnableTUN:    false,
	}

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	var doc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, r := range doc.Route.Rules {
		if ds, ok := r["domain_suffix"].([]any); ok && len(ds) == 1 && ds[0] == "gvt1.com" {
			got["gvt1.com"], _ = r["outbound"].(string)
		}
		if dm, ok := r["domain"].([]any); ok && len(dm) == 1 {
			if s, ok := dm[0].(string); ok {
				got[s], _ = r["outbound"].(string)
			}
		}
	}
	if got["gvt1.com"] != "proxy" {
		t.Fatalf("expected gvt1.com -> proxy, got %q", got["gvt1.com"])
	}
	if got["accounts.google.com"] != "group-us-gcp" {
		t.Fatalf("expected accounts.google.com -> group-us-gcp, got %q", got["accounts.google.com"])
	}
	if got["policies.google.com"] != "group-us-gcp" {
		t.Fatalf("expected policies.google.com -> group-us-gcp via name fallback, got %q", got["policies.google.com"])
	}
}

func TestCompileFakeIPAndHijackDNS(t *testing.T) {
	def := ruleset.DefaultRoutingProfile()
	if def.FakeIP {
		t.Fatal("expected DefaultRoutingProfile FakeIP to default to false")
	}
	if !def.HijackDNSEnabled() {
		t.Fatal("expected DefaultRoutingProfile HijackDNS to default to true")
	}

	simDefault := ruleset.Simulate(def, ruleset.SimulationInput{IP: "fc00::1"})
	if simDefault.Outbound != "direct" {
		t.Fatalf("expected private fc00::1 -> direct when FakeIP is disabled, got %q", simDefault.Outbound)
	}

	in := CompileInput{
		Nodes: []*config.Node{
			{
				ID: "us-gcp-vless", Name: "US Node", Protocol: config.ProtocolVLESS,
				Address: "free.200107089.xyz", Port: 443, UUID: "1a2e150a-fcfa-46ff-9526-166e7bca1b39",
				Flow: "xtls-rprx-vision", Security: "reality", Sni: "www.apple.com",
				PublicKey: "9FC7JObgyM8O5pMX2woUqdcppsZjywwcDXnHpQwq3Eo", ShortID: "6baad067", Fingerprint: "chrome", Network: "tcp",
			},
		},
		Routing: ruleset.RoutingProfile{
			Mode:           "rule",
			BlockAds:       true,
			BypassLAN:      true,
			BypassCN:       true,
			LocalDNS:       "223.5.5.5",
			RemoteDNS:      "https://dns.google/dns-query",
			DomainStrategy: "prefer_ipv4",
			HijackDNS:      ruleset.BoolPtr(true),
			FakeIP:         true,
			FakeIPFilter:   []string{"*.internal.corp"},
			CustomRules: []ruleset.RoutingRule{
				{ID: "p0", Enabled: true, Domains: []string{"direct-custom.example.com"}, Outbound: "direct"},
				{ID: "p2", Enabled: true, Domains: []string{"accounts.google.com"}, Outbound: "us-gcp-vless"},
			},
		},
		RuleSets:      ruleset.BuiltinRuleSets(""),
		ActiveNodeID:  "us-gcp-vless",
		MixedPort:     10808,
		ClashAPIPort:  9090,
		EnableTUN:     true,
		CacheFilePath: filepath.Join(t.TempDir(), "cache.db"),
	}

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile FakeIP failed: %v", err)
	}

	simFake := ruleset.Simulate(in.Routing, ruleset.SimulationInput{IP: "fc00::1"})
	if simFake.Outbound != "proxy" {
		t.Fatalf("expected FakeIP fc00::1 not to hit builtin private direct rule, got %+v", simFake)
	}

	var doc struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
		Experimental struct {
			CacheFile map[string]any `json:"cache_file"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}

	hasFakeIPServer := false
	for _, s := range doc.DNS.Servers {
		if s["tag"] == "fakeip-dns" && s["type"] == "fakeip" && s["inet4_range"] == "198.18.0.0/15" {
			if _, hasV6 := s["inet6_range"]; hasV6 {
				t.Fatalf("did not expect inet6_range on fakeip-dns under prefer_ipv4, got %+v", s)
			}
			hasFakeIPServer = true
		}
	}
	if !hasFakeIPServer {
		t.Fatalf("missing IPv4-only fakeip-dns server in %+v", doc.DNS.Servers)
	}
	hasPredefinedSuppress := false
	for _, r := range doc.DNS.Rules {
		if r["action"] == "predefined" && r["rcode"] == "NOERROR" {
			hasPredefinedSuppress = true
			break
		}
	}
	if !hasPredefinedSuppress {
		t.Fatalf("expected predefined NOERROR rule for AAAA/HTTPS in FakeIP + prefer_ipv4 mode: %+v", doc.DNS.Rules)
	}

	// Verify prefer_ipv6 restores dual-stack TUN + FakeIPv6 + disables AAAA/HTTPS suppression.
	v6In := in
	v6In.Routing.DomainStrategy = "prefer_ipv6"
	v6Out, err := Compile(v6In)
	if err != nil {
		t.Fatalf("Compile FakeIP prefer_ipv6 failed: %v", err)
	}
	var v6Doc struct {
		DNS struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
		Inbounds []map[string]any `json:"inbounds"`
	}
	if err := json.Unmarshal(v6Out.Raw, &v6Doc); err != nil {
		t.Fatal(err)
	}
	foundV6FakeIP := false
	for _, s := range v6Doc.DNS.Servers {
		if s["tag"] == "fakeip-dns" && s["inet4_range"] == "198.18.0.0/15" && s["inet6_range"] == "fc00::/18" {
			foundV6FakeIP = true
		}
	}
	if !foundV6FakeIP {
		t.Fatalf("expected dual-stack fakeip-dns under prefer_ipv6, got %+v", v6Doc.DNS.Servers)
	}
	for _, r := range v6Doc.DNS.Rules {
		if _, hasQType := r["query_type"]; hasQType && r["action"] == "predefined" {
			t.Fatalf("did not expect predefined AAAA/HTTPS suppression rule under prefer_ipv6: %+v", r)
		}
	}
	foundV6TUN := false
	for _, ib := range v6Doc.Inbounds {
		if ib["type"] == "tun" {
			addrs, _ := ib["address"].([]any)
			if len(addrs) == 2 && addrs[0] == "172.19.0.1/30" && addrs[1] == "fdfe:dcba:9876::1/126" {
				foundV6TUN = true
			}
		}
	}
	if !foundV6TUN {
		t.Fatalf("expected dual-stack TUN address under prefer_ipv6, got %+v", v6Doc.Inbounds)
	}

	if doc.Experimental.CacheFile["enabled"] != true || doc.Experimental.CacheFile["store_fakeip"] != true {
		t.Fatalf("expected experimental.cache_file store_fakeip=true, got %+v", doc.Experimental.CacheFile)
	}

	rawStr := string(out.Raw)
	for _, want := range []string{"free.200107089.xyz", "direct-custom.example.com", "internal.corp"} {
		if !strings.Contains(rawStr, want) {
			t.Fatalf("expected FakeIP bypass domain %q in compiled DNS rules", want)
		}
	}
	for _, r := range doc.Route.Rules {
		if _, hasPrivateFlag := r["ip_is_private"]; hasPrivateFlag {
			t.Fatalf("unexpected ip_is_private rule when FakeIP=true (overlaps fc00::/18)")
		}
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-fakeip.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput()
		if err != nil {
			t.Fatalf("sing-box check FakeIP config failed: %v\n%s\n%s", err, output, rawStr)
		}
		if strings.Contains(strings.ToLower(string(output)), "deprecated") || strings.Contains(string(output), "WARN") {
			t.Fatalf("expected zero deprecation/warn output from sing-box check, got: %s", output)
		}
	}

	// Verify hijack_dns=false omits hijack-dns route rules cleanly.
	in.Routing.HijackDNS = ruleset.BoolPtr(false)
	noHijackOut, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile hijack_dns=false failed: %v", err)
	}
	if strings.Contains(string(noHijackOut.Raw), "hijack-dns") {
		t.Fatal("expected hijack-dns rules omitted when hijack_dns=false")
	}
}

func TestCompileKillSwitchPreventsDirectFallback(t *testing.T) {
	def := ruleset.DefaultRoutingProfile()
	if !def.KillSwitchEnabled() {
		t.Fatal("expected DefaultRoutingProfile KillSwitch to default to true")
	}

	in := CompileInput{
		Nodes: []*config.Node{
			{
				ID: "naive-only", Name: "Naive Only", Protocol: config.ProtocolNaive,
				Address: "naive.example.com", Port: 443, Username: "u", Password: "p", Security: "tls",
			},
		},
		Routing:      def,
		RuleSets:     ruleset.BuiltinRuleSets(""),
		ActiveNodeID: "naive-only",
		MixedPort:    10808,
		ClashAPIPort: 9090,
		IncludeNaive: false,
	}

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if out.ActiveTag != BlockOutboundTag {
		t.Fatalf("expected ActiveTag=%q when no valid node and KillSwitch=true, got %q", BlockOutboundTag, out.ActiveTag)
	}

	var doc struct {
		Outbounds []struct {
			Tag       string   `json:"tag"`
			Type      string   `json:"type"`
			Default   string   `json:"default"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	var foundProxy, foundBlock bool
	for _, ob := range doc.Outbounds {
		if ob.Tag == BlockOutboundTag && ob.Type == "block" {
			foundBlock = true
		}
		if ob.Tag == "proxy" {
			foundProxy = true
			if ob.Default != BlockOutboundTag {
				t.Fatalf("expected proxy default=%q with KillSwitch=true and no usable nodes, got %q", BlockOutboundTag, ob.Default)
			}
			for _, m := range ob.Outbounds {
				if m == "direct" {
					t.Fatalf("did not expect direct inside proxy selector when KillSwitch=true: %v", ob.Outbounds)
				}
			}
		}
	}
	if !foundBlock || !foundProxy {
		t.Fatalf("missing block-out (%v) or proxy (%v) outbound", foundBlock, foundProxy)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-ks.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with KillSwitch block-out: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileLoadBalanceDomainHashSharding(t *testing.T) {
	in := CompileInput{
		Nodes: []*config.Node{
			{ID: "n1", Name: "Tokyo-1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none", Latency: 30},
			{ID: "n2", Name: "Singapore-2", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Security: "none", Latency: 45},
			{ID: "n3", Name: "Dead-3", Protocol: config.ProtocolSocks, Address: "198.51.100.3", Port: 1080, Security: "none", Latency: -1},
		},
		Groups: []storage.Group{
			{
				ID:          "lb1",
				Name:        "Balanced Exit",
				Strategy:    "loadbalance",
				NodeIDs:     []string{"n1", "n2", "n3"},
				Interval:    "3m",
				ToleranceMS: 50,
			},
		},
		ActiveGroupID: "lb1",
		Routing: ruleset.RoutingProfile{
			Mode:     "rule",
			BypassCN: false,
		},
	}

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile loadbalance failed: %v", err)
	}

	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
		Route     struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}

	// Expect logical domain_regex shard rules routing through lb-shard-lb1-0 / lb-shard-lb1-1 selectors,
	// each wrapping only healthy nodes (node-n1 / node-n2) + block-out, never dead node-n3.
	shardSelectors := map[string]string{}
	for _, ob := range doc.Outbounds {
		tag, _ := ob["tag"].(string)
		if ob["type"] == "selector" && strings.HasPrefix(tag, "lb-shard-lb1-") {
			def, _ := ob["default"].(string)
			shardSelectors[tag] = def
		}
	}
	if len(shardSelectors) != 2 || shardSelectors["lb-shard-lb1-0"] != "node-n1" || shardSelectors["lb-shard-lb1-1"] != "node-n2" {
		t.Fatalf("expected 2 lb-shard selector wrappers pointing to node-n1/node-n2, got %v", shardSelectors)
	}
	shardTargets := map[string]bool{}
	hashRuleCount := 0
	affinityGlobalCount := 0
	for _, r := range doc.Route.Rules {
		if r["type"] == "logical" && r["mode"] == "and" {
			ob, _ := r["outbound"].(string)
			if ob == "node-n3" {
				t.Fatalf("expected dead node-n3 (latency=-1) to be excluded from loadbalance shards: %+v", r)
			}
			subRules, _ := r["rules"].([]any)
			hasDomainRegex := false
			hasDomainSuffix := false
			for _, sr := range subRules {
				if sm, ok := sr.(map[string]any); ok {
					if _, ok := sm["domain_regex"]; ok {
						hasDomainRegex = true
					}
					if _, ok := sm["domain_suffix"]; ok {
						hasDomainSuffix = true
					}
				}
			}
			if hasDomainRegex && (ob == "lb-shard-lb1-0" || ob == "lb-shard-lb1-1") {
				shardTargets[ob] = true
				hashRuleCount++
			}
			if hasDomainSuffix && ob == "lb-shard-lb1-0" {
				affinityGlobalCount++
			}
		}
	}
	if hashRuleCount != 2 || !shardTargets["lb-shard-lb1-0"] || !shardTargets["lb-shard-lb1-1"] || affinityGlobalCount != 1 {
		t.Fatalf("expected 2 healthy loadbalance hash rules + 1 logical affinity rule (lb-shard-lb1-0/1), got hash=%d affinity=%d targets=%v", hashRuleCount, affinityGlobalCount, shardTargets)
	}

	if idxRoot, idxSub := DomainHashShardIndex("github.com", 2), DomainHashShardIndex("api.github.com", 2); idxRoot < 0 || idxRoot != idxSub {
		t.Fatalf("expected eTLD+1 affinity for github.com (%d) == api.github.com (%d)", idxRoot, idxSub)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-lb.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed for loadbalance domain-hash config: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileMultiListenerPriorityWebRTCAndExtendedRules(t *testing.T) {
	in := CompileInput{
		Nodes: []*config.Node{
			{ID: "n1", Name: "Primary", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none"},
			{ID: "n2", Name: "Secondary", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Security: "none"},
		},
		Listeners: []*config.ListenConfig{
			{ID: "lis-n2", Name: "Port 2082", Protocol: "mixed", Address: "127.0.0.1", Port: 2082, NodeIDs: []string{"n2"}, Enabled: true},
			{ID: "lis-dir", Name: "Port 2083", Protocol: "http", Address: "127.0.0.1", Port: 2083, TargetOutbound: "direct", Enabled: true},
		},
		Routing: ruleset.RoutingProfile{
			Mode:       "global",
			WebRTCMode: "proxy",
			BypassLAN:  true,
			CustomRules: []ruleset.RoutingRule{
				{
					ID:           "ext-1",
					Name:         "Extended Rule",
					Enabled:      true,
					DomainRegex:  []string{"^api\\.example\\.org$"},
					SourceIPCIDR: []string{"192.168.10.0/24"},
					Network:      []string{"udp"},
					PortRange:    []string{"1000-2000"},
					SourcePort:   []int{55000},
					ProcessPath:  []string{"/usr/bin/curl"},
					Inbound:      []string{"mixed-in"},
					Invert:       true,
					Outbound:     "direct",
				},
			},
		},
		ActiveNodeID: "n1",
		MixedPort:    10808,
		ClashAPIPort: 9090,
	}

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile extended config failed: %v", err)
	}

	var doc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}

	idxLisN2, idxLisDir, idxGlobal, idxWebRTCProxy := -1, -1, -1, -1
	for i, r := range doc.Route.Rules {
		if ib, ok := r["inbound"].([]any); ok && len(ib) == 1 {
			if ib[0] == "in-lis-n2" && r["outbound"] == "node-n2" {
				idxLisN2 = i
			}
			if ib[0] == "in-lis-dir" && r["outbound"] == "direct" {
				idxLisDir = i
			}
		}
		if r["clash_mode"] == "Global" {
			idxGlobal = i
		}
		if pr, ok := r["protocol"].([]any); ok && len(pr) == 1 && pr[0] == "stun" && r["outbound"] == "proxy" {
			idxWebRTCProxy = i
		}
	}
	if idxLisN2 < 0 || idxLisDir < 0 || idxGlobal < 0 || idxWebRTCProxy < 0 {
		t.Fatalf("missing expected rules in route.rules: n2=%d dir=%d global=%d webrtc=%d", idxLisN2, idxLisDir, idxGlobal, idxWebRTCProxy)
	}
	if idxLisN2 >= idxGlobal || idxLisDir >= idxGlobal {
		t.Fatalf("expected dedicated listener inbound rules (%d, %d) BEFORE clash_mode Global (%d)", idxLisN2, idxLisDir, idxGlobal)
	}
	if idxWebRTCProxy >= idxGlobal {
		t.Fatalf("expected WebRTC proxy rule (%d) BEFORE clash_mode Global (%d)", idxWebRTCProxy, idxGlobal)
	}

	// Verify Simulator honors WebRTC modes + extended rules.
	simBlock := ruleset.Simulate(ruleset.RoutingProfile{Mode: "rule", BypassCN: true, WebRTCMode: "block"}, ruleset.SimulationInput{
		Domain: "stun.qq.com", Network: "udp", Port: 3478,
	})
	if simBlock.Outbound != "block" || simBlock.Action != "reject" {
		t.Fatalf("expected webrtc_mode=block to reject stun.qq.com, got %+v", simBlock)
	}
	simProxy := ruleset.Simulate(ruleset.RoutingProfile{Mode: "rule", BypassCN: true, WebRTCMode: "proxy"}, ruleset.SimulationInput{
		Protocol: "stun", Network: "udp", Port: 19302,
	})
	if simProxy.Outbound != "proxy" {
		t.Fatalf("expected webrtc_mode=proxy to steer STUN to proxy before BypassCN, got %+v", simProxy)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-ext.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with extended rules & listener bindings: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileIPv4PreResolveForProxyOutbounds(t *testing.T) {
	in := CompileInput{
		Nodes: []*config.Node{
			{ID: "n1", Name: "Primary", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none"},
		},
		Listeners: []*config.ListenConfig{
			{ID: "lis-n1", Name: "Side", Protocol: "mixed", Address: "127.0.0.1", Port: 2082, NodeIDs: []string{"n1"}, Enabled: true},
		},
		Routing: ruleset.RoutingProfile{
			Mode:           "rule",
			BypassCN:       true,
			DomainStrategy: "prefer_ipv4",
			LocalDNS:       "223.5.5.5",
			RemoteDNS:      "https://dns.google/dns-query",
			CustomRules: []ruleset.RoutingRule{
				{ID: "p1", Name: "Proxy Domain", Enabled: true, DomainSuffix: []string{"ippure.com"}, Outbound: "proxy"},
				{ID: "d1", Name: "Direct Domain", Enabled: true, DomainSuffix: []string{"example.cn"}, Outbound: "direct"},
			},
		},
		RuleSets:     ruleset.BuiltinRuleSets(""),
		ActiveNodeID: "n1",
		MixedPort:    10808,
		ClashAPIPort: 9090,
	}

	// Both prefer_ipv4 and ipv4_only must emit the 4 ipv4_only resolve rules (listener, global,
	// custom proxy, final) so domain-targeted proxy flows (e.g. Chrome HTTP CONNECT via mixed-in)
	// resolve to IPv4 via remote-dns and never hit broken remote IPv6 / domain filters on ippure.com.
	assertResolveRules := func(label string, raw []byte) {
		t.Helper()
		var doc struct {
			Route struct {
				Rules []map[string]any `json:"rules"`
			} `json:"route"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		var resolveCount, directResolveCount int
		for _, r := range doc.Route.Rules {
			if r["action"] == "resolve" && r["server"] == "remote-dns" && r["strategy"] == "ipv4_only" {
				resolveCount++
				if ds, ok := r["domain_suffix"].([]any); ok && len(ds) == 1 && ds[0] == "example.cn" {
					directResolveCount++
				}
			}
		}
		if resolveCount != 4 {
			t.Fatalf("[%s] expected 4 ipv4_only resolve rules (listener, global, custom proxy, final), got %d in %+v", label, resolveCount, doc.Route.Rules)
		}
		if directResolveCount != 0 {
			t.Fatalf("[%s] did not expect direct custom rule to pre-resolve via remote-dns", label)
		}
		last := doc.Route.Rules[len(doc.Route.Rules)-1]
		if last["action"] != "resolve" || last["strategy"] != "ipv4_only" || len(last) != 3 {
			t.Fatalf("[%s] expected final catch-all ipv4_only resolve rule at tail of route.rules, got %+v", label, last)
		}
	}

	prefOut, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile prefer_ipv4 failed: %v", err)
	}
	assertResolveRules("prefer_ipv4", prefOut.Raw)
	// Legacy domain-based DoH ("https://dns.google/dns-query") must bootstrap via doh-bootstrap-dns hosts.
	if !strings.Contains(string(prefOut.Raw), `"tag": "doh-bootstrap-dns"`) || !strings.Contains(string(prefOut.Raw), `"domain_resolver": "doh-bootstrap-dns"`) {
		t.Fatalf("expected doh-bootstrap-dns hosts resolver for domain-based DoH, got:\n%s", string(prefOut.Raw))
	}

	v4In := in
	v4In.Routing.DomainStrategy = "ipv4_only"
	out, err := Compile(v4In)
	if err != nil {
		t.Fatalf("Compile ipv4_only failed: %v", err)
	}
	assertResolveRules("ipv4_only", out.Raw)

	v6In := in
	v6In.Routing.DomainStrategy = "prefer_ipv6"
	v6Out, err := Compile(v6In)
	if err != nil {
		t.Fatalf("Compile prefer_ipv6 failed: %v", err)
	}
	if strings.Contains(string(v6Out.Raw), `"ipv4_only"`) {
		t.Fatalf("did not expect ipv4_only strategy under prefer_ipv6")
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		for name, raw := range map[string][]byte{"prefer_ipv4": prefOut.Raw, "ipv4_only": out.Raw} {
			cfgPath := filepath.Join(t.TempDir(), "sing-box-"+name+".json")
			if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed (%s): %v\n%s\n%s", name, err, output, string(raw))
			}
		}
	}
}

func TestCompileNodeDetourChainAndCycleDetection(t *testing.T) {
	relay1 := &config.Node{
		ID: "relay-hk", Name: "HK Relay", Protocol: config.ProtocolVLESS,
		Address: "hk.example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111",
		Network: "tcp", Security: "tls", Sni: "hk.example.com",
	}
	relay2 := &config.Node{
		ID: "relay-jp", Name: "JP Relay", Protocol: config.ProtocolTrojan,
		Address: "jp.example.com", Port: 443, Password: "secret",
		Network: "tcp", Security: "tls", Sni: "jp.example.com",
	}
	gcp := &config.Node{
		ID: "gcp-us", Name: "GCP US", Protocol: config.ProtocolVLESS,
		Address: "198.51.100.10", Port: 443, UUID: "22222222-2222-2222-2222-222222222222",
		Network: "tcp", Security: "reality", Sni: "www.apple.com",
		PublicKey: "testpubkey123456789012345678901234567890123", ShortID: "a1b2c3d4",
		Flow: "xtls-rprx-vision", DetourID: "grp-fast",
	}
	directDetour := &config.Node{
		ID: "landing-2", Name: "Landing 2", Protocol: config.ProtocolVLESS,
		Address: "us2.example.com", Port: 443, UUID: "33333333-3333-3333-3333-333333333333",
		Network: "tcp", Security: "tls", Sni: "us2.example.com", DetourID: "relay-hk",
	}
	groups := []storage.Group{
		{ID: "grp-fast", Name: "Fast Auto", Strategy: "urltest", NodeIDs: []string{"relay-hk", "relay-jp"}},
		{ID: "grp-lb", Name: "LB Group", Strategy: "loadbalance", NodeIDs: []string{"relay-hk", "relay-jp"}},
	}
	nodes := []*config.Node{relay1, relay2, gcp, directDetour}

	// Valid detour targets (urltest group and single node).
	if err := ValidateDetourTarget("gcp-us", "grp-fast", nodes, groups); err != nil {
		t.Fatalf("expected grp-fast detour valid, got %v", err)
	}
	if err := ValidateDetourTarget("landing-2", "relay-hk", nodes, groups); err != nil {
		t.Fatalf("expected relay-hk detour valid, got %v", err)
	}
	// Reject self-loop, loadbalance group, direct node cycle, and group cycle.
	if err := ValidateDetourTarget("gcp-us", "gcp-us", nodes, groups); err == nil {
		t.Fatal("expected self-loop detour to fail")
	}
	if err := ValidateDetourTarget("gcp-us", "grp-lb", nodes, groups); err == nil {
		t.Fatal("expected loadbalance group detour to fail")
	}
	if err := ValidateDetourTarget("relay-hk", "landing-2", nodes, groups); err == nil {
		t.Fatal("expected node-to-node cycle detour to fail")
	}
	if err := ValidateDetourTarget("relay-hk", "gcp-us", nodes, groups); err == nil {
		t.Fatal("expected group-mediated cycle detour to fail")
	}

	out, err := Compile(CompileInput{
		Nodes:        nodes,
		Groups:       groups,
		Routing:      ruleset.DefaultRoutingProfile(),
		RuleSets:     ruleset.BuiltinRuleSets(""),
		ActiveNodeID: "gcp-us",
		MixedPort:    10808,
		ClashAPIPort: 9090,
		ProtectPath:  "/tmp/protect.sock",
	})
	if err != nil {
		t.Fatalf("Compile with detour failed: %v", err)
	}

	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}

	gcpTag := NodeTag("gcp-us")
	fastGroupTag := GroupTag("grp-fast")
	relayHKTag := NodeTag("relay-hk")
	landing2Tag := NodeTag("landing-2")
	if !out.IncludedTags[gcpTag] || !out.IncludedTags[fastGroupTag] || !out.IncludedTags[relayHKTag] || !out.IncludedTags[landing2Tag] {
		t.Fatalf("missing compiled tags in IncludedTags: %+v", out.IncludedTags)
	}

	var checkedGCP, checkedLanding2 bool
	for _, ob := range doc.Outbounds {
		switch ob["tag"] {
		case gcpTag:
			checkedGCP = true
			if ob["detour"] != fastGroupTag {
				t.Fatalf("expected gcp detour=%q, got %+v", fastGroupTag, ob["detour"])
			}
			if _, hasProtect := ob["protect_path"]; hasProtect {
				t.Fatalf("expected protect_path stripped when detour is set: %+v", ob)
			}
		case landing2Tag:
			checkedLanding2 = true
			if ob["detour"] != relayHKTag {
				t.Fatalf("expected landing-2 detour=%q, got %+v", relayHKTag, ob["detour"])
			}
		}
	}
	if !checkedGCP || !checkedLanding2 {
		t.Fatalf("missing expected detour outbounds in compiled config")
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-detour.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with detour chain: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileGroupDetourThreeHopAndCycleDetection(t *testing.T) {
	hop1 := &config.Node{
		ID: "hop1-hk", Name: "HK Entry", Protocol: config.ProtocolVLESS,
		Address: "hk.example.com", Port: 443, UUID: "11111111-1111-1111-1111-111111111111",
		Network: "tcp", Security: "tls", Sni: "hk.example.com",
	}
	hop2 := &config.Node{
		ID: "hop2-jp", Name: "JP Mid", Protocol: config.ProtocolTrojan,
		Address: "jp.example.com", Port: 443, Password: "secret",
		Network: "tcp", Security: "tls", Sni: "jp.example.com",
	}
	landingDirect := &config.Node{
		ID: "land-us-a", Name: "US Landing A", Protocol: config.ProtocolVLESS,
		Address: "198.51.100.11", Port: 443, UUID: "22222222-2222-2222-2222-222222222222",
		Network: "tcp", Security: "tls", Sni: "us-a.example.com",
	}
	landingChained := &config.Node{
		ID: "land-us-b", Name: "US Landing B", Protocol: config.ProtocolVLESS,
		Address: "198.51.100.12", Port: 443, UUID: "33333333-3333-3333-3333-333333333333",
		Network: "tcp", Security: "tls", Sni: "us-b.example.com",
		DetourID: "hop2-jp",
	}
	nodes := []*config.Node{hop1, hop2, landingDirect, landingChained}
	groups := []storage.Group{
		// Deliberately set interval=1h (> 30m default idle_timeout) to verify auto idle_timeout fix.
		{ID: "grp-entry", Name: "Entry Auto", Strategy: "urltest", Interval: "1h", ToleranceMS: 50, NodeIDs: []string{"hop1-hk"}},
		{ID: "grp-landing", Name: "US Pool", Strategy: "selector", SelectedNodeID: "land-us-b", DetourID: "grp-entry", NodeIDs: []string{"land-us-a", "land-us-b"}},
	}

	if err := ValidateAllDetours(nodes, groups); err != nil {
		t.Fatalf("expected valid 3-hop group detour graph, got %v", err)
	}

	// Cycle check 1: grp-entry cannot detour back to grp-landing.
	cyclicGroups1 := []storage.Group{
		{ID: "grp-entry", Name: "Entry Auto", Strategy: "urltest", DetourID: "grp-landing", NodeIDs: []string{"hop1-hk"}},
		groups[1],
	}
	if err := ValidateAllDetours(nodes, cyclicGroups1); err == nil {
		t.Fatal("expected group-to-group detour cycle to be rejected")
	}

	// Cycle check 2: group detour pointing to one of its own members must fail.
	cyclicGroups2 := []storage.Group{
		groups[0],
		{ID: "grp-landing", Name: "US Pool", Strategy: "selector", DetourID: "land-us-a", NodeIDs: []string{"land-us-a", "land-us-b"}},
	}
	if err := ValidateAllDetours(nodes, cyclicGroups2); err == nil {
		t.Fatal("expected group detour pointing to own member to be rejected")
	}

	// Cycle check 3: 3-hop loop where hop2-jp detours back to grp-landing.
	hop2Loop := *hop2
	hop2Loop.DetourID = "grp-landing"
	if err := ValidateAllDetours([]*config.Node{hop1, &hop2Loop, landingDirect, landingChained}, groups); err == nil {
		t.Fatal("expected 3-hop loop through intermediate node to be rejected")
	}

	out, err := Compile(CompileInput{
		Nodes:         nodes,
		Groups:        groups,
		Routing:       ruleset.DefaultRoutingProfile(),
		RuleSets:      ruleset.BuiltinRuleSets(""),
		ActiveGroupID: "grp-landing",
		MixedPort:     10808,
		ClashAPIPort:  9090,
	})
	if err != nil {
		t.Fatalf("Compile 3-hop group detour failed: %v", err)
	}

	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	byTag := map[string]map[string]any{}
	for _, ob := range doc.Outbounds {
		if tag, ok := ob["tag"].(string); ok {
			byTag[tag] = ob
		}
	}

	// Verify two-layer urltest wrapper: group-grp-entry (selector) -> group-grp-entry-auto (urltest with idle_timeout=2h0m0s).
	entryOb := byTag[GroupTag("grp-entry")]
	if entryOb == nil || entryOb["type"] != "selector" || entryOb["default"] != GroupAutoTag("grp-entry") {
		t.Fatalf("expected grp-entry selector wrapper defaulting to %q, got %+v", GroupAutoTag("grp-entry"), entryOb)
	}
	entryAutoOb := byTag[GroupAutoTag("grp-entry")]
	if entryAutoOb == nil || entryAutoOb["type"] != "urltest" || entryAutoOb["idle_timeout"] != "2h0m0s" {
		t.Fatalf("expected grp-entry auto urltest with idle_timeout=2h0m0s for 1h interval, got %+v", entryAutoOb)
	}
	// Verify standalone landingDirect remains direct (no detour), while scoped clone detours via grp-entry.
	if _, hasStandaloneDetour := byTag[NodeTag("land-us-a")]["detour"]; hasStandaloneDetour {
		t.Fatalf("standalone land-us-a should not be mutated with group detour")
	}
	scopedA := byTag[GroupScopedNodeTag("land-us-a", "grp-landing")]
	if scopedA == nil || scopedA["detour"] != GroupTag("grp-entry") {
		t.Fatalf("expected 2-hop scoped land-us-a detour=%q, got %+v", GroupTag("grp-entry"), scopedA)
	}
	// Verify 3-hop chain: scoped land-us-b -> scoped hop2-jp -> grp-entry!
	scopedHop2Tag := GroupScopedNodeTag("hop2-jp", "grp-landing")
	scopedB := byTag[GroupScopedNodeTag("land-us-b", "grp-landing")]
	scopedHop2 := byTag[scopedHop2Tag]
	if scopedB == nil || scopedB["detour"] != scopedHop2Tag {
		t.Fatalf("expected 3-hop scoped land-us-b detour=%q, got %+v", scopedHop2Tag, scopedB)
	}
	if scopedHop2 == nil || scopedHop2["detour"] != GroupTag("grp-entry") {
		t.Fatalf("expected 3-hop scoped hop2-jp detour=%q, got %+v", GroupTag("grp-entry"), scopedHop2)
	}
	// Verify grp-landing selector points to scoped clones and default matches scoped land-us-b.
	landGrp := byTag[GroupTag("grp-landing")]
	if landGrp == nil || landGrp["default"] != GroupScopedNodeTag("land-us-b", "grp-landing") {
		t.Fatalf("expected grp-landing default=%q, got %+v", GroupScopedNodeTag("land-us-b", "grp-landing"), landGrp)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-3hop.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with 3-hop group detour: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileDesktopTUNLanBroadcastExclude(t *testing.T) {
	node := &config.Node{
		ID:       "n-lan-bcast",
		Name:     "LAN Broadcast Test",
		Protocol: config.ProtocolTrojan,
		Address:  "jp.example.com",
		Port:     443,
		Password: "secret",
		Security: "tls",
		Sni:      "jp.example.com",
	}
	profile := ruleset.DefaultRoutingProfile()
	profile.BypassLAN = true
	profile.AllowLANBroadcast = true

	out, err := Compile(CompileInput{
		Nodes:        []*config.Node{node},
		Routing:      profile,
		ActiveNodeID: node.ID,
		EnableTUN:    true,
		TUNStack:     "mixed",
	})
	if err != nil {
		t.Fatalf("Compile with AllowLANBroadcast failed: %v", err)
	}
	var parsed struct {
		Inbounds []struct {
			Tag                 string   `json:"tag"`
			RouteExcludeAddress []string `json:"route_exclude_address"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(out.Raw, &parsed); err != nil {
		t.Fatalf("unmarshal compiled config: %v", err)
	}
	var excludeSet map[string]bool
	for _, ib := range parsed.Inbounds {
		if ib.Tag == "tun-in" {
			excludeSet = make(map[string]bool, len(ib.RouteExcludeAddress))
			for _, cidr := range ib.RouteExcludeAddress {
				excludeSet[cidr] = true
			}
			break
		}
	}
	if excludeSet == nil {
		t.Fatal("missing tun-in inbound in desktop TUN config")
	}
	for _, want := range []string{"127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4"} {
		if !excludeSet[want] {
			t.Fatalf("expected desktop TUN route_exclude_address to include %s, got %v", want, excludeSet)
		}
	}
	// Private unicast ranges must stay inside Desktop TUN so router/Tailscale DNS (192.168.x.1,
	// 10.x.x.1, 100.100.100.100:53) reaches hijack-dns instead of leaking/poisoning OS DNS.
	for _, forbidden := range []string{"10.0.0.0/8", "100.64.0.0/10", "172.16.0.0/12", "192.168.0.0/16"} {
		if excludeSet[forbidden] {
			t.Fatalf("desktop TUN route_exclude_address must not exclude %s (breaks hijack-dns for LAN/Tailscale DNS)", forbidden)
		}
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-lan-bcast.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with desktop TUN LAN broadcast exclusions: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileGooglePlayAllowlistIPv6RejectAndAndroidAppRules(t *testing.T) {
	nodes := []*config.Node{
		{ID: "n1", Name: "Node 1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none"},
		{ID: "n2", Name: "Node 2", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Security: "none"},
		{ID: "n3", Name: "Node 3", Protocol: config.ProtocolSocks, Address: "198.51.100.3", Port: 1080, Security: "none"},
		{ID: "n4", Name: "Node 4", Protocol: config.ProtocolSocks, Address: "198.51.100.4", Port: 1080, Security: "none"},
		{ID: "n5", Name: "Node 5", Protocol: config.ProtocolSocks, Address: "198.51.100.5", Port: 1080, Security: "none"},
	}
	groups := []storage.Group{
		{ID: "g-lb", Name: "LB Pool", Strategy: "loadbalance", NodeIDs: []string{"n1", "n2", "n3", "n4", "n5"}},
	}
	profile := ruleset.DefaultRoutingProfile()
	profile.BlockAds = true
	profile.CustomRules = []ruleset.RoutingRule{
		{
			ID:          "app-play",
			Name:        "Play Store Direct",
			Enabled:     true,
			PackageName: []string{"com.android.vending"},
			Outbound:    "proxy",
		},
	}

	out, err := Compile(CompileInput{
		Nodes:                 nodes,
		Groups:                groups,
		Routing:               profile,
		RuleSets:              ruleset.BuiltinRuleSets(""),
		ForceRemoteRules:      true,
		ActiveGroupID:         "g-lb",
		MixedPort:             10808,
		ClashAPIPort:          9090,
		AndroidMode:           true,
		AndroidAppSocksPort:   10899,
		AndroidAppSocksSecret: "testsecret",
		AndroidAppPackages:    []string{"com.android.vending"},
	})
	if err != nil {
		t.Fatalf("Compile Android comprehensive test failed: %v", err)
	}
	raw := string(out.Raw)

	// 1. Default RemoteDNS is literal IP DoH (1.1.1.1), so doh-bootstrap-dns is NOT needed.
	if strings.Contains(raw, `"tag": "doh-bootstrap-dns"`) {
		t.Fatalf("did not expect doh-bootstrap-dns when RemoteDNS is literal IP 1.1.1.1")
	}
	// 2. BlockAds rule must allowlist Google Play / Play Points domains via logical and + invert.
	if !strings.Contains(raw, `"play.googleapis.com"`) || !strings.Contains(raw, `"invert": true`) {
		t.Fatalf("expected BlockAds logical allowlist for Google Play domains, got:\n%s", raw)
	}
	// 3. Load-balance must cap shards at MaxLoadBalanceShards (4), default interval 10m, and pin Google/ippure.com to shard 0 (lb-shard-g-lb-0 -> node-n1).
	if strings.Contains(raw, `"outbound": "node-n5"`) || strings.Contains(raw, `"lb-shard-g-lb-4"`) {
		t.Fatalf("expected loadbalance shard count capped at %d, found node-n5 / lb-shard-g-lb-4 route", MaxLoadBalanceShards)
	}
	if !strings.Contains(raw, `"interval": "10m"`) {
		t.Fatalf("expected loadbalance default interval 10m, got:\n%s", raw)
	}
	if !strings.Contains(raw, `"ippure.com"`) || !strings.Contains(raw, `"outbound": "lb-shard-g-lb-0"`) || !strings.Contains(raw, `"default": "node-n1"`) {
		t.Fatalf("expected loadbalance session affinity pinning ippure.com/Google to shard 0 selector (lb-shard-g-lb-0 -> node-n1), got:\n%s", raw)
	}
	// 4. Android non-IPv6 mode must reject global IPv6 (2000::/3) inside sing-box so carrier IPv6 cannot leak.
	if !strings.Contains(raw, `"2000::/3"`) {
		t.Fatalf("expected Android IPv6 anti-leak reject rule for 2000::/3 when IPv6 disabled, got:\n%s", raw)
	}
	// 5. Android package_name rule must compile to auth_user + android-app-in SOCKS5 inbound.
	if !strings.Contains(raw, `"tag": "android-app-in"`) || !strings.Contains(raw, `"auth_user":`) || !strings.Contains(raw, `"com.android.vending"`) {
		t.Fatalf("expected android-app-in SOCKS5 inbound and auth_user rule for package_name, got:\n%s", raw)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-android-full.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with Android app rules + LB affinity + BlockAds allowlist: %v\n%s\n%s", err, output, raw)
		}
	}
}

func TestCompileRuleSetsGatedOnLocalSRS(t *testing.T) {
	node := &config.Node{
		ID:       "n1",
		Name:     "Node 1",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.1",
		Port:     1080,
		Security: "none",
	}
	profile := ruleset.DefaultRoutingProfile()
	profile.BlockAds = true
	profile.BypassCN = true

	// Without local .srs files on disk and ForceRemoteRules=false, neither BlockAds nor BypassCN rules may be emitted.
	emptyDir := t.TempDir()
	out, err := Compile(CompileInput{
		Nodes:            []*config.Node{node},
		Routing:          profile,
		RuleSets:         ruleset.BuiltinRuleSets(emptyDir),
		ForceRemoteRules: false,
		ActiveNodeID:     node.ID,
		MixedPort:        10808,
		ClashAPIPort:     9090,
	})
	if err != nil {
		t.Fatalf("Compile with missing local .srs failed: %v", err)
	}
	raw := string(out.Raw)
	for _, forbidden := range []string{`"geosite-category-ads-all"`, `"geosite-cn"`, `"geoip-cn"`, `"play.googleapis.com"`, `"rule_set"`} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("did not expect %s when local .srs files are missing, got:\n%s", forbidden, raw)
		}
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-missing-srs.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with missing .srs gated out: %v\n%s\n%s", err, output, raw)
		}
	}
}

func TestCompileHybridURLTestAndFailoverManualPin(t *testing.T) {
	nodes := []*config.Node{
		{ID: "n1", Name: "Node 1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none"},
		{ID: "n2", Name: "Node 2", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Security: "none"},
	}
	groups := []storage.Group{
		{ID: "g-url-auto", Name: "URL Auto", Strategy: "urltest", SelectedNodeID: "n1", ManualPin: false, NodeIDs: []string{"n1", "n2"}},
		{ID: "g-fail-pin", Name: "Failover Pinned", Strategy: "failover", SelectedNodeID: "n2", ManualPin: true, NodeIDs: []string{"n1", "n2"}},
	}

	out, err := Compile(CompileInput{
		Nodes:         nodes,
		Groups:        groups,
		Routing:       ruleset.DefaultRoutingProfile(),
		ActiveGroupID: "g-fail-pin",
		MixedPort:     10808,
		ClashAPIPort:  9090,
	})
	if err != nil {
		t.Fatalf("Compile hybrid urltest/failover failed: %v", err)
	}

	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	byTag := map[string]map[string]any{}
	for _, ob := range doc.Outbounds {
		if tag, ok := ob["tag"].(string); ok {
			byTag[tag] = ob
		}
	}

	// Unpinned urltest defaults to group-g-url-auto-auto despite legacy SelectedNodeID="n1".
	urlWrap := byTag[GroupTag("g-url-auto")]
	urlAuto := byTag[GroupAutoTag("g-url-auto")]
	if urlWrap == nil || urlWrap["type"] != "selector" || urlWrap["default"] != GroupAutoTag("g-url-auto") {
		t.Fatalf("expected unpinned urltest wrapper defaulting to auto, got %+v", urlWrap)
	}
	if urlAuto == nil || urlAuto["type"] != "urltest" {
		t.Fatalf("expected internal urltest outbound for g-url-auto, got %+v", urlAuto)
	}

	// Manually pinned failover defaults to pinned node-n2 while still including group-g-fail-pin-auto for fast revert.
	failWrap := byTag[GroupTag("g-fail-pin")]
	failAuto := byTag[GroupAutoTag("g-fail-pin")]
	if failWrap == nil || failWrap["type"] != "selector" || failWrap["default"] != NodeTag("n2") {
		t.Fatalf("expected pinned failover wrapper defaulting to node-n2, got %+v", failWrap)
	}
	if failAuto == nil || failAuto["type"] != "urltest" {
		t.Fatalf("expected internal urltest outbound for g-fail-pin, got %+v", failAuto)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-hybrid-groups.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with hybrid urltest/failover groups: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileAndroidPowerOptimizations(t *testing.T) {
	nodes := []*config.Node{
		{
			ID:                       "n-anytls",
			Name:                     "AnyTLS Mobile",
			Protocol:                 config.ProtocolAnyTLS,
			Address:                  "anytls.example.com",
			Port:                     443,
			Password:                 "secret-pass",
			Security:                 "tls",
			Sni:                      "anytls.example.com",
			IdleSessionCheckInterval: "30s",
			IdleSessionTimeout:       "30s",
			MinIdleSession:           5,
		},
		{
			ID:                "n-tuic",
			Name:              "TUIC Mobile",
			Protocol:          config.ProtocolTUIC,
			Address:           "tuic.example.com",
			Port:              443,
			UUID:              "11111111-1111-4111-8111-111111111111",
			Password:          "tuic-pass",
			Security:          "tls",
			Sni:               "tuic.example.com",
			CongestionControl: "bbr",
			Heartbeat:         "10s",
		},
	}
	groups := []storage.Group{
		{
			ID:       "g-failover",
			Name:     "Failover",
			Strategy: "failover",
			NodeIDs:  []string{"n-anytls", "n-tuic"},
		},
	}

	// Android mode: failover defaults to 5m, idle_timeout=10m, AnyTLS min_idle_session<=1 & check>=60s, TUIC heartbeat>=30s.
	androidOut, err := Compile(CompileInput{
		Nodes:         nodes,
		Groups:        groups,
		Routing:       ruleset.DefaultRoutingProfile(),
		ActiveGroupID: "g-failover",
		AndroidMode:   true,
	})
	if err != nil {
		t.Fatalf("Compile(AndroidMode=true) failed: %v", err)
	}
	var androidDoc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(androidOut.Raw, &androidDoc); err != nil {
		t.Fatalf("unmarshal android config: %v", err)
	}
	aByTag := map[string]map[string]any{}
	for _, ob := range androidDoc.Outbounds {
		if tag, ok := ob["tag"].(string); ok {
			aByTag[tag] = ob
		}
	}
	failAuto := aByTag[GroupAutoTag("g-failover")]
	if failAuto == nil || failAuto["interval"] != "5m" || failAuto["idle_timeout"] != "10m0s" {
		t.Fatalf("expected Android failover interval=5m and idle_timeout=10m0s, got %+v", failAuto)
	}
	anyOb := aByTag[NodeTag("n-anytls")]
	if anyOb == nil || anyOb["idle_session_check_interval"] != "60s" || anyOb["min_idle_session"] != float64(1) {
		t.Fatalf("expected Android AnyTLS check_interval=60s and min_idle_session=1, got %+v", anyOb)
	}
	tuicOb := aByTag[NodeTag("n-tuic")]
	if tuicOb == nil || tuicOb["heartbeat"] != "30s" {
		t.Fatalf("expected Android TUIC heartbeat clamped to 30s, got %+v", tuicOb)
	}

	// Desktop mode (AndroidMode=false): protocol keepalive params remain untouched.
	desktopOut, err := Compile(CompileInput{
		Nodes:         nodes,
		Groups:        groups,
		Routing:       ruleset.DefaultRoutingProfile(),
		ActiveGroupID: "g-failover",
		AndroidMode:   false,
	})
	if err != nil {
		t.Fatalf("Compile(AndroidMode=false) failed: %v", err)
	}
	var desktopDoc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(desktopOut.Raw, &desktopDoc); err != nil {
		t.Fatalf("unmarshal desktop config: %v", err)
	}
	dByTag := map[string]map[string]any{}
	for _, ob := range desktopDoc.Outbounds {
		if tag, ok := ob["tag"].(string); ok {
			dByTag[tag] = ob
		}
	}
	dAny := dByTag[NodeTag("n-anytls")]
	if dAny == nil || dAny["idle_session_check_interval"] != "30s" || dAny["min_idle_session"] != float64(5) {
		t.Fatalf("expected Desktop AnyTLS keepalive untouched (30s / 5), got %+v", dAny)
	}
	dTuic := dByTag[NodeTag("n-tuic")]
	if dTuic == nil || dTuic["heartbeat"] != "10s" {
		t.Fatalf("expected Desktop TUIC heartbeat untouched (10s), got %+v", dTuic)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-android-power.json")
		if err := os.WriteFile(cfgPath, androidOut.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with Android power optimizations: %v\n%s\n%s", err, output, string(androidOut.Raw))
		}
	}
}

func TestCompileCustomRulesMasterToggleAndGooglePlayBypassCNExemption(t *testing.T) {
	node := &config.Node{
		ID:       "n-play",
		Name:     "Play Node",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.40",
		Port:     1080,
		Security: "none",
	}

	// Build a profile with an enabled custom rule, but master switch CustomRulesEnabled=false.
	profile := ruleset.DefaultRoutingProfile()
	profile.BlockAds = true
	profile.BypassCN = true
	profile.CustomRulesEnabled = ruleset.BoolPtr(false)
	profile.CustomRules = []ruleset.RoutingRule{
		{
			ID:           "r-pause",
			Name:         "Paused Custom Rule",
			Enabled:      true,
			DomainSuffix: []string{"paused-custom.example"},
			Outbound:     "direct",
		},
	}

	for _, fakeIP := range []bool{false, true} {
		profile.FakeIP = fakeIP
		out, err := Compile(CompileInput{
			Nodes:            []*config.Node{node},
			Routing:          profile,
			RuleSets:         ruleset.BuiltinRuleSets(t.TempDir()),
			ForceRemoteRules: true,
			ActiveNodeID:     node.ID,
			AndroidMode:      true,
		})
		if err != nil {
			t.Fatalf("Compile(fakeIP=%v) failed: %v", fakeIP, err)
		}
		raw := string(out.Raw)
		if strings.Contains(raw, "paused-custom.example") {
			t.Fatalf("expected CustomRulesEnabled=false to skip custom rules (fakeIP=%v), got:\n%s", fakeIP, raw)
		}

		// Verify BOTH dns.rules (geosite-cn -> local-dns) AND route.rules (BypassCN -> direct)
		// exempt Google Play download CDN domains (gvt1.com, xn--ngstr-lra8j.com, dl.google.com).
		var doc struct {
			DNS struct {
				Rules []map[string]any `json:"rules"`
			} `json:"dns"`
			Route struct {
				Rules []map[string]any `json:"rules"`
			} `json:"route"`
		}
		if err := json.Unmarshal(out.Raw, &doc); err != nil {
			t.Fatalf("unmarshal config: %v", err)
		}

		hasPlayExemptLogical := func(rules []map[string]any, expectKey, expectVal string) bool {
			for _, r := range rules {
				if r["type"] != "logical" || r["mode"] != "and" || r[expectKey] != expectVal {
					continue
				}
				subRaw, _ := json.Marshal(r["rules"])
				sub := string(subRaw)
				if strings.Contains(sub, `"geosite-cn"`) &&
					strings.Contains(sub, `"gvt1.com"`) &&
					strings.Contains(sub, `"xn--ngstr-lra8j.com"`) &&
					strings.Contains(sub, `"dl.google.com"`) &&
					strings.Contains(sub, `"invert":true`) {
					return true
				}
			}
			return false
		}
		if !hasPlayExemptLogical(doc.DNS.Rules, "server", "local-dns") {
			t.Fatalf("expected DNS geosite-cn -> local-dns logical rule exempting Google Play CDN domains (fakeIP=%v), got:\n%s", fakeIP, raw)
		}
		if !hasPlayExemptLogical(doc.Route.Rules, "outbound", "direct") {
			t.Fatalf("expected Route BypassCN -> direct logical rule exempting Google Play CDN domains (fakeIP=%v), got:\n%s", fakeIP, raw)
		}

		if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
			cfgPath := filepath.Join(t.TempDir(), fmt.Sprintf("sing-box-play-fakeip-%v.json", fakeIP))
			if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
				t.Fatalf("sing-box check failed (fakeIP=%v): %v\n%s\n%s", fakeIP, err, output, raw)
			}
		}
	}

	// Re-enabling master switch emits the custom rule again.
	profile.FakeIP = false
	profile.CustomRulesEnabled = ruleset.BoolPtr(true)
	enabledOut, err := Compile(CompileInput{
		Nodes:        []*config.Node{node},
		Routing:      profile,
		ActiveNodeID: node.ID,
	})
	if err != nil {
		t.Fatalf("Compile(CustomRulesEnabled=true) failed: %v", err)
	}
	if !strings.Contains(string(enabledOut.Raw), "paused-custom.example") {
		t.Fatalf("expected CustomRulesEnabled=true to emit custom rule, got:\n%s", string(enabledOut.Raw))
	}
}

func TestCompileFailoverTriggerTolerance(t *testing.T) {
	nodes := []*config.Node{
		{ID: "n1", Name: "Primary", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Security: "none"},
		{ID: "n2", Name: "Backup", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Security: "none"},
	}
	groups := []storage.Group{
		{
			ID:              "g-unavail",
			Name:            "Failover Unavailable Only",
			Strategy:        "failover",
			FailoverTrigger: "unavailable_only",
			HighLatencyMS:   450,
			NodeIDs:         []string{"n1", "n2"},
		},
		{
			ID:              "g-custom-ms",
			Name:            "Failover Custom Latency",
			Strategy:        "failover",
			FailoverTrigger: "high_latency_or_unavailable",
			HighLatencyMS:   600,
			NodeIDs:         []string{"n1", "n2"},
		},
		{
			ID:              "g-inherit-ms",
			Name:            "Failover Inherit Global Latency",
			Strategy:        "failover",
			FailoverTrigger: "high_latency_or_unavailable",
			HighLatencyMS:   0,
			NodeIDs:         []string{"n1", "n2"},
		},
	}

	out, err := Compile(CompileInput{
		Nodes:         nodes,
		Groups:        groups,
		Routing:       ruleset.DefaultRoutingProfile(),
		ActiveGroupID: "g-unavail",
		HighLatencyMS: 950,
	})
	if err != nil {
		t.Fatalf("Compile failover triggers failed: %v", err)
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	tolerances := map[string]int{}
	for _, ob := range doc.Outbounds {
		if ob["type"] == "urltest" {
			tag, _ := ob["tag"].(string)
			tol, _ := ob["tolerance"].(float64)
			tolerances[tag] = int(tol)
		}
	}
	if tolerances["group-g-unavail-auto"] != 65535 {
		t.Fatalf("expected unavailable_only tolerance=65535, got %d (%+v)", tolerances["group-g-unavail-auto"], tolerances)
	}
	if tolerances["group-g-custom-ms-auto"] != 600 {
		t.Fatalf("expected custom high_latency_ms tolerance=600, got %d (%+v)", tolerances["group-g-custom-ms-auto"], tolerances)
	}
	if tolerances["group-g-inherit-ms-auto"] != 950 {
		t.Fatalf("expected inherited global HighLatencyMS tolerance=950, got %d (%+v)", tolerances["group-g-inherit-ms-auto"], tolerances)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-failover-triggers.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed for failover triggers: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}
}

func TestCompileTailscaleParallelMeshAndHeadscale(t *testing.T) {
	node := &config.Node{
		ID:       "n1",
		Name:     "Relay HK",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.1",
		Port:     1080,
		Security: "none",
	}
	profile := ruleset.DefaultRoutingProfile()
	profile.Mode = "global"
	profile.BypassLAN = true
	profile.FakeIP = true
	profile.CustomRules = []ruleset.RoutingRule{
		{
			ID:           "r-ts",
			Name:         "Internal App via Tailscale",
			Enabled:      true,
			DomainSuffix: []string{"corp.internal"},
			Outbound:     ruleset.TailscaleEndpointTag,
		},
	}

	tsCfg := ruleset.TailscaleConfig{
		Enabled:      true,
		ControlURL:   "https://headscale.example.com",
		AuthKey:      "tskey-auth-test-secret",
		Hostname:     "prismray-test",
		AcceptRoutes: true,
		MagicDNS:     true,
		ExtraDomains: []string{"corp.internal"},
		ExtraSubnets: []string{"10.240.0.0/16"},
		DetourID:     "n1",
		UDPTimeout:   "5m",
		Ephemeral:    true,
	}

	out, err := Compile(CompileInput{
		Nodes:             []*config.Node{node},
		Routing:           profile,
		Tailscale:         &tsCfg,
		TailscaleStateDir: filepath.Join(t.TempDir(), "ts-state"),
		ActiveNodeID:      node.ID,
		MixedPort:         10808,
		ClashAPIPort:      9090,
	})
	if err != nil {
		t.Fatalf("Compile with Tailscale failed: %v", err)
	}

	var doc struct {
		Endpoints []map[string]any `json:"endpoints"`
		DNS       struct {
			Servers []map[string]any `json:"servers"`
			Rules   []map[string]any `json:"rules"`
		} `json:"dns"`
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatalf("unmarshal tailscale config: %v", err)
	}
	if len(doc.Endpoints) != 1 {
		t.Fatalf("expected 1 tailscale endpoint, got %d", len(doc.Endpoints))
	}
	ep := doc.Endpoints[0]
	if ep["type"] != "tailscale" || ep["tag"] != ruleset.TailscaleEndpointTag || ep["control_url"] != "https://headscale.example.com" || ep["detour"] != "node-n1" {
		t.Fatalf("unexpected tailscale endpoint: %+v", ep)
	}

	foundTSDNS := false
	for _, srv := range doc.DNS.Servers {
		if srv["type"] == "tailscale" && srv["tag"] == ruleset.TailscaleDNSTag && srv["endpoint"] == ruleset.TailscaleEndpointTag {
			foundTSDNS = true
		}
	}
	if !foundTSDNS {
		t.Fatalf("expected tailscale MagicDNS server %q in dns.servers: %+v", ruleset.TailscaleDNSTag, doc.DNS.Servers)
	}

	idxTSRoute, idxGlobal, idxBypassLAN := -1, -1, -1
	for i, r := range doc.Route.Rules {
		if r["outbound"] == ruleset.TailscaleEndpointTag && idxTSRoute < 0 {
			if cidrs, ok := r["ip_cidr"].([]any); ok && len(cidrs) >= 2 {
				idxTSRoute = i
			}
		}
		if r["clash_mode"] == "Global" && idxGlobal < 0 {
			idxGlobal = i
		}
		if r["ip_is_private"] == true && r["outbound"] == "direct" && idxBypassLAN < 0 {
			idxBypassLAN = i
		}
	}
	if idxTSRoute < 0 || idxGlobal < 0 {
		t.Fatalf("missing tailscale route (%d) or Global (%d) in route.rules: %+v", idxTSRoute, idxGlobal, doc.Route.Rules)
	}
	if idxTSRoute >= idxGlobal {
		t.Fatalf("expected Tailscale mesh route (%d) BEFORE clash_mode Global (%d)", idxTSRoute, idxGlobal)
	}
	if idxBypassLAN >= 0 && idxTSRoute >= idxBypassLAN {
		t.Fatalf("expected Tailscale mesh route (%d) BEFORE BypassLAN (%d)", idxTSRoute, idxBypassLAN)
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-tailscale.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed for Tailscale parallel mesh config: %v\n%s\n%s", err, output, string(out.Raw))
		}
	}

	// Regression test: direct Tailscale (empty DetourID) must omit "detour" (sing-box rejects
	// detouring to an empty direct outbound) and attach protect_path on Android.
	tsDirect := ruleset.TailscaleConfig{
		Enabled:      true,
		AuthKey:      "tskey-auth-direct",
		Hostname:     "prismray-direct",
		AcceptRoutes: true,
		MagicDNS:     true,
		UDPTimeout:   "5m",
	}
	directOut, err := Compile(CompileInput{
		Nodes:             []*config.Node{node},
		Routing:           profile,
		Tailscale:         &tsDirect,
		TailscaleStateDir: filepath.Join(t.TempDir(), "ts-direct-state"),
		ActiveNodeID:      node.ID,
		MixedPort:         10808,
		ClashAPIPort:      9090,
		AndroidMode:       true,
		ProtectPath:       "/tmp/protect.sock",
	})
	if err != nil {
		t.Fatalf("Compile with direct Tailscale failed: %v", err)
	}
	var directDoc struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal(directOut.Raw, &directDoc); err != nil {
		t.Fatalf("unmarshal direct tailscale config: %v", err)
	}
	if len(directDoc.Endpoints) != 1 {
		t.Fatalf("expected 1 direct tailscale endpoint, got %d", len(directDoc.Endpoints))
	}
	dep := directDoc.Endpoints[0]
	if _, hasDetour := dep["detour"]; hasDetour {
		t.Fatalf("direct tailscale endpoint must not emit detour: %+v", dep)
	}
	if dep["protect_path"] != "/tmp/protect.sock" {
		t.Fatalf("expected protect_path on Android direct tailscale endpoint, got %+v", dep)
	}
}

func TestCompileCustomLoadBalanceShardCount(t *testing.T) {
	nodes := make([]*config.Node, 0, 7)
	nodeIDs := make([]string, 0, 7)
	for i := 1; i <= 7; i++ {
		id := fmt.Sprintf("n%d", i)
		nodeIDs = append(nodeIDs, id)
		nodes = append(nodes, &config.Node{
			ID:       id,
			Name:     "Node " + id,
			Protocol: config.ProtocolSocks,
			Address:  fmt.Sprintf("198.51.100.%d", i),
			Port:     1080,
			Latency:  20 + i*5,
		})
	}
	groups := []storage.Group{
		{
			ID:                "g-lb-6",
			Name:              "LB 6 Shards",
			Strategy:          "loadbalance",
			LoadBalanceShards: 6,
			NodeIDs:           nodeIDs,
		},
	}
	out, err := Compile(CompileInput{
		Nodes:         nodes,
		Groups:        groups,
		Routing:       ruleset.DefaultRoutingProfile(),
		ActiveGroupID: "g-lb-6",
		MixedPort:     10808,
		ClashAPIPort:  9090,
	})
	if err != nil {
		t.Fatalf("Compile custom 6-shard loadbalance failed: %v", err)
	}
	raw := string(out.Raw)
	for i := 0; i < 6; i++ {
		wantRoute := fmt.Sprintf(`"outbound": "lb-shard-g-lb-6-%d"`, i)
		wantDefault := fmt.Sprintf(`"default": "node-n%d"`, i+1)
		if !strings.Contains(raw, wantRoute) || !strings.Contains(raw, wantDefault) {
			t.Fatalf("expected shard %d (%s & %s) in compiled config", i, wantRoute, wantDefault)
		}
	}
	if strings.Contains(raw, `"lb-shard-g-lb-6-6"`) || strings.Contains(raw, `"default": "node-n7"`) {
		t.Fatalf("expected custom 6-shard cap to exclude node-n7 from shard wrappers & route rules")
	}
	if regexes := BuildDomainHashBucketRegexes(6); len(regexes) != 6 {
		t.Fatalf("expected 6 bucket regexes, got %d", len(regexes))
	}
	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-lb6.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed for 6-shard loadbalance: %v\n%s", err, output)
		}
	}
}

func TestCompileIPv6DisabledDNSPrecedesDirectGlobalAndCN(t *testing.T) {
	disable := true
	routing := ruleset.DefaultRoutingProfile()
	routing.Mode = "rule"
	routing.DisableIPv6 = &disable
	routing.BypassCN = true
	routing.FakeIP = true

	node := &config.Node{
		ID:       "n1",
		Name:     "Node 1",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.10",
		Port:     1080,
	}
	rsDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(rsDir, "geosite-cn.srs"), []byte("srs"), 0o600)
	_ = os.WriteFile(filepath.Join(rsDir, "geoip-cn.srs"), []byte("srs"), 0o600)
	out, err := Compile(CompileInput{
		Nodes:        []*config.Node{node},
		Routing:      routing,
		ActiveNodeID: node.ID,
		RuleSets:     ruleset.BuiltinRuleSets(rsDir),
		MixedPort:    10808,
		ClashAPIPort: 9090,
		EnableTUN:    true,
	})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	dnsObj, _ := doc["dns"].(map[string]any)
	dnsRules, _ := dnsObj["rules"].([]any)
	aaaaIdx, directIdx, globalIdx, cnIdx := -1, -1, -1, -1
	for idx, raw := range dnsRules {
		m, _ := raw.(map[string]any)
		if m["action"] == "predefined" && m["rcode"] == "NOERROR" && aaaaIdx < 0 {
			aaaaIdx = idx
		}
		if m["clash_mode"] == "Direct" && directIdx < 0 {
			directIdx = idx
		}
		if m["clash_mode"] == "Global" && globalIdx < 0 {
			globalIdx = idx
		}
		if m["type"] == "logical" {
			if subRules, ok := m["rules"].([]any); ok {
				for _, sr := range subRules {
					sm, _ := sr.(map[string]any)
					if sm["rule_set"] == "geosite-cn" && cnIdx < 0 {
						cnIdx = idx
					}
				}
			}
		} else if m["rule_set"] == "geosite-cn" && cnIdx < 0 {
			cnIdx = idx
		}
	}
	if aaaaIdx < 0 {
		t.Fatalf("expected AAAA/HTTPS NOERROR predefined DNS rule when DisableIPv6=true")
	}
	if directIdx < 0 || globalIdx < 0 || cnIdx < 0 {
		t.Fatalf("expected Direct (%d), Global (%d), and geosite-cn (%d) DNS rules", directIdx, globalIdx, cnIdx)
	}
	if !(aaaaIdx < directIdx && aaaaIdx < globalIdx && aaaaIdx < cnIdx) {
		t.Fatalf("expected AAAA/HTTPS NOERROR rule (%d) BEFORE Direct (%d), Global (%d), and geosite-cn (%d)", aaaaIdx, directIdx, globalIdx, cnIdx)
	}

	// Verify route rules place BypassLAN (ip_is_private -> direct) and 2000::/3 -> reject BEFORE clash_mode: Global.
	routeObj, _ := doc["route"].(map[string]any)
	routeRules, _ := routeObj["rules"].([]any)
	lanIdx, ipv6RejectIdx, routeGlobalIdx := -1, -1, -1
	for idx, raw := range routeRules {
		m, _ := raw.(map[string]any)
		if m["outbound"] == "direct" && lanIdx < 0 {
			if priv, _ := m["ip_is_private"].(bool); priv {
				lanIdx = idx
			} else if cidrs, ok := m["ip_cidr"].([]any); ok {
				for _, c := range cidrs {
					if c == "192.168.0.0/16" {
						lanIdx = idx
						break
					}
				}
			}
		}
		if cidrs, ok := m["ip_cidr"].([]any); ok && m["action"] == "reject" {
			for _, c := range cidrs {
				if c == "2000::/3" && ipv6RejectIdx < 0 {
					ipv6RejectIdx = idx
				}
			}
		}
		if m["clash_mode"] == "Global" && routeGlobalIdx < 0 {
			routeGlobalIdx = idx
		}
	}
	if lanIdx < 0 || ipv6RejectIdx < 0 || routeGlobalIdx < 0 {
		t.Fatalf("expected lan (%d), ipv6 reject (%d), and Global (%d) route rules", lanIdx, ipv6RejectIdx, routeGlobalIdx)
	}
	if !(lanIdx < routeGlobalIdx && ipv6RejectIdx < routeGlobalIdx) {
		t.Fatalf("expected BypassLAN (%d) and 2000::/3 reject (%d) BEFORE Global (%d)", lanIdx, ipv6RejectIdx, routeGlobalIdx)
	}
}

func TestCompileSystemTailscaleCoexistence(t *testing.T) {
	bypassTS := true
	disableIPv6 := true
	routing := ruleset.DefaultRoutingProfile()
	routing.BypassSystemTailscale = &bypassTS
	routing.DisableIPv6 = &disableIPv6
	routing.WebRTCMode = "block"

	node := &config.Node{
		ID:       "n1",
		Name:     "Node 1",
		Protocol: config.ProtocolSocks,
		Address:  "198.51.100.10",
		Port:     1080,
	}
	out, err := Compile(CompileInput{
		Nodes:        []*config.Node{node},
		Routing:      routing,
		ActiveNodeID: node.ID,
		MixedPort:    10808,
		ClashAPIPort: 9090,
		EnableTUN:    true,
		SystemTailscale: &SystemTailscaleInfo{
			Detected:       true,
			Interface:      "tailscale0",
			IPv4:           "100.64.10.20",
			MagicDNSActive: true,
			SearchDomains:  []string{"tail1234.ts.net"},
		},
	})
	if err != nil {
		t.Fatalf("Compile with SystemTailscale failed: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// 1. DNS: system-tailscale-dns server exists (detouring to system-tailscale-direct) and its rule precedes AAAA/HTTPS NOERROR.
	dnsObj, _ := doc["dns"].(map[string]any)
	servers, _ := dnsObj["servers"].([]any)
	foundSysDNSServer := false
	for _, raw := range servers {
		m, _ := raw.(map[string]any)
		if m["tag"] == "system-tailscale-dns" && m["server"] == "100.100.100.100" && m["detour"] == "system-tailscale-direct" {
			foundSysDNSServer = true
		}
	}
	if !foundSysDNSServer {
		t.Fatalf("expected system-tailscale-dns server (100.100.100.100 -> system-tailscale-direct) in DNS config")
	}

	dnsRules, _ := dnsObj["rules"].([]any)
	sysTsDNSIdx, aaaaIdx := -1, -1
	for idx, raw := range dnsRules {
		m, _ := raw.(map[string]any)
		if m["server"] == "system-tailscale-dns" && sysTsDNSIdx < 0 {
			sysTsDNSIdx = idx
		}
		if m["action"] == "predefined" && m["rcode"] == "NOERROR" && aaaaIdx < 0 {
			aaaaIdx = idx
		}
	}
	if sysTsDNSIdx < 0 || aaaaIdx < 0 || sysTsDNSIdx > aaaaIdx {
		t.Fatalf("expected system-tailscale-dns rule (%d) BEFORE AAAA/HTTPS NOERROR (%d)", sysTsDNSIdx, aaaaIdx)
	}

	// 2. Route: 100.64.0.0/10 & fd7a:115c:a1e0::/48 route to system-tailscale-direct before Global; tailscaled UDP 3478 exempted direct before WebRTC reject.
	routeObj, _ := doc["route"].(map[string]any)
	routeRules, _ := routeObj["rules"].([]any)
	sysTsRouteIdx, globalIdx, stunExemptIdx, webrtcRejectIdx := -1, -1, -1, -1
	for idx, raw := range routeRules {
		m, _ := raw.(map[string]any)
		if m["outbound"] == "system-tailscale-direct" {
			if cidrs, ok := m["ip_cidr"].([]any); ok {
				hasCGNAT := false
				hasTS6 := false
				for _, c := range cidrs {
					if c == "100.64.0.0/10" {
						hasCGNAT = true
					}
					if c == "fd7a:115c:a1e0::/48" {
						hasTS6 = true
					}
				}
				if hasCGNAT && hasTS6 && sysTsRouteIdx < 0 {
					sysTsRouteIdx = idx
				}
			}
		}
		if m["outbound"] == "direct" {
			if procs, ok := m["process_name"].([]any); ok {
				for _, p := range procs {
					if p == "tailscaled" && stunExemptIdx < 0 {
						stunExemptIdx = idx
					}
				}
			}
		}
		if m["clash_mode"] == "Global" && globalIdx < 0 {
			globalIdx = idx
		}
		if m["action"] == "reject" {
			if ports, ok := m["port"].([]any); ok {
				for _, p := range ports {
					if f, ok := p.(float64); ok && int(f) == 3478 && webrtcRejectIdx < 0 {
						webrtcRejectIdx = idx
					}
				}
			}
		}
	}
	if sysTsRouteIdx < 0 || globalIdx < 0 || sysTsRouteIdx > globalIdx {
		t.Fatalf("expected System Tailscale CIDR direct rule (%d) BEFORE Global (%d)", sysTsRouteIdx, globalIdx)
	}
	if stunExemptIdx < 0 || webrtcRejectIdx < 0 || stunExemptIdx > webrtcRejectIdx {
		t.Fatalf("expected tailscaled UDP 3478 exemption (%d) BEFORE WebRTC reject (%d)", stunExemptIdx, webrtcRejectIdx)
	}
	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-sys-ts.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed for System Tailscale coexistence config: %v\n%s", err, output)
		}
	}
}

func TestCompileWebRTCProxyLocalDoHIMDSAndInvertedLBAffinity(t *testing.T) {
	disableIPv6 := true
	bypassTS := true
	routing := ruleset.DefaultRoutingProfile()
	routing.Mode = "rule"
	routing.WebRTCMode = "proxy"
	routing.BypassLAN = true
	routing.DisableIPv6 = &disableIPv6
	routing.BypassSystemTailscale = &bypassTS
	routing.LocalDNS = "https://dns.alidns.com/dns-query"
	routing.RemoteDNS = "https://dns.google/dns-query"
	routing.CustomRules = []ruleset.RoutingRule{
		{
			ID:           "inv-1",
			Name:         "Invert to LB",
			Enabled:      true,
			DomainSuffix: []string{"excluded.example"},
			Invert:       true,
			Outbound:     "g-lb",
		},
	}

	out, err := Compile(CompileInput{
		Nodes: []*config.Node{
			{ID: "n1", Name: "N1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Latency: 20},
			{ID: "n2", Name: "N2", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Latency: 30},
		},
		Groups: []storage.Group{
			{ID: "g-lb", Name: "LB", Strategy: "loadbalance", NodeIDs: []string{"n1", "n2"}},
		},
		Routing:       routing,
		ActiveGroupID: "g-lb",
		EnableTUN:     true,
		SystemTailscale: &SystemTailscaleInfo{
			Detected:  true,
			Interface: "tailscale0",
		},
	})
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
		t.Fatal(err)
	}

	// 1. Both local & remote DoH hosts populate doh-bootstrap-dns.
	dnsObj, _ := doc["dns"].(map[string]any)
	servers, _ := dnsObj["servers"].([]any)
	foundLocalDoH, foundMergedBootstrap := false, false
	for _, rawSrv := range servers {
		m, _ := rawSrv.(map[string]any)
		if m["tag"] == "local-dns" && m["domain_resolver"] == "doh-bootstrap-dns" {
			foundLocalDoH = true
		}
		if m["tag"] == "doh-bootstrap-dns" {
			pre, _ := m["predefined"].(map[string]any)
			if _, ok1 := pre["dns.alidns.com"]; ok1 {
				if _, ok2 := pre["dns.google"]; ok2 {
					foundMergedBootstrap = true
				}
			}
		}
	}
	if !foundLocalDoH || !foundMergedBootstrap {
		t.Fatalf("expected merged local/remote doh-bootstrap-dns (local=%v merged=%v)", foundLocalDoH, foundMergedBootstrap)
	}

	// 2. WebRTC proxy DNS rules resolve stun. and turn. via remote-dns.
	dnsRules, _ := dnsObj["rules"].([]any)
	hasStunDNS, hasTurnDNS := false, false
	for _, rawRule := range dnsRules {
		m, _ := rawRule.(map[string]any)
		if m["server"] == "remote-dns" {
			if _, ok := m["domain_keyword"]; ok {
				hasStunDNS = true
			}
			if _, ok := m["domain_regex"]; ok {
				hasTurnDNS = true
			}
		}
	}
	if !hasStunDNS || !hasTurnDNS {
		t.Fatalf("expected WebRTC proxy DNS stun/turn remote-dns rules, got stun=%v turn=%v", hasStunDNS, hasTurnDNS)
	}

	// 3. Route ordering: IMDS reject -> BypassLAN -> 2000::/3 reject -> tailscaled exempt -> WebRTC proxy -> inverted LB logical affinity.
	routeObj, _ := doc["route"].(map[string]any)
	routeRules, _ := routeObj["rules"].([]any)
	imdsIdx, lanIdx, v6Idx, tsExemptIdx, stunProxyIdx, turnTCPIdx := -1, -1, -1, -1, -1, -1
	invertedAffinityIsolated := false
	for idx, rawR := range routeRules {
		m, _ := rawR.(map[string]any)
		if cidrs, ok := m["ip_cidr"].([]any); ok && len(cidrs) > 0 && cidrs[0] == "169.254.169.254/32" && m["action"] == "reject" {
			imdsIdx = idx
		}
		if m["ip_is_private"] == true && m["outbound"] == "direct" && lanIdx < 0 {
			lanIdx = idx
		}
		if cidrs, ok := m["ip_cidr"].([]any); ok && len(cidrs) == 1 && cidrs[0] == "2000::/3" && m["action"] == "reject" {
			v6Idx = idx
		}
		if procs, ok := m["process_name"].([]any); ok && len(procs) > 0 && procs[0] == "tailscaled" && m["outbound"] == "direct" {
			tsExemptIdx = idx
		}
		if kw, ok := m["domain_keyword"].([]any); ok && len(kw) == 1 && kw[0] == "stun." && m["outbound"] == "lb-shard-g-lb-0" {
			stunProxyIdx = idx
		}
		if netList, ok := m["network"].([]any); ok && len(netList) == 1 && netList[0] == "tcp" && m["outbound"] == "lb-shard-g-lb-0" {
			turnTCPIdx = idx
		}
		if m["type"] == "logical" && m["mode"] == "and" && m["outbound"] == "lb-shard-g-lb-0" {
			if sub, ok := m["rules"].([]any); ok && len(sub) == 2 {
				s0, _ := sub[0].(map[string]any)
				s1, _ := sub[1].(map[string]any)
				if s0["invert"] == true && s1["domain_suffix"] != nil && s1["invert"] == nil {
					invertedAffinityIsolated = true
				}
			}
		}
	}
	if imdsIdx < 0 || lanIdx <= imdsIdx || v6Idx <= lanIdx || tsExemptIdx <= v6Idx || stunProxyIdx <= tsExemptIdx || turnTCPIdx < 0 {
		t.Fatalf("unexpected route order: imds=%d lan=%d v6=%d tsExempt=%d stunProxy=%d turnTCP=%d", imdsIdx, lanIdx, v6Idx, tsExemptIdx, stunProxyIdx, turnTCPIdx)
	}
	if !invertedAffinityIsolated {
		t.Fatalf("expected inverted custom rule affinity to isolate invert inside logical and subrule")
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-webrtc-proxy.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed: %v\n%s", err, output)
		}
	}

	// Custom local DoH domain emits system-local-bootstrap resolver.
	routing2 := ruleset.DefaultRoutingProfile()
	routing2.LocalDNS = "https://custom-doh.example.org/dns-query"
	out2, err := Compile(CompileInput{Nodes: []*config.Node{{ID: "n1", Name: "N1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080}}, Routing: routing2})
	if err != nil || !strings.Contains(string(out2.Raw), `"tag": "system-local-bootstrap"`) {
		t.Fatalf("expected system-local-bootstrap for custom local DoH domain, err=%v", err)
	}

	// Verify Simulator alignment with IMDS reject and BypassLAN > WebRTC > TURN TCP.
	if simIMDS := ruleset.Simulate(ruleset.RoutingProfile{Mode: "rule", BypassLAN: true}, ruleset.SimulationInput{IP: "169.254.169.254", Port: 80}); simIMDS.Action != "reject" {
		t.Fatalf("expected cloud metadata IP rejected in Simulate, got %+v", simIMDS)
	}
	if simLanStun := ruleset.Simulate(ruleset.RoutingProfile{Mode: "rule", BypassLAN: true, WebRTCMode: "proxy"}, ruleset.SimulationInput{IP: "192.168.1.20", Network: "udp", Port: 3478}); simLanStun.Outbound != "direct" {
		t.Fatalf("expected LAN UDP 3478 direct before WebRTC proxy, got %+v", simLanStun)
	}
	if simTurnTCP := ruleset.Simulate(ruleset.RoutingProfile{Mode: "rule", BypassCN: true, WebRTCMode: "proxy"}, ruleset.SimulationInput{Domain: "turn.qq.com", Network: "tcp", Port: 5349}); simTurnTCP.Outbound != "proxy" {
		t.Fatalf("expected TURN TCP 5349 proxied before BypassCN, got %+v", simTurnTCP)
	}
}
