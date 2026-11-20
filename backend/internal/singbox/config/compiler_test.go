// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
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
			if len(addrs) != 1 || addrs[0] != "172.19.0.1/30" {
				t.Fatalf("expected IPv4-only TUN address under prefer_ipv4, got %v", ib["address"])
			}
			excl, _ := ib["route_exclude_address"].([]any)
			if len(excl) != 1 || excl[0] != "127.0.0.0/8" {
				t.Fatalf("expected IPv4-only route_exclude_address under prefer_ipv4, got %v", ib["route_exclude_address"])
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

	// Expect logical domain_regex shard rules referencing only healthy nodes (node-n1 / node-n2), not dead node-n3.
	shardTargets := map[string]bool{}
	shardCount := 0
	for _, r := range doc.Route.Rules {
		if r["type"] == "logical" && r["mode"] == "and" {
			ob, _ := r["outbound"].(string)
			if ob == "node-n3" {
				t.Fatalf("expected dead node-n3 (latency=-1) to be excluded from loadbalance shards: %+v", r)
			}
			if ob == "node-n1" || ob == "node-n2" {
				shardTargets[ob] = true
				shardCount++
			}
		}
	}
	if shardCount != 2 || !shardTargets["node-n1"] || !shardTargets["node-n2"] {
		t.Fatalf("expected 2 healthy loadbalance shard rules (node-n1, node-n2), got count=%d targets=%v", shardCount, shardTargets)
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

	out, err := Compile(in)
	if err != nil {
		t.Fatalf("Compile prefer_ipv4 failed: %v", err)
	}
	var doc struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(out.Raw, &doc); err != nil {
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
		t.Fatalf("expected 4 ipv4_only resolve rules (listener, global, custom proxy, final), got %d in %+v", resolveCount, doc.Route.Rules)
	}
	if directResolveCount != 0 {
		t.Fatalf("did not expect direct custom rule to pre-resolve via remote-dns")
	}
	last := doc.Route.Rules[len(doc.Route.Rules)-1]
	if last["action"] != "resolve" || last["strategy"] != "ipv4_only" || len(last) != 3 {
		t.Fatalf("expected final catch-all ipv4_only resolve rule at tail of route.rules, got %+v", last)
	}

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
		cfgPath := filepath.Join(t.TempDir(), "sing-box-resolve.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with action=resolve rules: %v\n%s\n%s", err, output, string(out.Raw))
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

	// Verify idle_timeout emitted for 1h urltest group so sing-box won't exit on startup.
	entryOb := byTag[GroupTag("grp-entry")]
	if entryOb == nil || entryOb["idle_timeout"] != "2h0m0s" {
		t.Fatalf("expected grp-entry idle_timeout=2h0m0s for 1h interval, got %+v", entryOb)
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
	raw := string(out.Raw)
	for _, want := range []string{`"224.0.0.0/4"`, `"240.0.0.0/4"`, `"192.168.0.0/16"`, `"10.0.0.0/8"`, `"172.19.0.4/30"`} {
		if !strings.Contains(raw, want) {
			t.Fatalf("expected desktop TUN route_exclude_address to include %s, got:\n%s", want, raw)
		}
	}
	if strings.Contains(raw, `"172.16.0.0/12"`) && strings.Contains(raw, `"route_exclude_address":["127.0.0.0/8","10.0.0.0/8","100.64.0.0/10","169.254.0.0/16","172.16.0.0/12"`) {
		t.Fatal("route_exclude_address must not blindly exclude 172.19.0.0/30 TUN DNS subnet")
	}

	if binary := os.Getenv("SINGBOX_TEST_BINARY"); binary != "" {
		cfgPath := filepath.Join(t.TempDir(), "sing-box-lan-bcast.json")
		if err := os.WriteFile(cfgPath, out.Raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := exec.Command(binary, "check", "-c", cfgPath).CombinedOutput(); err != nil {
			t.Fatalf("sing-box check failed with desktop TUN LAN broadcast exclusions: %v\n%s\n%s", err, output, raw)
		}
	}
}
