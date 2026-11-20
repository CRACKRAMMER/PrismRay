// SPDX-License-Identifier: MPL-2.0

package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
)

func fixtureNode(id string) *config.Node {
	return &config.Node{ID: id, Protocol: config.ProtocolVLESS, Address: "127.0.0.1", Port: 9, UUID: "11111111-1111-4111-8111-111111111111", Network: "tcp", Security: "none"}
}
func TestListenerValidationAndRouting(t *testing.T) {
	node := fixtureNode("a")
	lis := &config.ListenConfig{ID: "l", Protocol: "socks", Address: "127.0.0.1", Port: 10808, NodeIDs: []string{"a"}, Enabled: true}
	cfg, err := GenerateMultiListenerConfig([]*config.ListenConfig{lis}, []*config.Node{node}, 10085)
	if err != nil {
		t.Fatal(err)
	}
	rules := cfg.Routing.Rules
	if len(rules) != 4 || rules[0].OutboundTag != "api" || rules[1].OutboundTag != "direct" || rules[2].OutboundTag != "direct" || rules[3].OutboundTag != "out-a" {
		t.Fatalf("unexpected routing order: %+v", rules)
	}
	if len(rules[1].IP) != 0 || len(rules[2].Domain) != 0 {
		t.Fatal("IP and domain bypass conditions combined")
	}
	for _, modify := range []func(*config.ListenConfig){
		func(l *config.ListenConfig) { l.Port = 10085 },
		func(l *config.ListenConfig) { l.NodeIDs = []string{"missing"} },
		func(l *config.ListenConfig) { l.Enabled = false },
		func(l *config.ListenConfig) { l.Port = 65536 },
	} {
		invalid := *lis
		modify(&invalid)
		if _, err := GenerateMultiListenerConfig([]*config.ListenConfig{&invalid}, []*config.Node{node}, 10085); err == nil {
			t.Fatal("invalid listener accepted")
		}
	}
}

// Optional local compatibility check; validates generated configs without opening
// proxy ports or connecting to a remote node. CI does not download Xray.
func TestXrayAcceptsGeneratedConfig(t *testing.T) {
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("set XRAY_TEST_BINARY for local Xray config validation")
	}
	a, b := fixtureNode("a"), fixtureNode("b")
	single, err := GenerateConfig(a, 10808, 10085)
	if err != nil {
		t.Fatal(err)
	}
	multi, err := GenerateMultiListenerConfig([]*config.ListenConfig{{ID: "l", Protocol: "socks", Address: "127.0.0.1", Port: 10808, NodeIDs: []string{"a", "b"}, Enabled: true}}, []*config.Node{a, b}, 10085)
	if err != nil {
		t.Fatal(err)
	}
	configs := []*XrayConfig{single, multi}
	for _, transport := range []string{"tcp", "ws", "grpc"} {
		vmess := fixtureNode("vmess")
		vmess.Protocol = config.ProtocolVMess
		vmess.Network = transport
		vmess.Cipher = "auto"
		vmess.Path = "/proxy"
		vmess.ServiceName = "proxy"
		generated, e := GenerateConfig(vmess, 10808, 10085)
		if e != nil {
			t.Fatal(e)
		}
		configs = append(configs, generated)
	}
	for _, mode := range []string{"rule", "global", "direct"} {
		candidate, e := GenerateConfig(a, 10808, 10085)
		if e != nil {
			t.Fatal(e)
		}
		if e = candidate.ApplyPreferences(Preferences{Mode: mode, DomainStrategy: "IPIfNonMatch", DNSServers: []string{"https://1.1.1.1/dns-query"}, Rules: []RoutingRule{{Domain: []string{"domain:example.org"}, OutboundTag: "block"}}}); e != nil {
			t.Fatal(e)
		}
		configs = append(configs, candidate)
	}
	xhttpNode := &config.Node{
		ID: "xhttp-v26", Protocol: config.ProtocolVLESS, Address: "xhttp.example.com", Port: 443,
		UUID: "11111111-1111-4111-8111-111111111111", Network: "xhttp", XHTTPMode: "auto", Path: "/xhttp",
		Security: "reality", Sni: "www.microsoft.com", Fingerprint: "chrome",
		PublicKey: "zwWqEjRwDWQ2NM5x0PXxuTQxgDEUMBQwoRFBV34QrwU", ShortID: "01ab",
	}
	huNode := &config.Node{
		ID: "hu-v26", Protocol: config.ProtocolTrojan, Address: "hu.example.com", Port: 443,
		Password: "secret", Network: "httpupgrade", Path: "/hu", Host: "hu.example.com", Security: "tls", Sni: "hu.example.com",
	}
	sidecar, err := GenerateSidecarConfig([]BridgeSpec{
		{Node: xhttpNode, ListenPort: 18081},
		{Node: huNode, ListenPort: 18082},
	}, "warning", 0x21780)
	if err != nil {
		t.Fatalf("GenerateSidecarConfig failed: %v", err)
	}
	configs = append(configs, sidecar)

	for _, cfg := range configs {
		data, err := cfg.ToJSON()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "xray.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-test", "-c", path)
		cmd.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+filepath.Dir(binary))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("Xray rejected config: %v\n%s", err, output)
		}
	}
}
