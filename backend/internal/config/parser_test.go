// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSubscriptionProtocols(t *testing.T) {
	cases := []struct {
		name, input               string
		protocol                  ProtocolEnum
		method, password, service string
	}{
		{"vless grpc", "vless://id@example.com:443?type=grpc&serviceName=tunnel", ProtocolVLESS, "", "", "tunnel"},
		{"trojan reality", "trojan://pass@example.com:443?security=reality&pbk=key&sid=01", ProtocolTrojan, "", "pass", ""},
		{"ss userinfo", "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:p:a@ss")) + "@[::1]:8388#Name", ProtocolShadowsocks, "aes-256-gcm", "p:a@ss", ""},
		{"ss legacy", "ss://" + base64.RawStdEncoding.EncodeToString([]byte("aes-256-gcm:pass@example.com:8388")), ProtocolShadowsocks, "aes-256-gcm", "pass", ""},
		{"ss plain", "ss://aes-256-gcm:pass@example.com:8388", ProtocolShadowsocks, "aes-256-gcm", "pass", ""},
		{"ss 2022", "ss://2022-blake3-aes-128-gcm:base64key@example.com:8388?uot=1#ss2022", ProtocolShadowsocks, "2022-blake3-aes-128-gcm", "base64key", ""},
		{"hy2 alias", "hy2://pass@hy2.example.com:443?sni=sni.example.com&obfs=salamander&obfs-password=opass#Hy2", ProtocolHysteria2, "", "pass", ""},
		{"tuic", "tuic://uuid-1:pass@tuic.example.com:443?congestion_control=bbr#TUIC", ProtocolTUIC, "", "pass", ""},
		{"anytls", "anytls://secret@any.example.com:443#AnyTLS", ProtocolAnyTLS, "", "secret", ""},
		{"wg", "wg://privkey@wg.example.com:51820?publickey=peerpub#WG", ProtocolWireGuard, "", "", ""},
		{"naive", "naive+quic://u:p@naive.example.com:443#Naive", ProtocolNaive, "", "p", ""},
		{"socks5", "socks5://u:p@socks.example.com:1080#SOCKS", ProtocolSocks, "", "p", ""},
		{"http", "http://u:p@http.example.com:8080#HTTP", ProtocolHTTP, "", "p", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, input := range []string{tc.input, base64.RawStdEncoding.EncodeToString([]byte(tc.input))} {
				nodes, err := ParseSubscription(input)
				if err != nil {
					t.Fatal(err)
				}
				n := nodes[0]
				if n.Protocol != tc.protocol || n.Method != tc.method || n.Password != tc.password || n.ServiceName != tc.service {
					t.Fatalf("unexpected node: %+v", n)
				}
			}
		})
	}
}

func TestSubscriptionRejectsInvalidLines(t *testing.T) {
	for _, input := range []string{"", "garbage", "vless://example.com:443", "trojan://pass@host:65536", "ss://bad@host:8388", "vless://id@host:443\ninvalid"} {
		if _, err := ParseSubscription(input); err == nil {
			t.Errorf("accepted %q", input)
		}
	}
}

func TestResilientSubscriptionImportAndWarnings(t *testing.T) {
	mixed := strings.Join([]string{
		"# airport subscription",
		"vless://id-1@xhttp.example.com:443?type=xhttp&mode=auto&path=/x&encryption=mlkem768x25519plus.native.0rtt&pqv=pqv-key&security=reality&pbk=pbk1#XrayXHTTP",
		"unknownproto://foo@bar:123#broken-unknown",
		"hysteria2://hy2pass@hy2.example.com:443?insecure=1#InsecureHy2",
		"badline-without-scheme",
	}, "\n")
	res, err := ParseSubscriptionResilient(mixed)
	if err != nil {
		t.Fatalf("resilient parse failed: %v", err)
	}
	if len(res.Nodes) != 2 {
		t.Fatalf("expected 2 valid nodes, got %d", len(res.Nodes))
	}
	if !res.Nodes[0].RequiresXray() {
		t.Fatalf("expected XHTTP+vlessenc+mldsa65 node to require Xray")
	}
	if res.Nodes[1].RequiresXray() || !res.Nodes[1].AllowInsecure {
		t.Fatalf("unexpected hy2 flags: %+v", res.Nodes[1])
	}
	if len(res.Skipped) != 2 {
		t.Fatalf("expected 2 skipped entries, got %+v", res.Skipped)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "InsecureHy2") {
		t.Fatalf("expected insecure warning, got %+v", res.Warnings)
	}
}

func TestWireGuardConfAndUserinfoHeader(t *testing.T) {
	conf := `
[Interface]
PrivateKey = local-priv-key
Address = 10.66.66.2/32, fd42:42:42::2/128
MTU = 1380

[Peer]
PublicKey = peer-pub-key
PresharedKey = psk-123
Endpoint = engage.cloudflareclient.com:2408
`
	res, err := ParseSubscriptionResilient(conf)
	if err != nil || len(res.Nodes) != 1 {
		t.Fatalf("WireGuard .conf parse failed: %v", err)
	}
	n := res.Nodes[0]
	if n.Protocol != ProtocolWireGuard || n.Port != 2408 || n.MTU != 1380 || len(n.LocalAddresses) != 2 {
		t.Fatalf("unexpected WireGuard node: %+v", n)
	}

	meta := ParseUserinfoHeader("upload=1073741824; download=2147483648; total=10737418240; expire=1800000000")
	if meta.UploadBytes != 1073741824 || meta.DownloadBytes != 2147483648 || meta.TotalBytes != 10737418240 || meta.ExpireUnix != 1800000000 {
		t.Fatalf("unexpected userinfo meta: %+v", meta)
	}
}

func TestEngineSelectionLogic(t *testing.T) {
	wg := &Node{Protocol: ProtocolWireGuard, Address: "1.1.1.1", Port: 51820, PrivateKey: "a", PeerPublicKey: "b", EnginePref: "xray"}
	if wg.Validate() == nil {
		t.Fatal("expected WireGuard + EnginePref=xray to fail validation")
	}
	stdVless := &Node{Protocol: ProtocolVLESS, Address: "example.com", Port: 443, UUID: "id", Network: "ws"}
	if stdVless.RequiresXray() {
		t.Fatal("standard VLESS WS should default to sing-box")
	}
	stdVless.EnginePref = "xray"
	if !stdVless.RequiresXray() {
		t.Fatal("EnginePref=xray should force Xray")
	}
}
