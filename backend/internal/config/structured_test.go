// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/base64"
	"testing"
)

func TestStructuredSubscriptions(t *testing.T) {
	cases := map[string]string{
		"clash": `proxies:
 - name: sample
   type: vmess
   server: example.com
   port: 443
   uuid: 11111111-1111-4111-8111-111111111111
   alterId: 0
   cipher: auto
   tls: true
   network: ws
   ws-opts:
     path: /proxy
     headers: {Host: cdn.example.com}`,
		"sing-box": `{"outbounds":[{"type":"direct","tag":"direct"},{"type":"vmess","server":"example.com","server_port":443,"uuid":"11111111-1111-4111-8111-111111111111","security":"auto","tls":{"enabled":true},"transport":{"type":"ws","path":"/proxy","headers":{"Host":"cdn.example.com"}}}]}`,
		"xray":     `{"outbounds":[{"protocol":"vmess","settings":{"vnext":[{"address":"example.com","port":443,"users":[{"id":"11111111-1111-4111-8111-111111111111","security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/proxy","headers":{"Host":"cdn.example.com"}}}}]}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			for _, content := range []string{input, base64.StdEncoding.EncodeToString([]byte("\ufeff" + input))} {
				nodes, e := ParseSubscription(content)
				if e != nil {
					t.Fatal(e)
				}
				n := nodes[0]
				if len(nodes) != 1 || n.Protocol != ProtocolVMess || n.Address != "example.com" || n.Port != 443 || n.Network != "ws" || n.Security != "tls" || n.Path != "/proxy" || n.Host != "cdn.example.com" {
					t.Fatalf("incorrect conversion: %+v", n)
				}
				again, e := ParseSubscription(n.URI())
				if e != nil {
					t.Fatal(e)
				}
				if again[0].UUID != n.UUID || again[0].Path != n.Path || again[0].Cipher != n.Cipher {
					t.Fatal("VMess roundtrip changed connection")
				}
			}
		})
	}
	for _, input := range []string{`{"version":1,"servers":[{"server":"example.com","server_port":8388,"method":"aes-128-gcm","password":"test"}]}`, `[{"server":"example.com","server_port":8388,"method":"aes-128-gcm","password":"test"}]`, `{"server":"example.com","server_port":8388,"method":"aes-128-gcm","password":"test"}`} {
		nodes, e := ParseSubscription(input)
		if e != nil || len(nodes) != 1 {
			t.Fatalf("SIP008: %v", e)
		}
	}
}

func TestStructuredExtendedProtocolsAndResilientSkip(t *testing.T) {
	clashYAML := `proxies:
  - name: hy2-node
    type: hysteria2
    server: hy2.example.com
    port: 443
    password: secret
    skip-cert-verify: true
  - name: tuic-node
    type: tuic
    server: tuic.example.com
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: tpass
    congestion-controller: bbr
  - name: broken-vmess
    type: vmess
    server: bad.example.com
    port: 443
    uuid: test
    alterId: 64
  - name: broken-ss
    type: ss
    server: badss.example.com
    port: 443
    password: test`
	res, err := ParseSubscriptionResilient(clashYAML)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Nodes) != 2 || len(res.Skipped) != 2 || len(res.Warnings) != 1 {
		t.Fatalf("unexpected resilient clash result: nodes=%d skipped=%d warnings=%d", len(res.Nodes), len(res.Skipped), len(res.Warnings))
	}
	if !res.Nodes[0].AllowInsecure {
		t.Fatal("expected skip-cert-verify mapped to AllowInsecure=true")
	}

	singConfig := `{"endpoints":[{"type":"wireguard","tag":"wg-ep","private_key":"pk1","address":["10.0.0.2/32"],"peers":[{"address":"1.2.3.4","port":51820,"public_key":"pub1"}]}],"outbounds":[{"type":"anytls","tag":"any-1","server":"any.example.com","server_port":443,"password":"apass","tls":{"enabled":true}},{"type":"trojan","tag":"hu-1","server":"hu.example.com","server_port":443,"password":"pass","tls":{"enabled":true},"transport":{"type":"httpupgrade","path":"/ws"}}]}`
	singRes, err := ParseSubscriptionResilient(singConfig)
	if err != nil {
		t.Fatal(err)
	}
	if len(singRes.Nodes) != 3 {
		t.Fatalf("expected 3 nodes from sing-box outbounds+endpoints, got %d", len(singRes.Nodes))
	}
	if !singRes.Nodes[1].RequiresXray() {
		t.Fatal("expected httpupgrade node to require Xray coprocessor")
	}
	if singRes.Nodes[2].Protocol != ProtocolWireGuard {
		t.Fatalf("expected WireGuard endpoint, got %s", singRes.Nodes[2].Protocol)
	}
}

func TestStructuredRejectsInvalidDocuments(t *testing.T) {
	for _, input := range []string{
		"proxies: []\n---\nproxies: []",
		`{"proxies": "invalid"}`,
		`{"outbounds":[{"type":"direct"}]}`,
	} {
		if n, e := ParseSubscriptionResilient(input); e == nil || (n != nil && len(n.Nodes) != 0) {
			t.Fatalf("accepted invalid subscription: %s", input)
		}
	}
}

func TestSubscriptionCommentAndFragment(t *testing.T) {
	if n, e := ParseSubscription("# heading\n vless://test@example.com:443#proxies:node"); e != nil || len(n) != 1 {
		t.Fatalf("URI misdetected: %v", e)
	}
}
