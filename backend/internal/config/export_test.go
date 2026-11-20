// SPDX-License-Identifier: MPL-2.0

package config

import (
	"reflect"
	"testing"
)

func TestExportRoundTrip(t *testing.T) {
	uris := []string{
		"vless://id@example.com:443?security=reality&type=grpc&serviceName=myservice&pbk=key&sid=ab#node",
		"vless://id@example.com:443?security=reality&type=xhttp&mode=packet-up&path=%2Fxhttp&encryption=none&pbk=key&pqv=pqv123#vless-xhttp",
		"trojan://a%40b@example.com:443?security=tls&type=ws&path=%2Fx#node",
		"ss://YWVzLTI1Ni1nY206cGFzcw@example.com:443?uot=1#node",
		"hysteria2://hy2pass@hy2.example.com:8443?sni=hy2.example.com&obfs=salamander&obfs-password=obfssecret&mport=20000-30000&upmbps=100&downmbps=200#hy2",
		"tuic://11111111-1111-4111-8111-111111111111:tuicpass@tuic.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3#tuic",
		"anytls://anypass@any.example.com:443?sni=any.example.com&fp=chrome#anytls",
		"wireguard://privkey@wg.example.com:51820?publickey=peerpk&address=10.0.0.2/32&mtu=1408&reserved=1,2,3#wg",
		"naive+https://user:pass@naive.example.com:443?sni=naive.example.com#naive",
		"socks5://user:pass@socks.example.com:1080#socks",
		"https://user:pass@http.example.com:8443?sni=http.example.com#https",
	}
	for _, uri := range uris {
		nodes, e := ParseSubscription(uri)
		if e != nil {
			t.Fatalf("parse %q failed: %v", uri, e)
		}
		again, e := ParseSubscription(nodes[0].URI())
		if e != nil {
			t.Fatalf("re-parse %q -> %q failed: %v", uri, nodes[0].URI(), e)
		}
		a, b := nodes[0], again[0]
		a.ID = ""
		b.ID = ""
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("roundtrip mismatch for %s:\n got: %#v\nwant: %#v", a.Protocol, b, a)
		}
	}
}
