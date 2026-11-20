// SPDX-License-Identifier: MPL-2.0
package config

import (
	"testing"

	model "github.com/CRACKRAMMER/PrismRay/backend/internal/config"
)

func TestModesKeepAPIAndOrderedCustomRules(t *testing.T) {
	for _, mode := range []string{"rule", "custom", "bypass-lan", "bypass-cn", "global", "direct"} {
		c, e := GenerateConfig(&model.Node{Protocol: model.ProtocolTrojan, Address: "example.com", Port: 443, Password: "secret", Security: "tls", Network: "tcp"}, 10808, 10085)
		if e != nil {
			t.Fatal(e)
		}
		e = c.ApplyPreferences(Preferences{Mode: mode, LogLevel: "debug", DomainStrategy: "IPIfNonMatch", DNSServers: []string{"https://1.1.1.1/dns-query"}, Rules: []RoutingRule{{Domain: []string{"domain:example.org"}, OutboundTag: "block"}}})
		if e != nil {
			t.Fatal(e)
		}
		if c.Routing.Rules[0].OutboundTag != "api" {
			t.Fatal("lost stats API routing")
		}
		if c.Log.LogLevel != "debug" {
			t.Fatal("log level not applied")
		}
		if mode == "rule" && c.Routing.Rules[1].OutboundTag != "block" {
			t.Fatal("custom rule must precede bypass")
		}
		if mode == "global" && (len(c.Routing.Rules) != 2 || c.Routing.Rules[1].OutboundTag != "proxy") {
			t.Fatal("global still bypasses")
		}
		if mode == "direct" && c.Routing.Rules[1].OutboundTag != "direct" {
			t.Fatal("direct mode still proxies")
		}
	}
}

func TestProxyRuleUsesListenerBalancer(t *testing.T) {
	a := &model.Node{ID: "a", Protocol: model.ProtocolTrojan, Address: "example.com", Port: 443, Password: "secret"}
	b := *a
	b.ID = "b"
	c, e := GenerateMultiListenerConfig([]*model.ListenConfig{{ID: "l", Protocol: "socks", Address: "127.0.0.1", Port: 10808, NodeIDs: []string{"a", "b"}, Enabled: true}}, []*model.Node{a, &b}, 10085)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.ApplyPreferences(Preferences{Mode: "rule", DomainStrategy: "AsIs", Rules: []RoutingRule{{Domain: []string{"domain:example.org"}, OutboundTag: "proxy"}}}); e != nil {
		t.Fatal(e)
	}
	r := c.Routing.Rules[1]
	if r.BalancerTag != "bal-l" || r.OutboundTag != "" || len(r.InboundTag) != 1 || r.InboundTag[0] != "in-l" {
		t.Fatal("proxy rule bypassed listener balancer")
	}
}
