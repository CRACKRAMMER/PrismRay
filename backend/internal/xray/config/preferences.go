// SPDX-License-Identifier: MPL-2.0
package config

import "fmt"

// Preferences are applied to both quick-connect and multiple listeners.
type Preferences struct {
	Mode           string        `json:"mode"`
	LogLevel       string        `json:"log_level"`
	Rules          []RoutingRule `json:"rules"`
	DNSServers     []string      `json:"dns_servers"`
	DomainStrategy string        `json:"domain_strategy"`
}

func (p Preferences) Validate() error {
	if p.Mode != "rule" && p.Mode != "custom" && p.Mode != "global" && p.Mode != "bypass-lan" && p.Mode != "bypass-cn" && p.Mode != "direct" {
		return fmt.Errorf("invalid routing preset")
	}
	if p.LogLevel != "" && p.LogLevel != "error" && p.LogLevel != "warning" && p.LogLevel != "info" && p.LogLevel != "debug" {
		return fmt.Errorf("log level must be error, warning, info or debug")
	}
	if p.DomainStrategy != "AsIs" && p.DomainStrategy != "IPIfNonMatch" && p.DomainStrategy != "IPOnDemand" {
		return fmt.Errorf("invalid domain strategy")
	}
	for _, r := range p.Rules {
		if r.OutboundTag != "direct" && r.OutboundTag != "block" && r.OutboundTag != "proxy" {
			return fmt.Errorf("custom rule target must be proxy, direct or block")
		}
		if len(r.Domain) == 0 && len(r.IP) == 0 {
			return fmt.Errorf("rule requires domain or IP")
		}
		if r.BalancerTag != "" || len(r.InboundTag) > 0 {
			return fmt.Errorf("custom inbound/balancer rules are not supported")
		}
	}
	for _, d := range p.DNSServers {
		if d == "" {
			return fmt.Errorf("empty DNS server")
		}
	}
	return nil
}
func (c *XrayConfig) ApplyPreferences(p Preferences) error {
	if err := p.Validate(); err != nil {
		return err
	}
	rules := []RoutingRule{c.Routing.Rules[0]}
	if p.Mode == "rule" || p.Mode == "custom" || p.Mode == "bypass-lan" || p.Mode == "bypass-cn" {
		for _, r := range p.Rules {
			r.Type = "field"
			if r.OutboundTag == "proxy" {
				for _, target := range c.Routing.Rules[1:] {
					if len(target.Domain) > 0 || len(target.IP) > 0 {
						continue
					}
					custom := r
					custom.InboundTag = target.InboundTag
					custom.OutboundTag = target.OutboundTag
					custom.BalancerTag = target.BalancerTag
					rules = append(rules, custom)
				}
			} else {
				rules = append(rules, r)
			}
		}
		if p.Mode == "rule" || p.Mode == "bypass-cn" {
			rules = append(rules, bypassRules()...)
		} else if p.Mode == "bypass-lan" {
			rules = append(rules, RoutingRule{Type: "field", OutboundTag: "direct", IP: []string{"geoip:private"}})
		}
	}
	if p.Mode == "direct" {
		rules = append(rules, RoutingRule{Type: "field", Port: "0-65535", OutboundTag: "direct"})
	} else {
		for _, r := range c.Routing.Rules[1:] {
			if len(r.Domain) == 0 && len(r.IP) == 0 {
				rules = append(rules, r)
			}
		}
	}
	c.Routing.Rules = rules
	c.Routing.DomainStrategy = p.DomainStrategy
	if p.LogLevel == "" {
		p.LogLevel = "warning"
	}
	c.Log.LogLevel = p.LogLevel
	if len(p.DNSServers) > 0 {
		c.DNS = map[string]interface{}{"servers": p.DNSServers, "queryStrategy": "UseIP"}
	}
	return nil
}
