// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
	"fmt"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
)

// GenerateConfig creates a complete Xray configuration for a single node (quick-connect mode).
// statsPort is the local port for the Xray gRPC stats API (dokodemo-door).
func GenerateConfig(node *config.Node, inboundPort int, statsPort int) (*XrayConfig, error) {
	if node == nil {
		return nil, fmt.Errorf("node is required")
	}
	if err := node.Validate(); err != nil {
		return nil, err
	}
	if inboundPort == 0 {
		inboundPort = 10808
	}
	if statsPort == 0 {
		statsPort = 10085
	}

	if inboundPort < 1 || inboundPort >= 65535 || statsPort < 1 || statsPort > 65535 || statsPort == inboundPort || statsPort == inboundPort+1 {
		return nil, fmt.Errorf("invalid or conflicting inbound/stats ports")
	}
	xrayConf := baseConfig(statsPort)

	// SOCKS proxy inbound
	xrayConf.Inbounds = append(xrayConf.Inbounds, InboundConfig{
		Tag:      "socks-in",
		Port:     inboundPort,
		Listen:   "127.0.0.1",
		Protocol: "socks",
		Sniffing: &SniffingConfig{
			Enabled:      true,
			DestOverride: []string{"http", "tls"},
		},
		Settings: map[string]interface{}{"udp": true},
	})

	// HTTP proxy inbound
	xrayConf.Inbounds = append(xrayConf.Inbounds, InboundConfig{
		Tag:      "http-in",
		Port:     inboundPort + 1,
		Listen:   "127.0.0.1",
		Protocol: "http",
	})

	proxyOutbound, err := buildProxyOutbound(node, "proxy")
	if err != nil {
		return nil, err
	}
	xrayConf.Outbounds = append(xrayConf.Outbounds, *proxyOutbound)
	appendDirectBlock(xrayConf)

	// Routing: bypass CN, everything else through proxy
	xrayConf.Routing.Rules = append(xrayConf.Routing.Rules, bypassRules()...)
	xrayConf.Routing.Rules = append(xrayConf.Routing.Rules,
		RoutingRule{
			Type:        "field",
			OutboundTag: "proxy",
			Port:        "0-65535",
		},
	)

	return xrayConf, nil
}

// GenerateMultiListenerConfig builds an Xray config with multiple listeners.
// Each listener creates an inbound that routes to its assigned outbound(s).
// If a listener has multiple nodes, a round-robin balancer is used.
func GenerateMultiListenerConfig(
	listeners []*config.ListenConfig,
	nodes []*config.Node,
	statsPort int,
) (*XrayConfig, error) {
	if statsPort == 0 {
		statsPort = 10085
	}

	xrayConf := baseConfig(statsPort)
	usedPorts := map[int]bool{statsPort: true}
	activeListeners := 0

	// Build node lookup
	nodeMap := make(map[string]*config.Node, len(nodes))
	for _, n := range nodes {
		nodeMap[n.ID] = n
	}

	// Track which outbounds we've already created (by node ID)
	createdOutbounds := make(map[string]bool)

	for _, lis := range listeners {
		if !lis.Enabled || len(lis.NodeIDs) == 0 {
			continue
		}

		if lis.Port < 1 || lis.Port > 65535 || usedPorts[lis.Port] {
			return nil, fmt.Errorf("listener %q has an invalid or duplicate port", lis.Name)
		}
		if lis.Address == "" {
			return nil, fmt.Errorf("listener %q requires a listen address", lis.Name)
		}
		if lis.Protocol != "" && lis.Protocol != "socks" && lis.Protocol != "http" {
			return nil, fmt.Errorf("unsupported listener protocol")
		}
		usedPorts[lis.Port] = true
		activeListeners++
		// Create inbound
		inboundTag := fmt.Sprintf("in-%s", lis.ID)
		proto := lis.Protocol
		if proto == "" {
			proto = "socks"
		}

		inbound := InboundConfig{
			Tag:      inboundTag,
			Port:     lis.Port,
			Listen:   lis.Address,
			Protocol: proto,
		}

		if proto == "socks" {
			inbound.Settings = map[string]interface{}{"udp": true}
			inbound.Sniffing = &SniffingConfig{
				Enabled:      true,
				DestOverride: []string{"http", "tls"},
			}
		}

		xrayConf.Inbounds = append(xrayConf.Inbounds, inbound)

		// Collect outbound tags for this listener
		var outboundTags []string
		for _, nodeID := range lis.NodeIDs {
			node, ok := nodeMap[nodeID]
			if !ok {
				return nil, fmt.Errorf("listener %q references missing node %q", lis.Name, nodeID)
			}
			if err := node.Validate(); err != nil {
				return nil, fmt.Errorf("listener %q: %w", lis.Name, err)
			}
			outTag := fmt.Sprintf("out-%s", nodeID)

			if !createdOutbounds[nodeID] {
				outbound, err := buildProxyOutbound(node, outTag)
				if err != nil {
					return nil, fmt.Errorf("listener %q node %q: %w", lis.Name, nodeID, err)
				}
				xrayConf.Outbounds = append(xrayConf.Outbounds, *outbound)
				createdOutbounds[nodeID] = true
			}
			outboundTags = append(outboundTags, outTag)
		}

		if len(outboundTags) == 0 {
			continue
		}

		// Route this inbound
		if len(outboundTags) == 1 {
			// Direct route to single outbound
			xrayConf.Routing.Rules = append(xrayConf.Routing.Rules, RoutingRule{
				Type:        "field",
				InboundTag:  []string{inboundTag},
				OutboundTag: outboundTags[0],
			})
		} else {
			// Create balancer for round-robin
			balancerTag := fmt.Sprintf("bal-%s", lis.ID)
			xrayConf.Routing.Balancers = append(xrayConf.Routing.Balancers, BalancerConfig{
				Tag:      balancerTag,
				Selector: outboundTags,
				Strategy: &StrategyConfig{Type: "roundRobin"},
			})
			xrayConf.Routing.Rules = append(xrayConf.Routing.Rules, RoutingRule{
				Type:        "field",
				InboundTag:  []string{inboundTag},
				BalancerTag: balancerTag,
			})
		}
	}

	if activeListeners == 0 {
		return nil, fmt.Errorf("at least one enabled listener with nodes is required")
	}
	appendDirectBlock(xrayConf)

	// Keep the API rule first, then bypass rules before per-listener routes.
	rules := xrayConf.Routing.Rules
	xrayConf.Routing.Rules = append(rules[:1:1], bypassRules()...)
	xrayConf.Routing.Rules = append(xrayConf.Routing.Rules, rules[1:]...)

	return xrayConf, nil
}

// baseConfig returns a config skeleton with logging, stats, API inbound, and empty routing.
func baseConfig(statsPort int) *XrayConfig {
	return &XrayConfig{
		Log:   &LogConfig{LogLevel: "warning"},
		Stats: &StatsConfig{},
		API: &APIConfig{
			Tag:      "api",
			Services: []string{"StatsService"},
		},
		Policy: &PolicyConfig{
			System: &SystemPolicy{
				StatsInboundUplink:    true,
				StatsInboundDownlink:  true,
				StatsOutboundUplink:   true,
				StatsOutboundDownlink: true,
			},
		},
		Inbounds: []InboundConfig{
			{
				Tag:      "api",
				Port:     statsPort,
				Listen:   "127.0.0.1",
				Protocol: "dokodemo-door",
				Settings: map[string]interface{}{"address": "127.0.0.1"},
			},
		},
		Outbounds: []OutboundConfig{},
		Routing: &RoutingConfig{
			DomainStrategy: "AsIs",
			Rules: []RoutingRule{
				{
					Type:        "field",
					InboundTag:  []string{"api"},
					OutboundTag: "api",
				},
			},
		},
	}
}

func appendDirectBlock(xrayConf *XrayConfig) {
	xrayConf.Outbounds = append(xrayConf.Outbounds,
		OutboundConfig{Tag: "direct", Protocol: "freedom"},
		OutboundConfig{Tag: "block", Protocol: "blackhole"},
	)
}

func buildProxyOutbound(node *config.Node, tag string) (*OutboundConfig, error) {
	network := node.Network
	if network == "" {
		network = "tcp"
	}
	if network == "splithttp" {
		network = "xhttp"
	}
	security := node.Security
	if security == "" {
		security = "none"
	}
	outbound := &OutboundConfig{
		Tag:      tag,
		Protocol: string(node.Protocol),
		StreamSettings: &StreamSettings{
			Network:  network,
			Security: security,
		},
		Mux: &MuxConfig{
			Enabled:     node.MuxEnabled,
			Concurrency: 8,
		},
	}

	switch node.Protocol {
	case config.ProtocolVMess:
		cipher := node.Cipher
		if cipher == "" {
			cipher = "auto"
		}
		outbound.Settings = map[string]interface{}{"vnext": []map[string]interface{}{{"address": node.Address, "port": node.Port, "users": []map[string]interface{}{{"id": node.UUID, "alterId": node.AlterID, "security": cipher}}}}}
	case config.ProtocolVLESS:
		enc := node.VLESSEncryption
		if enc == "" {
			enc = "none"
		}
		vnext := []map[string]interface{}{
			{
				"address": node.Address,
				"port":    node.Port,
				"users": []map[string]interface{}{
					{
						"id":         node.UUID,
						"encryption": enc,
						"flow":       node.Flow,
					},
				},
			},
		}
		outbound.Settings = map[string]interface{}{"vnext": vnext}

	case config.ProtocolShadowsocks:
		method := node.Method
		if method == "" {
			method = node.Security
		}
		servers := []map[string]interface{}{
			{
				"address":  node.Address,
				"port":     node.Port,
				"method":   method,
				"password": node.Password,
			},
		}
		outbound.Settings = map[string]interface{}{"servers": servers}
		outbound.StreamSettings = nil

	case config.ProtocolTrojan:
		servers := []map[string]interface{}{
			{
				"address":  node.Address,
				"port":     node.Port,
				"password": node.Password,
			},
		}
		outbound.Settings = map[string]interface{}{"servers": servers}

	case config.ProtocolSocks, config.ProtocolHTTP:
		srv := map[string]interface{}{
			"address": node.Address,
			"port":    node.Port,
		}
		if node.Username != "" || node.Password != "" {
			srv["users"] = []map[string]interface{}{
				{"user": node.Username, "pass": node.Password},
			}
		}
		outbound.Settings = map[string]interface{}{"servers": []map[string]interface{}{srv}}
		if node.Protocol == config.ProtocolSocks || security == "none" {
			outbound.StreamSettings = nil
		}

	default:
		return nil, fmt.Errorf("unsupported protocol for xray: %s", node.Protocol)
	}

	if outbound.StreamSettings != nil {
		if security == "tls" {
			outbound.StreamSettings.TLSSettings = &TLSConfig{
				ServerName:    node.Sni,
				Fingerprint:   node.Fingerprint,
				AllowInsecure: node.AllowInsecure,
				ALPN:          node.ALPN,
			}
		} else if security == "reality" {
			outbound.StreamSettings.RealitySettings = &RealityConfig{
				Fingerprint:   node.Fingerprint,
				ServerName:    node.Sni,
				PublicKey:     node.PublicKey,
				ShortID:       node.ShortID,
				SpiderX:       node.SpiderX,
				MLDSA65Verify: node.MLDSA65Verify,
			}
		}

		switch network {
		case "ws":
			headers := map[string]string{}
			if len(node.WSHeaders) > 0 {
				headers = node.WSHeaders
			} else if node.Host != "" {
				headers["Host"] = node.Host
			}
			outbound.StreamSettings.WSSettings = &WebSocketConfig{
				Path:    node.Path,
				Headers: headers,
			}
		case "grpc":
			outbound.StreamSettings.GRPCSettings = &GRPCConfig{
				ServiceName: node.ServiceName,
				MultiMode:   false,
			}
		case "xhttp":
			xhttp := map[string]interface{}{}
			if node.XHTTPMode != "" {
				xhttp["mode"] = node.XHTTPMode
			}
			if node.Host != "" {
				xhttp["host"] = node.Host
			}
			if node.Path != "" {
				xhttp["path"] = node.Path
			}
			if len(node.XHTTPExtra) > 0 {
				xhttp["extra"] = node.XHTTPExtra
			}
			outbound.StreamSettings.XHTTPSettings = xhttp
		case "httpupgrade":
			outbound.StreamSettings.HTTPUpgradeSettings = &HTTPUpgradeConfig{
				Path: node.Path,
				Host: node.Host,
			}
		}
	}

	return outbound, nil
}

// BridgeSpec binds a local loopback SOCKS5 port to a dedicated Xray v26 node.
type BridgeSpec struct {
	Node       *config.Node
	ListenPort int
}

// GenerateSidecarConfig generates a headless Xray coprocessor config exposing one
// loopback SOCKS5 inbound per bridged node. When mark > 0, streamSettings.sockopt.mark
// exempts coprocessor outbound traffic from Linux TUN routing table 2178.
func GenerateSidecarConfig(specs []BridgeSpec, logLevel string, mark uint32) (*XrayConfig, error) {
	if len(specs) == 0 {
		return nil, fmt.Errorf("at least one Xray bridge node is required")
	}
	if logLevel == "" {
		logLevel = "warning"
	}
	seenPorts := map[int]bool{}
	seenIDs := map[string]bool{}
	cfg := &XrayConfig{
		Log:       &LogConfig{LogLevel: logLevel},
		Inbounds:  make([]InboundConfig, 0, len(specs)),
		Outbounds: make([]OutboundConfig, 0, len(specs)+2),
		Routing: &RoutingConfig{
			DomainStrategy: "AsIs",
			Rules:          make([]RoutingRule, 0, len(specs)),
		},
	}

	for _, spec := range specs {
		if spec.Node == nil || spec.Node.ID == "" || spec.ListenPort < 1 || spec.ListenPort > 65535 {
			return nil, fmt.Errorf("invalid Xray bridge spec")
		}
		if seenPorts[spec.ListenPort] || seenIDs[spec.Node.ID] {
			return nil, fmt.Errorf("duplicate bridge port or node ID")
		}
		seenPorts[spec.ListenPort] = true
		seenIDs[spec.Node.ID] = true

		inTag := "bridge-in-" + spec.Node.ID
		outTag := "bridge-out-" + spec.Node.ID
		cfg.Inbounds = append(cfg.Inbounds, InboundConfig{
			Tag:      inTag,
			Port:     spec.ListenPort,
			Listen:   "127.0.0.1",
			Protocol: "socks",
			Settings: map[string]interface{}{"auth": "noauth", "udp": true},
		})
		ob, err := buildProxyOutbound(spec.Node, outTag)
		if err != nil {
			return nil, err
		}
		if mark > 0 {
			if ob.StreamSettings == nil {
				ob.StreamSettings = &StreamSettings{Network: "tcp", Security: "none"}
			}
			ob.StreamSettings.Sockopt = &SockoptConfig{Mark: mark}
		}
		cfg.Outbounds = append(cfg.Outbounds, *ob)
		cfg.Routing.Rules = append(cfg.Routing.Rules, RoutingRule{
			Type:        "field",
			InboundTag:  []string{inTag},
			OutboundTag: outTag,
		})
	}
	appendDirectBlock(cfg)
	return cfg, nil
}

// GenerateProbeConfig generates a single temporary Xray instance exposing one
// loopback SOCKS5 port per candidate node for high-concurrency batch probing.
func GenerateProbeConfig(specs []BridgeSpec) (*XrayConfig, error) {
	return GenerateSidecarConfig(specs, "error", 0)
}

// ToJSON serializes the config to formatting JSON.
func (c *XrayConfig) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func bypassRules() []RoutingRule {
	return []RoutingRule{
		{Type: "field", OutboundTag: "direct", Domain: []string{"geosite:cn"}},
		{Type: "field", OutboundTag: "direct", IP: []string{"geoip:private", "geoip:cn"}},
	}
}
