// SPDX-License-Identifier: MPL-2.0

package config

// XrayConfig matches the structure of config.json expected by Xray-core.
// We only define fields we need to control.
type XrayConfig struct {
	DNS       interface{}      `json:"dns,omitempty"`
	Log       *LogConfig       `json:"log,omitempty"`
	Stats     *StatsConfig     `json:"stats,omitempty"`
	API       *APIConfig       `json:"api,omitempty"`
	Policy    *PolicyConfig    `json:"policy,omitempty"`
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Routing   *RoutingConfig   `json:"routing,omitempty"`
}

type LogConfig struct {
	LogLevel string `json:"loglevel"`
	Access   string `json:"access,omitempty"`
	Error    string `json:"error,omitempty"`
}

// StatsConfig (empty object enables stats collection)
type StatsConfig struct{}

type APIConfig struct {
	Tag      string   `json:"tag"`
	Services []string `json:"services"`
}

type PolicyConfig struct {
	System *SystemPolicy `json:"system,omitempty"`
}

type SystemPolicy struct {
	StatsInboundUplink    bool `json:"statsInboundUplink"`
	StatsInboundDownlink  bool `json:"statsInboundDownlink"`
	StatsOutboundUplink   bool `json:"statsOutboundUplink"`
	StatsOutboundDownlink bool `json:"statsOutboundDownlink"`
}

type InboundConfig struct {
	Tag      string          `json:"tag"`
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Settings interface{}     `json:"settings,omitempty"`
	Sniffing *SniffingConfig `json:"sniffing,omitempty"`
}

type SniffingConfig struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
	RouteOnly    bool     `json:"routeOnly,omitempty"`
}

type OutboundConfig struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       interface{}     `json:"settings,omitempty"`
	StreamSettings *StreamSettings `json:"streamSettings,omitempty"`
	Mux            *MuxConfig      `json:"mux,omitempty"`
}

type MuxConfig struct {
	Enabled     bool `json:"enabled"`
	Concurrency int  `json:"concurrency,omitempty"`
}

type RoutingConfig struct {
	DomainStrategy string           `json:"domainStrategy"`
	Rules          []RoutingRule    `json:"rules"`
	Balancers      []BalancerConfig `json:"balancers,omitempty"`
}

type RoutingRule struct {
	Type        string   `json:"type"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	InboundTag  []string `json:"inboundTag,omitempty"`
	OutboundTag string   `json:"outboundTag,omitempty"`
	BalancerTag string   `json:"balancerTag,omitempty"`
}

// BalancerConfig enables round-robin / random load balancing across multiple outbounds.
type BalancerConfig struct {
	Tag      string          `json:"tag"`
	Selector []string        `json:"selector"`
	Strategy *StrategyConfig `json:"strategy,omitempty"`
}

type StrategyConfig struct {
	Type string `json:"type"` // "random", "roundRobin", "leastPing"
}

// StreamSettings ...
type StreamSettings struct {
	Network             string             `json:"network"`
	Security            string             `json:"security"`
	TLSSettings         *TLSConfig         `json:"tlsSettings,omitempty"`
	RealitySettings     *RealityConfig     `json:"realitySettings,omitempty"`
	WSSettings          *WebSocketConfig   `json:"wsSettings,omitempty"`
	TCPSettings         *TCPConfig         `json:"tcpSettings,omitempty"`
	GRPCSettings        *GRPCConfig        `json:"grpcSettings,omitempty"`
	XHTTPSettings       map[string]any     `json:"xhttpSettings,omitempty"`
	HTTPUpgradeSettings *HTTPUpgradeConfig `json:"httpupgradeSettings,omitempty"`
	Sockopt             *SockoptConfig     `json:"sockopt,omitempty"`
}

type SockoptConfig struct {
	Mark uint32 `json:"mark,omitempty"`
}

type HTTPUpgradeConfig struct {
	Path string `json:"path,omitempty"`
	Host string `json:"host,omitempty"`
}

type TLSConfig struct {
	ServerName    string   `json:"serverName,omitempty"`
	Fingerprint   string   `json:"fingerprint,omitempty"`
	AllowInsecure bool     `json:"allowInsecure,omitempty"`
	ALPN          []string `json:"alpn,omitempty"`
}

type RealityConfig struct {
	Fingerprint   string `json:"fingerprint"`
	ServerName    string `json:"serverName"`
	PublicKey     string `json:"publicKey"`
	ShortID       string `json:"shortId"`
	SpiderX       string `json:"spiderX"`
	MLDSA65Verify string `json:"mldsa65Verify,omitempty"`
}

type WebSocketConfig struct {
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type TCPConfig struct {
	Header interface{} `json:"header,omitempty"` // For http obfuscation
}

type GRPCConfig struct {
	ServiceName string `json:"serviceName,omitempty"`
	MultiMode   bool   `json:"multiMode,omitempty"`
}
