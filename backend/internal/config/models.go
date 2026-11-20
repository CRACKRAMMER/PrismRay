// SPDX-License-Identifier: MPL-2.0

package config

import (
	"fmt"
	"strings"
)

// ProtocolEnum represents supported proxy protocols in v1.0.0.
type ProtocolEnum string

const (
	ProtocolVMess       ProtocolEnum = "vmess"
	ProtocolVLESS       ProtocolEnum = "vless"
	ProtocolTrojan      ProtocolEnum = "trojan"
	ProtocolShadowsocks ProtocolEnum = "shadowsocks"
	ProtocolHysteria2   ProtocolEnum = "hysteria2"
	ProtocolTUIC        ProtocolEnum = "tuic"
	ProtocolAnyTLS      ProtocolEnum = "anytls"
	ProtocolWireGuard   ProtocolEnum = "wireguard"
	ProtocolNaive       ProtocolEnum = "naive"
	ProtocolSocks       ProtocolEnum = "socks"
	ProtocolHTTP        ProtocolEnum = "http"
)

// Node represents a unified proxy server configuration across all 11 protocols.
type Node struct {
	ID              string       `json:"id"`
	SubID           string       `json:"sub_id,omitempty"`
	Group           string       `json:"group,omitempty"`
	Name            string       `json:"name"`
	UserAlias       string       `json:"user_alias,omitempty"`
	Favorite        bool         `json:"favorite,omitempty"`
	EnginePref      string       `json:"engine_pref,omitempty"` // auto | sing-box | xray
	Protocol        ProtocolEnum `json:"protocol"`
	Address         string       `json:"address"`
	Port            int          `json:"port"`
	UUID            string       `json:"uuid,omitempty"`     // VLESS / VMess / TUIC
	Password        string       `json:"password,omitempty"` // SS / Trojan / Hy2 / TUIC / AnyTLS / Naive / SOCKS / HTTP
	Username        string       `json:"username,omitempty"` // Naive / SOCKS / HTTP
	Method          string       `json:"method,omitempty"`   // Shadowsocks cipher (incl. 2022-blake3-*)
	Cipher          string       `json:"cipher,omitempty"`   // VMess encryption cipher
	AlterID         int          `json:"alter_id,omitempty"`
	Flow            string       `json:"flow,omitempty"` // xtls-rprx-vision
	UoT             bool         `json:"uot,omitempty"`  // Shadowsocks UDP-over-TCP
	Security        string       `json:"security"`       // none | tls | reality
	AllowInsecure   bool         `json:"allow_insecure,omitempty"`
	Sni             string       `json:"sni,omitempty"`
	Fingerprint     string       `json:"fingerprint,omitempty"`
	ALPN            []string     `json:"alpn,omitempty"`
	PublicKey       string       `json:"public_key,omitempty"` // REALITY public key (also fallback peer pk)
	ShortID         string       `json:"short_id,omitempty"`   // REALITY short ID
	SpiderX         string       `json:"spider_x,omitempty"`
	MLDSA65Verify   string       `json:"mldsa65_verify,omitempty"`   // Xray v26 REALITY post-quantum verifier
	VLESSEncryption string       `json:"vless_encryption,omitempty"` // Xray v26 vlessenc / mlkem768

	// Stream / Transport settings
	Network         string            `json:"network,omitempty"` // tcp | ws | grpc | xhttp | httpupgrade | h2 | quic
	Path            string            `json:"path,omitempty"`
	Host            string            `json:"host,omitempty"`
	ServiceName     string            `json:"service_name,omitempty"`
	WSHeaders       map[string]string `json:"ws_headers,omitempty"`
	EarlyData       int               `json:"early_data,omitempty"`
	EarlyDataHeader string            `json:"early_data_header,omitempty"`
	XHTTPMode       string            `json:"xhttp_mode,omitempty"`
	XHTTPExtra      map[string]any    `json:"xhttp_extra,omitempty"`
	MuxEnabled      bool              `json:"mux_enabled,omitempty"`

	// Hysteria2 settings
	UpMbps       int    `json:"up_mbps,omitempty"`
	DownMbps     int    `json:"down_mbps,omitempty"`
	ObfsType     string `json:"obfs_type,omitempty"`
	ObfsPassword string `json:"obfs_password,omitempty"`
	HopPorts     string `json:"hop_ports,omitempty"`
	HopInterval  string `json:"hop_interval,omitempty"`

	// TUIC v5 settings
	CongestionControl string `json:"congestion_control,omitempty"` // cubic | new_reno | bbr
	UDPRelayMode      string `json:"udp_relay_mode,omitempty"`     // native | quic
	ZeroRTTHandshake  bool   `json:"zero_rtt_handshake,omitempty"`
	Heartbeat         string `json:"heartbeat,omitempty"`

	// AnyTLS settings
	IdleSessionCheckInterval string `json:"idle_session_check_interval,omitempty"`
	IdleSessionTimeout       string `json:"idle_session_timeout,omitempty"`
	MinIdleSession           int    `json:"min_idle_session,omitempty"`

	// WireGuard endpoint settings
	PrivateKey     string   `json:"private_key,omitempty"`
	PeerPublicKey  string   `json:"peer_public_key,omitempty"`
	PreSharedKey   string   `json:"pre_shared_key,omitempty"`
	LocalAddresses []string `json:"local_addresses,omitempty"`
	Reserved       []uint8  `json:"reserved,omitempty"`
	MTU            int      `json:"mtu,omitempty"`
	Workers        int      `json:"workers,omitempty"`

	// NaiveProxy settings
	NaiveQuic    bool              `json:"naive_quic,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`

	// Classification, Chained Relay & Probe Telemetry
	DetourID string   `json:"detour_id,omitempty"` // Optional relay node ID or policy group ID for chained proxy
	Tags     []string `json:"tags,omitempty"`
	// Latency from last real-connection probe (ms, 0 = untested, -1 = timeout/unreachable)
	Latency       int     `json:"latency,omitempty"`
	PingMS        int     `json:"ping_ms,omitempty"`
	DownSpeedMbps float64 `json:"down_speed_mbps,omitempty"`
	UpSpeedMbps   float64 `json:"up_speed_mbps,omitempty"`
}

// ListenConfig defines a local inbound listener (mixed/socks/http) mapped to targets.
type ListenConfig struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Protocol       string   `json:"protocol"` // "mixed" | "socks" | "http"
	Address        string   `json:"address"`
	Port           int      `json:"port"`
	AllowLAN       bool     `json:"allow_lan,omitempty"`
	Username       string   `json:"username,omitempty"`
	Password       string   `json:"password,omitempty"`
	TargetOutbound string   `json:"target_outbound,omitempty"` // "" | "proxy" | "direct"
	TargetGroupID  string   `json:"target_group_id,omitempty"`
	NodeIDs        []string `json:"node_ids"`
	Enabled        bool     `json:"enabled"`
}

// DisplayName returns the user's custom alias if present, otherwise the node name.
func (n *Node) DisplayName() string {
	if strings.TrimSpace(n.UserAlias) != "" {
		return strings.TrimSpace(n.UserAlias)
	}
	if strings.TrimSpace(n.Name) != "" {
		return n.Name
	}
	return fmt.Sprintf("%s-%s", n.Protocol, n.Address)
}

// SupportsXray reports whether Xray v26 can natively execute this node's protocol.
func (n *Node) SupportsXray() bool {
	switch n.Protocol {
	case ProtocolVMess, ProtocolVLESS, ProtocolTrojan, ProtocolShadowsocks, ProtocolSocks, ProtocolHTTP:
		return true
	default:
		return false
	}
}

// RequiresXray reports whether executing this node requires the Xray v26 coprocessor.
func (n *Node) RequiresXray() bool {
	if !n.SupportsXray() {
		return false
	}
	if n.EnginePref == "xray" {
		return true
	}
	if n.EnginePref == "sing-box" {
		return false
	}
	net := strings.ToLower(strings.TrimSpace(n.Network))
	if net == "xhttp" || net == "splithttp" || net == "httpupgrade" {
		return true
	}
	enc := strings.TrimSpace(n.VLESSEncryption)
	if enc != "" && enc != "none" {
		return true
	}
	return strings.TrimSpace(n.MLDSA65Verify) != ""
}

// Validate checks fields required before persisting or launching a node.
func (n *Node) Validate() error {
	if n == nil || strings.TrimSpace(n.Address) == "" || n.Port < 1 || n.Port > 65535 {
		return fmt.Errorf("address and port (1-65535) are required")
	}
	if n.EnginePref != "" && n.EnginePref != "auto" && n.EnginePref != "sing-box" && n.EnginePref != "xray" {
		return fmt.Errorf("unsupported engine preference %q", n.EnginePref)
	}
	if n.EnginePref == "xray" && !n.SupportsXray() {
		return fmt.Errorf("protocol %s is not supported by xray engine", n.Protocol)
	}
	switch n.Protocol {
	case ProtocolVMess:
		if n.Security == "reality" {
			return fmt.Errorf("VMess Reality is not supported")
		}
		if n.UUID == "" || n.AlterID != 0 {
			return fmt.Errorf("VMess UUID required; only AEAD (alterId=0) is supported")
		}
		switch n.Cipher {
		case "", "auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero":
		default:
			return fmt.Errorf("unsupported VMess cipher")
		}
	case ProtocolVLESS:
		if n.UUID == "" {
			return fmt.Errorf("VLESS UUID is required")
		}
	case ProtocolTrojan:
		if n.Password == "" {
			return fmt.Errorf("Trojan password is required")
		}
	case ProtocolShadowsocks:
		if n.Password == "" || (n.Method == "" && n.Security == "") {
			return fmt.Errorf("Shadowsocks method and password are required")
		}
	case ProtocolHysteria2:
		if n.Password == "" {
			return fmt.Errorf("Hysteria2 password is required")
		}
	case ProtocolTUIC:
		if n.UUID == "" {
			return fmt.Errorf("TUIC UUID is required")
		}
	case ProtocolAnyTLS:
		if n.Password == "" {
			return fmt.Errorf("AnyTLS password is required")
		}
	case ProtocolWireGuard:
		if strings.TrimSpace(n.PrivateKey) == "" {
			return fmt.Errorf("WireGuard private key is required")
		}
		if strings.TrimSpace(n.PeerPublicKey) == "" && strings.TrimSpace(n.PublicKey) == "" {
			return fmt.Errorf("WireGuard peer public key is required")
		}
	case ProtocolNaive, ProtocolSocks, ProtocolHTTP:
		// Username/password are optional on HTTP/SOCKS; address/port verified above.
	default:
		return fmt.Errorf("unsupported protocol %q", n.Protocol)
	}
	return nil
}
