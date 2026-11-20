// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// SubscriptionTrafficMeta holds quota and expiration details extracted from
// Subscription-Userinfo headers or informational metadata.
type SubscriptionTrafficMeta struct {
	UploadBytes   int64 `json:"upload_bytes"`
	DownloadBytes int64 `json:"download_bytes"`
	TotalBytes    int64 `json:"total_bytes"`
	ExpireUnix    int64 `json:"expire_unix"`
}

// SkippedEntry captures one entry skipped during resilient subscription import.
type SkippedEntry struct {
	Index  int    `json:"index"`
	Name   string `json:"name,omitempty"`
	Raw    string `json:"raw,omitempty"`
	Reason string `json:"reason"`
}

// SubscriptionImportResult contains valid parsed nodes alongside non-fatal skip
// and security warnings.
type SubscriptionImportResult struct {
	Nodes    []*Node                 `json:"nodes"`
	Skipped  []SkippedEntry          `json:"skipped"`
	Warnings []string                `json:"warnings"`
	Meta     SubscriptionTrafficMeta `json:"meta"`
}

func decodeBase64(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := encoding.DecodeString(s); err == nil {
			return string(b), nil
		}
	}
	return "", fmt.Errorf("invalid base64")
}

// ParseUserinfoHeader parses a standard `Subscription-Userinfo` header string
// such as `upload=123; download=456; total=1024; expire=1700000000`.
func ParseUserinfoHeader(header string) SubscriptionTrafficMeta {
	var meta SubscriptionTrafficMeta
	for _, part := range strings.Split(header, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		val, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "upload":
			meta.UploadBytes = val
		case "download":
			meta.DownloadBytes = val
		case "total":
			meta.TotalBytes = val
		case "expire":
			meta.ExpireUnix = val
		}
	}
	return meta
}

// ParseSubscription strictly parses a subscription and rejects inputs that contain
// any skipped or malformed entries.
func ParseSubscription(content string) ([]*Node, error) {
	res, err := ParseSubscriptionResilient(content)
	if err != nil {
		return nil, err
	}
	if len(res.Skipped) > 0 {
		first := res.Skipped[0]
		return nil, fmt.Errorf("subscription entry %d: %s", first.Index, first.Reason)
	}
	if len(res.Nodes) == 0 {
		return nil, fmt.Errorf("no supported nodes found")
	}
	return res.Nodes, nil
}

// ParseSubscriptionResilient imports all supported valid nodes from a subscription,
// skips unknown/broken entries cleanly with structured diagnostics, and flags
// insecure TLS nodes with explicit warnings.
func ParseSubscriptionResilient(content string) (*SubscriptionImportResult, error) {
	if len(content) > 4<<20 {
		return nil, fmt.Errorf("subscription exceeds 4 MiB")
	}
	content = strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if content == "" {
		return nil, fmt.Errorf("no supported nodes found")
	}
	if decoded, err := decodeBase64(content); err == nil && !strings.Contains(content, "://") && !strings.Contains(content, "[Interface]") {
		content = decoded
	}
	content = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(content), "\ufeff"))
	if content == "" {
		return nil, fmt.Errorf("no supported nodes found")
	}

	if strings.Contains(content, "[Interface]") && strings.Contains(content, "[Peer]") {
		return parseWireGuardConfResilient(content)
	}

	structured := strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") || strings.HasPrefix(content, "---")
	if !structured {
		for _, line := range strings.Split(content, "\n") {
			trimmed := strings.TrimSpace(line)
			for _, key := range []string{"proxies:", "outbounds:", "endpoints:", "servers:", "server:", "- proxies:", "- outbounds:"} {
				if strings.HasPrefix(trimmed, key) {
					structured = true
					break
				}
			}
			if structured {
				break
			}
		}
	}
	if structured {
		return parseStructuredResilient(content)
	}

	res := &SubscriptionImportResult{
		Nodes:    []*Node{},
		Skipped:  []SkippedEntry{},
		Warnings: []string{},
	}
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		node, err := ParseURI(line)
		if err != nil {
			res.Skipped = append(res.Skipped, SkippedEntry{
				Index:  i + 1,
				Raw:    truncatePreview(line, 120),
				Reason: err.Error(),
			})
			continue
		}
		if node.AllowInsecure {
			res.Warnings = append(res.Warnings, fmt.Sprintf("Node %q skips TLS certificate verification (AllowInsecure)", node.Name))
		}
		res.Nodes = append(res.Nodes, node)
	}
	if len(res.Nodes) == 0 && len(res.Skipped) == 0 {
		return nil, fmt.Errorf("no supported nodes found")
	}
	return res, nil
}

func truncatePreview(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func parseBoolQuery(q url.Values, keys ...string) bool {
	for _, k := range keys {
		v := strings.ToLower(strings.TrimSpace(q.Get(k)))
		if v == "1" || v == "true" || v == "yes" {
			return true
		}
	}
	return false
}

func splitCSVQuery(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// ParseURI parses a single share URI for any of the 11 supported protocols.
func ParseURI(uri string) (*Node, error) {
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return ParseVMessURI(uri)
	case strings.HasPrefix(lower, "vless://"):
		return ParseVlessURI(uri)
	case strings.HasPrefix(lower, "trojan://"):
		return parseURLNode(uri, ProtocolTrojan)
	case strings.HasPrefix(lower, "ss://"):
		return ParseShadowsocksURI(uri)
	case strings.HasPrefix(lower, "hysteria2://"), strings.HasPrefix(lower, "hy2://"):
		return ParseHysteria2URI(uri)
	case strings.HasPrefix(lower, "tuic://"):
		return ParseTUICURI(uri)
	case strings.HasPrefix(lower, "anytls://"):
		return ParseAnyTLSURI(uri)
	case strings.HasPrefix(lower, "wireguard://"), strings.HasPrefix(lower, "wg://"):
		return ParseWireGuardURI(uri)
	case strings.HasPrefix(lower, "naive+https://"), strings.HasPrefix(lower, "naive+quic://"):
		return ParseNaiveURI(uri)
	case strings.HasPrefix(lower, "socks5://"), strings.HasPrefix(lower, "socks://"):
		return ParseSocksURI(uri)
	case strings.HasPrefix(lower, "https://"), strings.HasPrefix(lower, "http://"):
		return ParseHTTPURI(uri)
	default:
		return nil, fmt.Errorf("unsupported URI scheme")
	}
}

func ParseVlessURI(uri string) (*Node, error) { return parseURLNode(uri, ProtocolVLESS) }

func parseURLNode(uri string, protocol ProtocolEnum) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid node URI")
	}
	if u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("missing node credentials")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	q := u.Query()
	network := strings.ToLower(strings.TrimSpace(q.Get("type")))
	if network == "splithttp" {
		network = "xhttp"
	}
	node := &Node{
		Protocol:        protocol,
		Address:         u.Hostname(),
		Port:            port,
		Name:            u.Fragment,
		Network:         network,
		Security:        strings.ToLower(strings.TrimSpace(q.Get("security"))),
		AllowInsecure:   parseBoolQuery(q, "allowInsecure", "insecure"),
		Flow:            q.Get("flow"),
		Sni:             q.Get("sni"),
		Fingerprint:     q.Get("fp"),
		ALPN:            splitCSVQuery(q.Get("alpn")),
		PublicKey:       q.Get("pbk"),
		ShortID:         q.Get("sid"),
		SpiderX:         q.Get("spx"),
		MLDSA65Verify:   q.Get("pqv"),
		VLESSEncryption: q.Get("encryption"),
		Path:            q.Get("path"),
		Host:            q.Get("host"),
		ServiceName:     q.Get("serviceName"),
		XHTTPMode:       q.Get("mode"),
	}
	if extraRaw := strings.TrimSpace(q.Get("extra")); extraRaw != "" {
		var extra map[string]any
		if json.Unmarshal([]byte(extraRaw), &extra) == nil {
			node.XHTTPExtra = extra
		}
	}
	if protocol == ProtocolVLESS {
		node.UUID = u.User.Username()
	} else {
		node.Password = u.User.Username()
	}
	if node.Network == "" {
		node.Network = "tcp"
	}
	if node.Security == "" {
		if protocol == ProtocolTrojan {
			node.Security = "tls"
		} else {
			node.Security = "none"
		}
	}
	if node.Fingerprint == "" {
		node.Fingerprint = "chrome"
	}
	if protocol == ProtocolTrojan && node.Sni == "" {
		node.Sni = node.Address
	}
	if node.Name == "" {
		node.Name = string(protocol) + "-" + node.Address
	}
	return node, node.Validate()
}

func ParseShadowsocksURI(uri string) (*Node, error) {
	part := strings.TrimPrefix(uri, "ss://")
	if strings.HasPrefix(strings.ToLower(uri), "ss://") {
		part = uri[5:]
	}
	var name string
	if index := strings.Index(part, "#"); index >= 0 {
		var err error
		name, err = url.PathUnescape(part[index+1:])
		if err != nil {
			return nil, fmt.Errorf("invalid node name")
		}
		part = part[:index]
	}
	if !strings.Contains(part, "@") {
		decoded, err := decodeBase64(part)
		if err != nil {
			return nil, err
		}
		part = decoded
	}
	u, err := url.Parse("ss://" + part)
	if err != nil || u.User == nil {
		return nil, fmt.Errorf("invalid Shadowsocks URI")
	}
	q := u.Query()
	if q.Get("plugin") != "" {
		return nil, fmt.Errorf("Shadowsocks plugins are not supported")
	}
	method := u.User.Username()
	password, hasPassword := u.User.Password()
	if !hasPassword {
		decoded, err := decodeBase64(method)
		if err != nil {
			return nil, fmt.Errorf("invalid Shadowsocks credentials")
		}
		var ok bool
		method, password, ok = strings.Cut(decoded, ":")
		if !ok {
			return nil, fmt.Errorf("invalid Shadowsocks credentials")
		}
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	node := &Node{
		Protocol: ProtocolShadowsocks,
		Address:  u.Hostname(),
		Port:     port,
		Name:     name,
		Method:   method,
		Password: password,
		UoT:      parseBoolQuery(q, "uot", "udp-over-tcp"),
		Network:  "tcp",
		Security: "none",
	}
	if node.Name == "" {
		node.Name = "SS-" + node.Address
	}
	return node, node.Validate()
}

// ParseHysteria2URI parses `hysteria2://` and `hy2://` URIs.
func ParseHysteria2URI(uri string) (*Node, error) {
	normalized := uri
	if strings.HasPrefix(strings.ToLower(uri), "hy2://") {
		normalized = "hysteria2://" + uri[6:]
	}
	u, err := url.Parse(normalized)
	if err != nil || u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("invalid Hysteria2 URI")
	}
	password := u.User.Username()
	if p, hasPass := u.User.Password(); hasPass && p != "" {
		password = password + ":" + p
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	q := u.Query()
	upMbps, _ := strconv.Atoi(q.Get("upmbps"))
	downMbps, _ := strconv.Atoi(q.Get("downmbps"))
	node := &Node{
		Protocol:      ProtocolHysteria2,
		Name:          u.Fragment,
		Address:       u.Hostname(),
		Port:          port,
		Password:      password,
		Security:      "tls",
		Sni:           q.Get("sni"),
		AllowInsecure: parseBoolQuery(q, "insecure", "allowInsecure"),
		ALPN:          splitCSVQuery(q.Get("alpn")),
		ObfsType:      q.Get("obfs"),
		ObfsPassword:  q.Get("obfs-password"),
		HopPorts:      q.Get("mport"),
		HopInterval:   q.Get("hop-interval"),
		UpMbps:        upMbps,
		DownMbps:      downMbps,
	}
	if node.Sni == "" {
		node.Sni = node.Address
	}
	if node.Name == "" {
		node.Name = "Hy2-" + node.Address
	}
	return node, node.Validate()
}

// ParseTUICURI parses `tuic://uuid:password@host:port?...#name` URIs.
func ParseTUICURI(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil || u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("invalid TUIC URI")
	}
	password, _ := u.User.Password()
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	q := u.Query()
	cc := strings.ToLower(strings.TrimSpace(q.Get("congestion_control")))
	if cc == "" {
		cc = "bbr"
	}
	relay := strings.ToLower(strings.TrimSpace(q.Get("udp_relay_mode")))
	if relay == "" {
		relay = "native"
	}
	node := &Node{
		Protocol:          ProtocolTUIC,
		Name:              u.Fragment,
		Address:           u.Hostname(),
		Port:              port,
		UUID:              u.User.Username(),
		Password:          password,
		Security:          "tls",
		Sni:               q.Get("sni"),
		AllowInsecure:     parseBoolQuery(q, "allow_insecure", "insecure", "allowInsecure"),
		ALPN:              splitCSVQuery(q.Get("alpn")),
		CongestionControl: cc,
		UDPRelayMode:      relay,
		ZeroRTTHandshake:  parseBoolQuery(q, "zero_rtt", "reduce_rtt"),
	}
	if node.Sni == "" {
		node.Sni = node.Address
	}
	if node.Name == "" {
		node.Name = "TUIC-" + node.Address
	}
	return node, node.Validate()
}

// ParseAnyTLSURI parses `anytls://password@host:port?...#name` URIs.
func ParseAnyTLSURI(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil || u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("invalid AnyTLS URI")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	q := u.Query()
	node := &Node{
		Protocol:      ProtocolAnyTLS,
		Name:          u.Fragment,
		Address:       u.Hostname(),
		Port:          port,
		Password:      u.User.Username(),
		Security:      "tls",
		Sni:           q.Get("sni"),
		Fingerprint:   q.Get("fp"),
		AllowInsecure: parseBoolQuery(q, "insecure", "allowInsecure"),
		ALPN:          splitCSVQuery(q.Get("alpn")),
	}
	if node.Sni == "" {
		node.Sni = node.Address
	}
	if node.Fingerprint == "" {
		node.Fingerprint = "chrome"
	}
	if node.Name == "" {
		node.Name = "AnyTLS-" + node.Address
	}
	return node, node.Validate()
}

// ParseWireGuardURI parses `wireguard://` and `wg://` URIs.
func ParseWireGuardURI(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil || u.User == nil || u.User.Username() == "" {
		return nil, fmt.Errorf("invalid WireGuard URI")
	}
	port := 51820
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	q := u.Query()
	mtu, _ := strconv.Atoi(q.Get("mtu"))
	if mtu <= 0 {
		mtu = 1408
	}
	addrs := splitCSVQuery(q.Get("address"))
	if len(addrs) == 0 {
		addrs = []string{"10.0.0.2/32"}
	}
	var reserved []uint8
	for _, seg := range splitCSVQuery(q.Get("reserved")) {
		if v, err := strconv.Atoi(seg); err == nil && v >= 0 && v <= 255 {
			reserved = append(reserved, uint8(v))
		}
	}
	peerPK := q.Get("publickey")
	if peerPK == "" {
		peerPK = q.Get("public_key")
	}
	node := &Node{
		Protocol:       ProtocolWireGuard,
		Name:           u.Fragment,
		Address:        u.Hostname(),
		Port:           port,
		Security:       "none",
		PrivateKey:     u.User.Username(),
		PeerPublicKey:  peerPK,
		PreSharedKey:   q.Get("presharedkey"),
		LocalAddresses: addrs,
		Reserved:       reserved,
		MTU:            mtu,
	}
	if node.Name == "" {
		node.Name = "WG-" + node.Address
	}
	return node, node.Validate()
}

// ParseNaiveURI parses `naive+https://user:pass@host:port` and `naive+quic://` URIs.
func ParseNaiveURI(uri string) (*Node, error) {
	quic := strings.HasPrefix(strings.ToLower(uri), "naive+quic://")
	trimmed := uri
	if quic {
		trimmed = "https://" + uri[len("naive+quic://"):]
	} else {
		trimmed = "https://" + uri[len("naive+https://"):]
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return nil, fmt.Errorf("invalid NaiveProxy URI")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	q := u.Query()
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	node := &Node{
		Protocol:      ProtocolNaive,
		Name:          u.Fragment,
		Address:       u.Hostname(),
		Port:          port,
		Username:      user,
		Password:      pass,
		NaiveQuic:     quic,
		Security:      "tls",
		Sni:           q.Get("sni"),
		AllowInsecure: parseBoolQuery(q, "insecure", "allowInsecure"),
	}
	if node.Sni == "" {
		node.Sni = node.Address
	}
	if node.Name == "" {
		node.Name = "Naive-" + node.Address
	}
	return node, node.Validate()
}

// ParseSocksURI parses `socks://` or `socks5://` URIs.
func ParseSocksURI(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS URI")
	}
	port := 1080
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	node := &Node{
		Protocol: ProtocolSocks,
		Name:     u.Fragment,
		Address:  u.Hostname(),
		Port:     port,
		Username: user,
		Password: pass,
		Security: "none",
		Network:  "tcp",
	}
	if node.Name == "" {
		node.Name = "SOCKS-" + node.Address
	}
	return node, node.Validate()
}

// ParseHTTPURI parses `http://` and `https://` proxy URIs.
func ParseHTTPURI(uri string) (*Node, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid HTTP proxy URI")
	}
	isHTTPS := strings.EqualFold(u.Scheme, "https")
	port := 80
	if isHTTPS {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return nil, fmt.Errorf("invalid port")
		}
	}
	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}
	q := u.Query()
	sec := "none"
	if isHTTPS {
		sec = "tls"
	}
	node := &Node{
		Protocol:      ProtocolHTTP,
		Name:          u.Fragment,
		Address:       u.Hostname(),
		Port:          port,
		Username:      user,
		Password:      pass,
		Security:      sec,
		Sni:           q.Get("sni"),
		AllowInsecure: parseBoolQuery(q, "insecure", "allowInsecure"),
		Network:       "tcp",
	}
	if node.Name == "" {
		node.Name = "HTTP-" + node.Address
	}
	return node, node.Validate()
}

func parseWireGuardConfResilient(content string) (*SubscriptionImportResult, error) {
	n := &Node{
		Protocol:       ProtocolWireGuard,
		Security:       "none",
		LocalAddresses: []string{"10.0.0.2/32"},
		MTU:            1408,
	}
	section := ""
	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		val := strings.TrimSpace(v)
		switch section {
		case "interface":
			switch key {
			case "privatekey":
				n.PrivateKey = val
			case "address":
				n.LocalAddresses = splitCSVQuery(val)
			case "mtu":
				if m, err := strconv.Atoi(val); err == nil && m > 0 {
					n.MTU = m
				}
			}
		case "peer":
			switch key {
			case "publickey":
				n.PeerPublicKey = val
			case "presharedkey":
				n.PreSharedKey = val
			case "endpoint":
				host, portStr, err := splitHostPort(val)
				if err == nil {
					n.Address = host
					n.Port = portStr
				}
			}
		}
	}
	if n.Name == "" {
		n.Name = "WireGuard-" + n.Address
	}
	if err := n.Validate(); err != nil {
		return nil, fmt.Errorf("invalid WireGuard config: %w", err)
	}
	return &SubscriptionImportResult{
		Nodes:    []*Node{n},
		Skipped:  []SkippedEntry{},
		Warnings: []string{},
	}, nil
}

func splitHostPort(endpoint string) (string, int, error) {
	endpoint = strings.TrimSpace(endpoint)
	if strings.HasPrefix(endpoint, "[") {
		end := strings.LastIndex(endpoint, "]:")
		if end < 0 {
			return "", 0, fmt.Errorf("invalid IPv6 endpoint")
		}
		p, err := strconv.Atoi(endpoint[end+2:])
		return endpoint[1:end], p, err
	}
	idx := strings.LastIndex(endpoint, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("missing port")
	}
	p, err := strconv.Atoi(endpoint[idx+1:])
	return endpoint[:idx], p, err
}
