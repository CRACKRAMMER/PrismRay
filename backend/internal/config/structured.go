// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type record map[string]interface{}

func obj(v interface{}) record {
	switch m := v.(type) {
	case record:
		return m
	case map[string]interface{}:
		return m
	}
	return record{}
}

func arr(v interface{}) []interface{} { a, _ := v.([]interface{}); return a }

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func strList(v interface{}) []string {
	raw, ok := v.([]interface{})
	if !ok {
		if s, ok := v.([]string); ok {
			return append([]string(nil), s...)
		}
		if s := str(v); s != "" {
			return splitCSVQuery(s)
		}
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s := strings.TrimSpace(str(item)); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func num(v interface{}) int {
	if v == nil {
		return 0
	}
	n, err := strconv.Atoi(str(v))
	if err != nil {
		return -1
	}
	return n
}

func yes(v interface{}) bool { return v == true || str(v) == "true" || str(v) == "1" }

func stringMap(v interface{}) map[string]string {
	m := obj(v)
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		out[k] = str(val)
	}
	return out
}

func finish(n *Node) (*Node, error) {
	if n == nil {
		return nil, nil
	}
	if n.Protocol != ProtocolVLESS && n.Flow != "" {
		return nil, fmt.Errorf("flow is supported only for VLESS")
	}
	if n.Protocol == ProtocolShadowsocks && n.Method == "" {
		return nil, fmt.Errorf("Shadowsocks method is required")
	}
	if n.Network == "" {
		n.Network = "tcp"
	}
	if n.Network == "splithttp" {
		n.Network = "xhttp"
	}
	if n.Security == "" {
		switch n.Protocol {
		case ProtocolTrojan, ProtocolHysteria2, ProtocolTUIC, ProtocolAnyTLS, ProtocolNaive:
			n.Security = "tls"
		default:
			n.Security = "none"
		}
	}
	if n.Security != "none" && n.Security != "tls" && n.Security != "reality" {
		return nil, fmt.Errorf("unsupported TLS mode %q", n.Security)
	}
	if n.Fingerprint == "" && (n.Protocol == ProtocolVLESS || n.Protocol == ProtocolVMess || n.Protocol == ProtocolTrojan || n.Protocol == ProtocolAnyTLS) {
		n.Fingerprint = "chrome"
	}
	if n.Name == "" {
		n.Name = string(n.Protocol) + "-" + n.Address
	}
	return n, n.Validate()
}

func parseStructuredResilient(content string) (*SubscriptionImportResult, error) {
	decoder := yaml.NewDecoder(strings.NewReader(content))
	var root interface{}
	if e := decoder.Decode(&root); e != nil {
		return nil, fmt.Errorf("invalid JSON/YAML subscription")
	}
	var extra interface{}
	if e := decoder.Decode(&extra); e != io.EOF {
		return nil, fmt.Errorf("multiple YAML documents are not supported")
	}
	res := &SubscriptionImportResult{
		Nodes:    []*Node{},
		Skipped:  []SkippedEntry{},
		Warnings: []string{},
	}
	if err := extractResilient(root, 0, res); err != nil {
		return nil, err
	}
	if len(res.Nodes) > 10000 {
		return nil, fmt.Errorf("too many subscription nodes")
	}
	if len(res.Nodes) == 0 && len(res.Skipped) == 0 {
		return nil, fmt.Errorf("no supported nodes found")
	}
	return res, nil
}

func extractResilient(root interface{}, depth int, res *SubscriptionImportResult) error {
	if depth > 8 {
		return fmt.Errorf("subscription nesting too deep")
	}
	if list, ok := root.([]interface{}); ok {
		for _, v := range list {
			if err := extractResilient(v, depth+1, res); err != nil {
				return err
			}
		}
		return nil
	}
	m := obj(root)
	var list []interface{}
	var endpoints []interface{}
	format := ""
	switch {
	case m["proxies"] != nil:
		list = arr(m["proxies"])
		format = "clash"
	case m["outbounds"] != nil || m["endpoints"] != nil:
		list = arr(m["outbounds"])
		endpoints = arr(m["endpoints"])
		format = "outbound"
	case m["servers"] != nil:
		list = arr(m["servers"])
		format = "sip008"
	case m["server"] != nil && m["server_port"] != nil:
		list = []interface{}{m}
		format = "sip008"
	default:
		return fmt.Errorf("unrecognized subscription object (expected proxies, outbounds, endpoints, or servers)")
	}
	if len(list)+len(endpoints) > 10000 {
		return fmt.Errorf("too many subscription nodes")
	}

	process := func(idx int, formatKind string, entry record) {
		var n *Node
		var e error
		switch formatKind {
		case "clash":
			n, e = clashNode(entry)
		case "sip008":
			n = &Node{
				Protocol: ProtocolShadowsocks,
				Address:  str(entry["server"]),
				Port:     num(entry["server_port"]),
				Name:     str(entry["remarks"]),
				Method:   str(entry["method"]),
				Password: str(entry["password"]),
			}
		case "endpoint":
			n, e = singEndpoint(entry)
		case "outbound":
			if entry["protocol"] != nil {
				n, e = xrayNode(entry)
			} else {
				n, e = singNode(entry)
			}
		}
		if e == nil && n != nil {
			n, e = finish(n)
		}
		if e != nil {
			name := str(entry["name"])
			if name == "" {
				name = str(entry["tag"])
			}
			res.Skipped = append(res.Skipped, SkippedEntry{
				Index:  idx,
				Name:   name,
				Reason: e.Error(),
			})
			return
		}
		if n != nil {
			if n.AllowInsecure {
				res.Warnings = append(res.Warnings, fmt.Sprintf("Node %q skips TLS certificate verification (AllowInsecure)", n.Name))
			}
			res.Nodes = append(res.Nodes, n)
		}
	}

	for i, v := range list {
		process(i+1, format, obj(v))
	}
	for i, v := range endpoints {
		process(len(list)+i+1, "endpoint", obj(v))
	}
	return nil
}

func clashNode(m record) (*Node, error) {
	proto := strings.ToLower(strings.TrimSpace(str(m["type"])))
	switch proto {
	case "ss":
		proto = "shadowsocks"
	case "hy2":
		proto = "hysteria2"
	case "socks5":
		proto = "socks"
	}
	n := &Node{
		Protocol:      ProtocolEnum(proto),
		Name:          str(m["name"]),
		Address:       str(m["server"]),
		Port:          num(m["port"]),
		UUID:          str(m["uuid"]),
		Username:      str(m["username"]),
		Password:      str(m["password"]),
		Method:        str(m["cipher"]),
		Cipher:        str(m["cipher"]),
		AlterID:       num(m["alterId"]),
		Flow:          str(m["flow"]),
		UoT:           yes(m["udp-over-tcp"]),
		Network:       strings.ToLower(strings.TrimSpace(str(m["network"]))),
		Sni:           str(m["servername"]),
		Fingerprint:   str(m["client-fingerprint"]),
		AllowInsecure: yes(m["skip-cert-verify"]),
		ALPN:          strList(m["alpn"]),
	}
	if n.Protocol == ProtocolShadowsocks {
		n.Cipher = ""
	} else {
		n.Method = ""
	}
	if n.Sni == "" {
		n.Sni = str(m["sni"])
	}
	if yes(m["tls"]) || proto == "trojan" || proto == "hysteria2" || proto == "tuic" || proto == "anytls" {
		n.Security = "tls"
	}
	reality := obj(m["reality-opts"])
	if len(reality) > 0 {
		n.Security = "reality"
		n.PublicKey = str(reality["public-key"])
		n.ShortID = str(reality["short-id"])
	}
	ws := obj(m["ws-opts"])
	if len(ws) > 0 {
		n.Path = str(ws["path"])
		headers := stringMap(ws["headers"])
		n.WSHeaders = headers
		n.Host = headers["Host"]
		if med := num(ws["max-early-data"]); med > 0 {
			n.EarlyData = med
		}
		n.EarlyDataHeader = str(ws["early-data-header-name"])
	}
	grpc := obj(m["grpc-opts"])
	if len(grpc) > 0 {
		n.ServiceName = str(grpc["grpc-service-name"])
	}
	switch n.Protocol {
	case ProtocolHysteria2:
		n.ObfsType = str(m["obfs"])
		n.ObfsPassword = str(m["obfs-password"])
		n.HopPorts = str(m["ports"])
		if up := num(m["up"]); up > 0 {
			n.UpMbps = up
		}
		if down := num(m["down"]); down > 0 {
			n.DownMbps = down
		}
	case ProtocolTUIC:
		n.CongestionControl = str(m["congestion-controller"])
		n.UDPRelayMode = str(m["udp-relay-mode"])
		n.ZeroRTTHandshake = yes(m["reduce-rtt"])
	case ProtocolWireGuard:
		n.PrivateKey = str(m["private-key"])
		n.PeerPublicKey = str(m["public-key"])
		n.PreSharedKey = str(m["preshared-key"])
		if ip := str(m["ip"]); ip != "" {
			n.LocalAddresses = []string{ip + "/32"}
		}
		if mtu := num(m["mtu"]); mtu > 0 {
			n.MTU = mtu
		}
	}
	return n, nil
}

func singEndpoint(m record) (*Node, error) {
	if strings.ToLower(str(m["type"])) != "wireguard" {
		return nil, fmt.Errorf("unsupported sing-box endpoint %q", str(m["type"]))
	}
	n := &Node{
		Protocol:       ProtocolWireGuard,
		Name:           str(m["tag"]),
		PrivateKey:     str(m["private_key"]),
		LocalAddresses: strList(m["address"]),
		MTU:            num(m["mtu"]),
		Security:       "none",
	}
	if n.MTU <= 0 {
		n.MTU = 1408
	}
	peers := arr(m["peers"])
	if len(peers) > 0 {
		peer := obj(peers[0])
		n.Address = str(peer["address"])
		n.Port = num(peer["port"])
		n.PeerPublicKey = str(peer["public_key"])
		n.PreSharedKey = str(peer["pre_shared_key"])
		for _, r := range arr(peer["reserved"]) {
			if rv := num(r); rv >= 0 && rv <= 255 {
				n.Reserved = append(n.Reserved, uint8(rv))
			}
		}
	}
	return n, nil
}

func singNode(m record) (*Node, error) {
	proto := strings.ToLower(strings.TrimSpace(str(m["type"])))
	switch proto {
	case "direct", "block", "dns", "selector", "urltest":
		return nil, nil
	case "wireguard":
		return singEndpoint(m)
	}
	n := &Node{
		Protocol:                 ProtocolEnum(proto),
		Name:                     str(m["tag"]),
		Address:                  str(m["server"]),
		Port:                     num(m["server_port"]),
		UUID:                     str(m["uuid"]),
		Username:                 str(m["username"]),
		Password:                 str(m["password"]),
		Method:                   str(m["method"]),
		Cipher:                   str(m["security"]),
		AlterID:                  num(m["alter_id"]),
		Flow:                     str(m["flow"]),
		UoT:                      yes(m["udp_over_tcp"]),
		ObfsPassword:             str(obj(m["obfs"])["password"]),
		ObfsType:                 str(obj(m["obfs"])["type"]),
		HopPorts:                 strings.Join(strList(m["server_ports"]), ","),
		HopInterval:              str(m["hop_interval"]),
		UpMbps:                   num(m["up_mbps"]),
		DownMbps:                 num(m["down_mbps"]),
		CongestionControl:        str(m["congestion_control"]),
		UDPRelayMode:             str(m["udp_relay_mode"]),
		ZeroRTTHandshake:         yes(m["zero_rtt_handshake"]),
		Heartbeat:                str(m["heartbeat"]),
		IdleSessionCheckInterval: str(m["idle_session_check_interval"]),
		IdleSessionTimeout:       str(m["idle_session_timeout"]),
		MinIdleSession:           num(m["min_idle_session"]),
		NaiveQuic:                yes(m["quic"]),
		ExtraHeaders:             stringMap(m["extra_headers"]),
	}
	tls := obj(m["tls"])
	if yes(tls["enabled"]) {
		n.Security = "tls"
		n.Sni = str(tls["server_name"])
		n.Fingerprint = str(obj(tls["utls"])["fingerprint"])
		n.AllowInsecure = yes(tls["insecure"])
		n.ALPN = strList(tls["alpn"])
		reality := obj(tls["reality"])
		if yes(reality["enabled"]) {
			n.Security = "reality"
			n.PublicKey = str(reality["public_key"])
			n.ShortID = str(reality["short_id"])
		}
	}
	transport := obj(m["transport"])
	if len(transport) > 0 {
		n.Network = strings.ToLower(strings.TrimSpace(str(transport["type"])))
		n.Path = str(transport["path"])
		n.ServiceName = str(transport["service_name"])
		headers := stringMap(transport["headers"])
		n.WSHeaders = headers
		n.Host = headers["Host"]
		if med := num(transport["max_early_data"]); med > 0 {
			n.EarlyData = med
		}
		n.EarlyDataHeader = str(transport["early_data_header_name"])
	}
	return n, nil
}

func xrayNode(m record) (*Node, error) {
	proto := strings.ToLower(strings.TrimSpace(str(m["protocol"])))
	switch proto {
	case "freedom", "blackhole", "dns", "loopback":
		return nil, nil
	}
	n := &Node{
		Protocol:   ProtocolEnum(proto),
		Name:       str(m["tag"]),
		MuxEnabled: yes(obj(m["mux"])["enabled"]),
	}
	settings := obj(m["settings"])
	if proto == "vmess" || proto == "vless" {
		servers := arr(settings["vnext"])
		if len(servers) != 1 {
			return nil, fmt.Errorf("expected one vnext server")
		}
		server := obj(servers[0])
		users := arr(server["users"])
		if len(users) != 1 {
			return nil, fmt.Errorf("expected one outbound user")
		}
		user := obj(users[0])
		n.Address = str(server["address"])
		n.Port = num(server["port"])
		n.UUID = str(user["id"])
		n.Cipher = str(user["security"])
		n.VLESSEncryption = str(user["encryption"])
		n.AlterID = num(user["alterId"])
		n.Flow = str(user["flow"])
	} else {
		servers := arr(settings["servers"])
		if len(servers) != 1 {
			return nil, fmt.Errorf("expected one outbound server for %s", proto)
		}
		server := obj(servers[0])
		n.Address = str(server["address"])
		n.Port = num(server["port"])
		n.Password = str(server["password"])
		n.Method = str(server["method"])
		if users := arr(server["users"]); len(users) > 0 {
			u := obj(users[0])
			n.Username = str(u["user"])
			n.Password = str(u["pass"])
		}
	}
	stream := obj(m["streamSettings"])
	n.Network = strings.ToLower(strings.TrimSpace(str(stream["network"])))
	if n.Network == "raw" {
		n.Network = "tcp"
	}
	n.Security = strings.ToLower(strings.TrimSpace(str(stream["security"])))
	tls := obj(stream["tlsSettings"])
	if len(tls) > 0 {
		n.Sni = str(tls["serverName"])
		n.Fingerprint = str(tls["fingerprint"])
		n.AllowInsecure = yes(tls["allowInsecure"])
		n.ALPN = strList(tls["alpn"])
	}
	reality := obj(stream["realitySettings"])
	if len(reality) > 0 {
		n.Sni = str(reality["serverName"])
		n.Fingerprint = str(reality["fingerprint"])
		n.PublicKey = str(reality["publicKey"])
		if n.PublicKey == "" {
			n.PublicKey = str(reality["password"])
		}
		n.ShortID = str(reality["shortId"])
		n.SpiderX = str(reality["spiderX"])
		n.MLDSA65Verify = str(reality["mldsa65Verify"])
	}
	ws := obj(stream["wsSettings"])
	if len(ws) > 0 {
		n.Path = str(ws["path"])
		headers := stringMap(ws["headers"])
		n.WSHeaders = headers
		n.Host = headers["Host"]
		if str(ws["host"]) != "" {
			n.Host = str(ws["host"])
		}
	}
	if xhttp := obj(stream["xhttpSettings"]); len(xhttp) > 0 {
		n.Path = str(xhttp["path"])
		n.Host = str(xhttp["host"])
		n.XHTTPMode = str(xhttp["mode"])
		if extra := obj(xhttp["extra"]); len(extra) > 0 {
			n.XHTTPExtra = extra
		}
	}
	if hu := obj(stream["httpupgradeSettings"]); len(hu) > 0 {
		n.Path = str(hu["path"])
		n.Host = str(hu["host"])
	}
	if grpc := obj(stream["grpcSettings"]); len(grpc) > 0 {
		n.ServiceName = str(grpc["serviceName"])
	}
	return n, nil
}

func ParseVMessURI(uri string) (*Node, error) {
	raw, e := decodeBase64(strings.TrimPrefix(uri, "vmess://"))
	if e != nil {
		return nil, fmt.Errorf("invalid VMess base64")
	}
	var m map[string]interface{}
	if json.Unmarshal([]byte(raw), &m) != nil {
		return nil, fmt.Errorf("invalid VMess JSON")
	}
	n := &Node{
		Protocol:      ProtocolVMess,
		Name:          str(m["ps"]),
		Address:       str(m["add"]),
		Port:          num(m["port"]),
		UUID:          str(m["id"]),
		AlterID:       num(m["aid"]),
		Cipher:        str(m["scy"]),
		Network:       str(m["net"]),
		Security:      str(m["tls"]),
		AllowInsecure: yes(m["allowInsecure"]) || yes(m["insecure"]),
		Sni:           str(m["sni"]),
		Fingerprint:   str(m["fp"]),
		ALPN:          strList(m["alpn"]),
		Host:          str(m["host"]),
		Path:          str(m["path"]),
	}
	if n.Network == "grpc" {
		n.ServiceName = n.Path
		n.Path = ""
	}
	if str(m["type"]) != "" && str(m["type"]) != "none" {
		return nil, fmt.Errorf("VMess header obfuscation is not supported")
	}
	return finish(n)
}
