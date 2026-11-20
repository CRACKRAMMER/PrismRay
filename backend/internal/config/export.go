// SPDX-License-Identifier: MPL-2.0

package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

func boolQueryStr(b bool) string {
	if b {
		return "1"
	}
	return ""
}

// URI serializes any supported Node into its share URI representation.
func (n *Node) URI() string {
	switch n.Protocol {
	case ProtocolVMess:
		path := n.Path
		if n.Network == "grpc" {
			path = n.ServiceName
		}
		security := n.Security
		if security == "none" {
			security = ""
		}
		raw, _ := json.Marshal(map[string]interface{}{
			"v":    "2",
			"ps":   n.Name,
			"add":  n.Address,
			"port": n.Port,
			"id":   n.UUID,
			"aid":  n.AlterID,
			"scy":  n.Cipher,
			"net":  n.Network,
			"type": "none",
			"tls":  security,
			"sni":  n.Sni,
			"fp":   n.Fingerprint,
			"host": n.Host,
			"path": path,
		})
		return "vmess://" + base64.StdEncoding.EncodeToString(raw)

	case ProtocolShadowsocks:
		u := url.URL{Scheme: "ss", Host: net.JoinHostPort(n.Address, strconv.Itoa(n.Port)), Fragment: n.Name}
		method := n.Method
		if method == "" {
			method = n.Security
		}
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(method + ":" + n.Password)))
		if n.UoT {
			u.RawQuery = "uot=1"
		}
		return u.String()

	case ProtocolHysteria2:
		u := url.URL{
			Scheme:   "hysteria2",
			User:     url.User(n.Password),
			Host:     net.JoinHostPort(n.Address, strconv.Itoa(n.Port)),
			Fragment: n.Name,
		}
		q := url.Values{}
		for k, v := range map[string]string{
			"sni":           n.Sni,
			"insecure":      boolQueryStr(n.AllowInsecure),
			"alpn":          strings.Join(n.ALPN, ","),
			"obfs":          n.ObfsType,
			"obfs-password": n.ObfsPassword,
			"mport":         n.HopPorts,
			"hop-interval":  n.HopInterval,
		} {
			if v != "" {
				q.Set(k, v)
			}
		}
		if n.UpMbps > 0 {
			q.Set("upmbps", strconv.Itoa(n.UpMbps))
		}
		if n.DownMbps > 0 {
			q.Set("downmbps", strconv.Itoa(n.DownMbps))
		}
		if len(n.XHTTPExtra) > 0 {
			if b, err := json.Marshal(n.XHTTPExtra); err == nil {
				q.Set("extra", string(b))
			}
		}
		u.RawQuery = q.Encode()
		return u.String()

	case ProtocolTUIC:
		u := url.URL{
			Scheme:   "tuic",
			User:     url.UserPassword(n.UUID, n.Password),
			Host:     net.JoinHostPort(n.Address, strconv.Itoa(n.Port)),
			Fragment: n.Name,
		}
		q := url.Values{}
		for k, v := range map[string]string{
			"sni":                n.Sni,
			"alpn":               strings.Join(n.ALPN, ","),
			"congestion_control": n.CongestionControl,
			"udp_relay_mode":     n.UDPRelayMode,
			"allow_insecure":     boolQueryStr(n.AllowInsecure),
			"zero_rtt":           boolQueryStr(n.ZeroRTTHandshake),
		} {
			if v != "" {
				q.Set(k, v)
			}
		}
		if len(n.XHTTPExtra) > 0 {
			if b, err := json.Marshal(n.XHTTPExtra); err == nil {
				q.Set("extra", string(b))
			}
		}
		u.RawQuery = q.Encode()
		return u.String()

	case ProtocolAnyTLS:
		u := url.URL{
			Scheme:   "anytls",
			User:     url.User(n.Password),
			Host:     net.JoinHostPort(n.Address, strconv.Itoa(n.Port)),
			Fragment: n.Name,
		}
		q := url.Values{}
		for k, v := range map[string]string{
			"sni":      n.Sni,
			"fp":       n.Fingerprint,
			"alpn":     strings.Join(n.ALPN, ","),
			"insecure": boolQueryStr(n.AllowInsecure),
		} {
			if v != "" {
				q.Set(k, v)
			}
		}
		if len(n.XHTTPExtra) > 0 {
			if b, err := json.Marshal(n.XHTTPExtra); err == nil {
				q.Set("extra", string(b))
			}
		}
		u.RawQuery = q.Encode()
		return u.String()

	case ProtocolWireGuard:
		u := url.URL{
			Scheme:   "wireguard",
			User:     url.User(n.PrivateKey),
			Host:     net.JoinHostPort(n.Address, strconv.Itoa(n.Port)),
			Fragment: n.Name,
		}
		q := url.Values{}
		pk := n.PeerPublicKey
		if pk == "" {
			pk = n.PublicKey
		}
		if pk != "" {
			q.Set("publickey", pk)
		}
		if n.PreSharedKey != "" {
			q.Set("presharedkey", n.PreSharedKey)
		}
		if len(n.LocalAddresses) > 0 {
			q.Set("address", strings.Join(n.LocalAddresses, ","))
		}
		if n.MTU > 0 {
			q.Set("mtu", strconv.Itoa(n.MTU))
		}
		if len(n.Reserved) > 0 {
			parts := make([]string, len(n.Reserved))
			for i, r := range n.Reserved {
				parts[i] = strconv.Itoa(int(r))
			}
			q.Set("reserved", strings.Join(parts, ","))
		}
		if len(n.XHTTPExtra) > 0 {
			if b, err := json.Marshal(n.XHTTPExtra); err == nil {
				q.Set("extra", string(b))
			}
		}
		u.RawQuery = q.Encode()
		return u.String()

	case ProtocolNaive:
		scheme := "naive+https"
		if n.NaiveQuic {
			scheme = "naive+quic"
		}
		u := url.URL{
			Scheme:   scheme,
			Host:     net.JoinHostPort(n.Address, strconv.Itoa(n.Port)),
			Fragment: n.Name,
		}
		if n.Username != "" {
			u.User = url.UserPassword(n.Username, n.Password)
		}
		q := url.Values{}
		if n.Sni != "" {
			q.Set("sni", n.Sni)
		}
		if n.AllowInsecure {
			q.Set("insecure", "1")
		}
		if len(n.XHTTPExtra) > 0 {
			if b, err := json.Marshal(n.XHTTPExtra); err == nil {
				q.Set("extra", string(b))
			}
		}
		u.RawQuery = q.Encode()
		return u.String()

	case ProtocolSocks:
		u := url.URL{Scheme: "socks5", Host: net.JoinHostPort(n.Address, strconv.Itoa(n.Port)), Fragment: n.Name}
		if n.Username != "" {
			u.User = url.UserPassword(n.Username, n.Password)
		}
		return u.String()

	case ProtocolHTTP:
		scheme := "http"
		if n.Security == "tls" {
			scheme = "https"
		}
		u := url.URL{Scheme: scheme, Host: net.JoinHostPort(n.Address, strconv.Itoa(n.Port)), Fragment: n.Name}
		if n.Username != "" {
			u.User = url.UserPassword(n.Username, n.Password)
		}
		q := url.Values{}
		if n.Sni != "" {
			q.Set("sni", n.Sni)
		}
		if n.AllowInsecure {
			q.Set("insecure", "1")
		}
		if len(n.XHTTPExtra) > 0 {
			if b, err := json.Marshal(n.XHTTPExtra); err == nil {
				q.Set("extra", string(b))
			}
		}
		u.RawQuery = q.Encode()
		return u.String()
	}

	u := url.URL{Scheme: string(n.Protocol), Host: net.JoinHostPort(n.Address, strconv.Itoa(n.Port)), Fragment: n.Name}
	if n.Protocol == ProtocolVLESS {
		u.User = url.User(n.UUID)
	} else {
		u.User = url.User(n.Password)
	}
	q := url.Values{}
	for k, v := range map[string]string{
		"security":      n.Security,
		"type":          n.Network,
		"sni":           n.Sni,
		"fp":            n.Fingerprint,
		"alpn":          strings.Join(n.ALPN, ","),
		"pbk":           n.PublicKey,
		"sid":           n.ShortID,
		"spx":           n.SpiderX,
		"pqv":           n.MLDSA65Verify,
		"encryption":    n.VLESSEncryption,
		"flow":          n.Flow,
		"path":          n.Path,
		"host":          n.Host,
		"serviceName":   n.ServiceName,
		"mode":          n.XHTTPMode,
		"allowInsecure": boolQueryStr(n.AllowInsecure),
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if len(n.XHTTPExtra) > 0 {
		if b, err := json.Marshal(n.XHTTPExtra); err == nil {
			q.Set("extra", string(b))
		}
	}
	u.RawQuery = q.Encode()
	return fmt.Sprint(u.String())
}
