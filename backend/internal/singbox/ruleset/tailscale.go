// SPDX-License-Identifier: MPL-2.0

package ruleset

import (
	"fmt"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"time"
)

const (
	// TailscaleEndpointTag is the canonical sing-box endpoint tag for the built-in Tailscale Mesh client.
	TailscaleEndpointTag = "tailscale-ep"
	// TailscaleDNSTag is the canonical sing-box MagicDNS server tag backed by TailscaleEndpointTag.
	TailscaleDNSTag = "tailscale-dns"
)

// TailscaleConfig configures PrismRay's built-in parallel Tailscale / Headscale mesh endpoint
// powered by sing-box's native with_tailscale (tsnet) integration.
type TailscaleConfig struct {
	Enabled           bool     `json:"enabled"`
	ControlURL        string   `json:"control_url,omitempty"`
	AuthKey           string   `json:"auth_key,omitempty"`
	HasAuthKey        bool     `json:"has_auth_key,omitempty"`
	ClearAuthKey      bool     `json:"clear_auth_key,omitempty"`
	Hostname          string   `json:"hostname,omitempty"`
	Ephemeral         bool     `json:"ephemeral,omitempty"`
	AcceptRoutes      bool     `json:"accept_routes"`
	ExitNode          string   `json:"exit_node,omitempty"`
	ExitNodeAllowLAN  bool     `json:"exit_node_allow_lan,omitempty"`
	AdvertiseRoutes   []string `json:"advertise_routes,omitempty"`
	AdvertiseExitNode bool     `json:"advertise_exit_node,omitempty"`
	MagicDNS          bool     `json:"magic_dns"`
	ExtraDomains      []string `json:"extra_domains,omitempty"`
	ExtraSubnets      []string `json:"extra_subnets,omitempty"`
	DetourID          string   `json:"detour_id,omitempty"`
	UDPTimeout        string   `json:"udp_timeout,omitempty"`
}

// DefaultTailscaleConfig returns safe defaults (disabled until configured by the user).
func DefaultTailscaleConfig() TailscaleConfig {
	return TailscaleConfig{
		Enabled:      false,
		Hostname:     "prismray-" + runtime.GOOS,
		AcceptRoutes: true,
		MagicDNS:     true,
		UDPTimeout:   "5m",
	}
}

// Normalize sanitizes string fields and restores safe defaults.
func (c *TailscaleConfig) Normalize() {
	c.ControlURL = strings.TrimSpace(c.ControlURL)
	c.AuthKey = strings.TrimSpace(c.AuthKey)
	c.Hostname = strings.TrimSpace(c.Hostname)
	if c.Hostname == "" {
		c.Hostname = "prismray-" + runtime.GOOS
	}
	c.ExitNode = strings.TrimSpace(c.ExitNode)
	c.DetourID = strings.TrimSpace(c.DetourID)
	c.UDPTimeout = strings.TrimSpace(c.UDPTimeout)
	if c.UDPTimeout == "" {
		c.UDPTimeout = "5m"
	}
	c.AdvertiseRoutes = cleanUniqueStrings(c.AdvertiseRoutes)
	c.ExtraSubnets = cleanUniqueStrings(c.ExtraSubnets)
	c.ExtraDomains = cleanUniqueDomains(c.ExtraDomains)
}

// Validate checks TailscaleConfig fields before persisting or compiling.
func (c *TailscaleConfig) Validate() error {
	c.Normalize()
	if c.ControlURL != "" {
		u, err := url.ParseRequestURI(c.ControlURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || strings.TrimSpace(u.Host) == "" {
			return fmt.Errorf("Tailscale 控制服务器地址必须为有效的 http(s) URL")
		}
	}
	for _, r := range c.Hostname {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return fmt.Errorf("Tailscale 主机名仅支持字母、数字、连字符和下划线")
		}
	}
	if len(c.Hostname) > 63 {
		return fmt.Errorf("Tailscale 主机名不能超过 63 个字符")
	}
	for _, cidr := range c.AdvertiseRoutes {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("无效的宣告网段 CIDR %q: %w", cidr, err)
		}
	}
	for _, cidr := range c.ExtraSubnets {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("无效的内网子网 CIDR %q: %w", cidr, err)
		}
	}
	if d, err := time.ParseDuration(c.UDPTimeout); err != nil || d <= 0 {
		return fmt.Errorf("无效的 UDP 超时时长 %q (例如 5m)", c.UDPTimeout)
	}
	return nil
}

// EffectiveDomains returns the Tailnet DNS suffixes routed to tailscale-dns and tailscale-ep.
func (c TailscaleConfig) EffectiveDomains() []string {
	out := []string{".ts.net"}
	seen := map[string]bool{".ts.net": true, "ts.net": true}
	for _, raw := range c.ExtraDomains {
		d := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if d == "" || seen[d] || seen["."+d] {
			continue
		}
		seen[d] = true
		seen["."+d] = true
		out = append(out, "."+d)
	}
	return out
}

// EffectiveSubnets returns the Tailscale CGNAT/ULA CIDRs plus any user-configured extra subnets.
func (c TailscaleConfig) EffectiveSubnets() []string {
	out := []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48"}
	seen := map[string]bool{"100.64.0.0/10": true, "fd7a:115c:a1e0::/48": true}
	for _, raw := range c.ExtraSubnets {
		if pfx, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
			canon := pfx.Masked().String()
			if !seen[canon] {
				seen[canon] = true
				out = append(out, canon)
			}
		}
	}
	return out
}

func cleanUniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		v := strings.TrimSpace(item)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func cleanUniqueDomains(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, item := range in {
		v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(item)), ".")
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
