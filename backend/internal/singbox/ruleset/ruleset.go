// SPDX-License-Identifier: MPL-2.0

package ruleset

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
)

// BuiltinTag enumerates default rule-set tags managed by PrismRay.
const (
	TagGeoSiteCN    = "geosite-cn"
	TagGeoIPCN      = "geoip-cn"
	TagGeoSiteNotCN = "geosite-geolocation-!cn"
	TagGeoSiteAds   = "geosite-category-ads-all"
)

// RuleSetSpec describes one built-in or custom .srs rule set.
type RuleSetSpec struct {
	ID             string `json:"id"`
	Tag            string `json:"tag"`
	Format         string `json:"format"`      // binary | source
	SourceType     string `json:"source_type"` // remote | local | inline
	URL            string `json:"url"`
	LocalPath      string `json:"local_path"`
	UpdateInterval string `json:"update_interval"`
	Enabled        bool   `json:"enabled"`
	Synced         bool   `json:"synced"`
	SizeBytes      int64  `json:"size_bytes"`
	LastSyncedAt   string `json:"last_synced_at,omitempty"`
}

// RoutingRule defines one ordered matching rule compiled to sing-box route.rules.
type RoutingRule struct {
	ID            string   `json:"id,omitempty"`
	Name          string   `json:"name,omitempty"`
	Enabled       bool     `json:"enabled"`
	Domains       []string `json:"domains,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`
	SourceIPCIDR  []string `json:"source_ip_cidr,omitempty"`
	IPIsPrivate   bool     `json:"ip_is_private,omitempty"`
	RuleSet       []string `json:"rule_set,omitempty"`
	Network       []string `json:"network,omitempty"` // tcp | udp
	Port          []int    `json:"port,omitempty"`
	PortRange     []string `json:"port_range,omitempty"` // start:end
	SourcePort    []int    `json:"source_port,omitempty"`
	ProcessName   []string `json:"process_name,omitempty"`
	ProcessPath   []string `json:"process_path,omitempty"`
	PackageName   []string `json:"package_name,omitempty"`
	Protocol      []string `json:"protocol,omitempty"`
	Inbound       []string `json:"inbound,omitempty"`
	Invert        bool     `json:"invert,omitempty"`
	Outbound      string   `json:"outbound"` // "proxy" | "direct" | "block" | node/group tag
}

const (
	defaultFakeIPv4Range = "198.18.0.0/15"
	defaultFakeIPv6Range = "fc00::/18"
)

// BoolPtr returns a pointer to v for optional boolean profile fields.
func BoolPtr(v bool) *bool { return &v }

// RoutingProfile holds v1.0 routing, DNS preset, FakeIP, WebRTC, and Android per-app settings.
type RoutingProfile struct {
	Mode              string        `json:"mode"` // "rule" | "global" | "direct"
	BlockAds          bool          `json:"block_ads"`
	BypassLAN         bool          `json:"bypass_lan"`
	AllowLANBroadcast bool          `json:"allow_lan_broadcast,omitempty"`
	BypassCN          bool          `json:"bypass_cn"`
	LocalDNS          string        `json:"local_dns"`
	RemoteDNS         string        `json:"remote_dns"`
	DomainStrategy    string        `json:"domain_strategy,omitempty"` // prefer_ipv4 | prefer_ipv6 | ipv4_only | as_is
	HijackDNS         *bool         `json:"hijack_dns,omitempty"`
	FakeIP            bool          `json:"fake_ip"`
	FakeIPv4Range     string        `json:"fake_ip_v4_range,omitempty"`
	FakeIPv6Range     string        `json:"fake_ip_v6_range,omitempty"`
	FakeIPFilter      []string      `json:"fake_ip_filter,omitempty"`
	KillSwitch        *bool         `json:"kill_switch,omitempty"`
	WebRTCMode        string        `json:"webrtc_mode,omitempty"` // block | proxy | direct
	LogLevel          string        `json:"log_level,omitempty"`
	PerAppMode        string        `json:"per_app_mode,omitempty"` // all | whitelist | blacklist
	PerAppPackages    []string      `json:"per_app_packages,omitempty"`
	CustomRules       []RoutingRule `json:"custom_rules"`
}

// HijackDNSEnabled reports whether DNS traffic interception is enabled (defaults to true).
func (p RoutingProfile) HijackDNSEnabled() bool {
	return p.HijackDNS == nil || *p.HijackDNS
}

// KillSwitchEnabled reports whether proxy fail-closed protection is active (defaults to true).
func (p RoutingProfile) KillSwitchEnabled() bool {
	return p.KillSwitch == nil || *p.KillSwitch
}

// IPv6Enabled reports whether TUN IPv6 routing and proxied AAAA/HTTPS IPv6 hints should be enabled.
// Defaults to false for "prefer_ipv4" and "ipv4_only" so IPv4-only proxy nodes do not break Happy Eyeballs.
func (p RoutingProfile) IPv6Enabled() bool {
	switch p.DomainStrategy {
	case "prefer_ipv6", "ipv6_only", "as_is":
		return true
	default:
		return false
	}
}

// DefaultRoutingProfile returns the recommended rule-based profile (FakeIP disabled, WebRTC blocked by default).
func DefaultRoutingProfile() RoutingProfile {
	return RoutingProfile{
		Mode:              "rule",
		BlockAds:          true,
		BypassLAN:         true,
		AllowLANBroadcast: false,
		BypassCN:          true,
		LocalDNS:          "223.5.5.5",
		RemoteDNS:         "https://dns.google/dns-query",
		DomainStrategy:    "prefer_ipv4",
		HijackDNS:         BoolPtr(true),
		FakeIP:            false,
		FakeIPv4Range:     defaultFakeIPv4Range,
		FakeIPv6Range:     defaultFakeIPv6Range,
		FakeIPFilter:      []string{},
		KillSwitch:        BoolPtr(true),
		WebRTCMode:        "block",
		LogLevel:          "info",
		PerAppMode:        "all",
		PerAppPackages:    []string{},
		CustomRules:       []RoutingRule{},
	}
}

// Normalize cleans defaults without mutating valid caller choices.
func (p *RoutingProfile) Normalize() {
	switch p.Mode {
	case "rule", "global", "direct":
	default:
		p.Mode = "rule"
	}
	if strings.TrimSpace(p.LocalDNS) == "" {
		p.LocalDNS = "223.5.5.5"
	}
	if strings.TrimSpace(p.RemoteDNS) == "" {
		p.RemoteDNS = "https://dns.google/dns-query"
	}
	switch p.DomainStrategy {
	case "", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only", "as_is":
	default:
		p.DomainStrategy = "prefer_ipv4"
	}
	if p.DomainStrategy == "" {
		p.DomainStrategy = "prefer_ipv4"
	}
	if p.HijackDNS == nil {
		p.HijackDNS = BoolPtr(true)
	}
	if p.KillSwitch == nil {
		p.KillSwitch = BoolPtr(true)
	}
	switch strings.ToLower(strings.TrimSpace(p.WebRTCMode)) {
	case "block", "proxy", "direct":
		p.WebRTCMode = strings.ToLower(strings.TrimSpace(p.WebRTCMode))
	default:
		p.WebRTCMode = "block"
	}
	for i := range p.CustomRules {
		if len(p.CustomRules[i].Network) > 0 {
			nets := make([]string, 0, len(p.CustomRules[i].Network))
			for _, net := range p.CustomRules[i].Network {
				n := strings.ToLower(strings.TrimSpace(net))
				if n == "tcp" || n == "udp" {
					nets = append(nets, n)
				}
			}
			p.CustomRules[i].Network = nets
		}
		if len(p.CustomRules[i].PortRange) > 0 {
			ranges := make([]string, 0, len(p.CustomRules[i].PortRange))
			for _, pr := range p.CustomRules[i].PortRange {
				clean := strings.ReplaceAll(strings.TrimSpace(pr), "-", ":")
				if clean != "" {
					ranges = append(ranges, clean)
				}
			}
			p.CustomRules[i].PortRange = ranges
		}
	}
	v4 := strings.TrimSpace(p.FakeIPv4Range)
	if pfx, err := netip.ParsePrefix(v4); err != nil || !pfx.Addr().Is4() {
		p.FakeIPv4Range = defaultFakeIPv4Range
	} else {
		p.FakeIPv4Range = pfx.Masked().String()
	}
	v6 := strings.TrimSpace(p.FakeIPv6Range)
	if pfx, err := netip.ParsePrefix(v6); err != nil || !pfx.Addr().Is6() {
		p.FakeIPv6Range = defaultFakeIPv6Range
	} else {
		p.FakeIPv6Range = pfx.Masked().String()
	}
	if len(p.FakeIPFilter) > 0 {
		seen := make(map[string]bool, len(p.FakeIPFilter))
		cleaned := make([]string, 0, len(p.FakeIPFilter))
		for _, entry := range p.FakeIPFilter {
			val := strings.ToLower(strings.TrimSpace(entry))
			if val == "" || seen[val] {
				continue
			}
			seen[val] = true
			cleaned = append(cleaned, val)
		}
		p.FakeIPFilter = cleaned
	} else {
		p.FakeIPFilter = []string{}
	}
	switch p.LogLevel {
	case "trace", "debug", "info", "warn", "error":
	default:
		p.LogLevel = "info"
	}
	switch p.PerAppMode {
	case "all", "whitelist", "blacklist":
	default:
		p.PerAppMode = "all"
	}
	// LAN broadcast / multicast bypass requires BypassLAN to be enabled.
	if !p.BypassLAN {
		p.AllowLANBroadcast = false
	}
}

// BuiltinRuleSets returns the canonical 2026 sing-box .srs rule sets.
func BuiltinRuleSets(dir string) []RuleSetSpec {
	specs := []RuleSetSpec{
		{
			ID:             "builtin-geosite-cn",
			Tag:            TagGeoSiteCN,
			Format:         "binary",
			SourceType:     "remote",
			URL:            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs",
			UpdateInterval: "24h",
			Enabled:        true,
		},
		{
			ID:             "builtin-geoip-cn",
			Tag:            TagGeoIPCN,
			Format:         "binary",
			SourceType:     "remote",
			URL:            "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs",
			UpdateInterval: "24h",
			Enabled:        true,
		},
		{
			ID:             "builtin-geosite-not-cn",
			Tag:            TagGeoSiteNotCN,
			Format:         "binary",
			SourceType:     "remote",
			URL:            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs",
			UpdateInterval: "24h",
			Enabled:        true,
		},
		{
			ID:             "builtin-geosite-ads",
			Tag:            TagGeoSiteAds,
			Format:         "binary",
			SourceType:     "remote",
			URL:            "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs",
			UpdateInterval: "24h",
			Enabled:        true,
		},
	}
	for i := range specs {
		if dir != "" {
			specs[i].LocalPath = filepath.Join(dir, specs[i].Tag+".srs")
			if st, err := os.Stat(specs[i].LocalPath); err == nil && st.Size() > 0 {
				specs[i].Synced = true
				specs[i].SizeBytes = st.Size()
				specs[i].LastSyncedAt = st.ModTime().UTC().Format(time.RFC3339)
			}
		}
	}
	return specs
}

// SyncRuleSet downloads one .srs binary rule set to disk safely.
func SyncRuleSet(ctx context.Context, client *http.Client, spec RuleSetSpec) (RuleSetSpec, error) {
	if strings.TrimSpace(spec.URL) == "" || strings.TrimSpace(spec.LocalPath) == "" {
		return spec, fmt.Errorf("rule set URL and local path are required")
	}
	parsedURL, err := url.ParseRequestURI(strings.TrimSpace(spec.URL))
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || strings.TrimSpace(parsedURL.Host) == "" {
		return spec, fmt.Errorf("rule set URL must be http or https")
	}
	for _, seg := range strings.FieldsFunc(spec.LocalPath, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return spec, fmt.Errorf("rule set local path cannot contain '..'")
		}
	}
	if client == nil {
		client = &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
					return fmt.Errorf("unsupported redirect scheme %q", req.URL.Scheme)
				}
				return nil
			},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return spec, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return spec, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return spec, fmt.Errorf("rule set download HTTP %d", resp.StatusCode)
	}
	const maxRuleSetBytes = 32 << 20
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRuleSetBytes+1))
	if err != nil {
		return spec, err
	}
	if len(body) == 0 || len(body) > maxRuleSetBytes {
		return spec, fmt.Errorf("invalid rule set size %d", len(body))
	}
	if err := os.MkdirAll(filepath.Dir(spec.LocalPath), 0700); err != nil {
		return spec, err
	}
	if err := fileutil.WritePrivate(spec.LocalPath, body); err != nil {
		return spec, err
	}
	spec.Synced = true
	spec.SizeBytes = int64(len(body))
	spec.LastSyncedAt = time.Now().UTC().Format(time.RFC3339)
	return spec, nil
}

// SimulationInput describes a connection tuple tested against a RoutingProfile.
type SimulationInput struct {
	Domain      string `json:"domain,omitempty"`
	IP          string `json:"ip,omitempty"`
	SourceIP    string `json:"source_ip,omitempty"`
	Network     string `json:"network,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
	PackageName string `json:"package_name,omitempty"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Inbound     string `json:"inbound,omitempty"`
}

// SimulationResult reports which rule matched and which outbound handles the traffic.
type SimulationResult struct {
	Outbound    string `json:"outbound"`
	MatchedRule string `json:"matched_rule"`
	Action      string `json:"action"` // route | reject
}

func isFakeIPAddr(profile RoutingProfile, ip netip.Addr) bool {
	if !profile.FakeIP {
		return false
	}
	for _, raw := range []string{profile.FakeIPv4Range, profile.FakeIPv6Range} {
		if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}

func isSTUNPort(port int) bool {
	switch port {
	case 3478, 5349, 19302, 19305, 19306, 19307:
		return true
	default:
		return false
	}
}

func isWebRTCTraffic(domain string, in SimulationInput) bool {
	if strings.EqualFold(strings.TrimSpace(in.Protocol), "stun") {
		return true
	}
	if strings.Contains(domain, "stun.") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(in.Network), "udp") && isSTUNPort(in.Port)
}

// Simulate evaluates a sample connection against the profile in compilation order.
func Simulate(profile RoutingProfile, in SimulationInput) SimulationResult {
	profile.Normalize()
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Domain), "."))
	ipStr := strings.TrimSpace(in.IP)
	var parsedIP netip.Addr
	var hasIP bool
	if ipStr != "" {
		if addr, err := netip.ParseAddr(ipStr); err == nil {
			parsedIP = addr
			hasIP = true
		}
	}
	var sourceIP netip.Addr
	var hasSourceIP bool
	if srcStr := strings.TrimSpace(in.SourceIP); srcStr != "" {
		if addr, err := netip.ParseAddr(srcStr); err == nil {
			sourceIP = addr
			hasSourceIP = true
		}
	}

	if profile.Mode != "direct" && isWebRTCTraffic(domain, in) {
		switch profile.WebRTCMode {
		case "block":
			return SimulationResult{Outbound: "block", MatchedRule: "webrtc:block", Action: "reject"}
		case "proxy":
			return SimulationResult{Outbound: "proxy", MatchedRule: "webrtc:proxy", Action: "route"}
		}
	}

	if hasIP && profile.BypassLAN && !isFakeIPAddr(profile, parsedIP) && (parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()) {
		return SimulationResult{Outbound: "direct", MatchedRule: "builtin:ip_is_private", Action: "route"}
	}

	switch profile.Mode {
	case "direct":
		return SimulationResult{Outbound: "direct", MatchedRule: "mode:direct", Action: "route"}
	case "global":
		return SimulationResult{Outbound: "proxy", MatchedRule: "mode:global", Action: "route"}
	}

	if profile.BlockAds && isKnownAdDomain(domain) {
		return SimulationResult{Outbound: "block", MatchedRule: "builtin:geosite-category-ads-all", Action: "reject"}
	}

	for i, rule := range profile.CustomRules {
		if !rule.Enabled {
			continue
		}
		if matchesRule(rule, domain, parsedIP, hasIP, sourceIP, hasSourceIP, in) {
			name := rule.Name
			if name == "" {
				name = fmt.Sprintf("custom_rule_%d", i+1)
			}
			action := "route"
			out := rule.Outbound
			if out == "" {
				out = "proxy"
			}
			if out == "block" || out == "reject" {
				out = "block"
				action = "reject"
			}
			return SimulationResult{Outbound: out, MatchedRule: name, Action: action}
		}
	}

	if profile.BypassCN {
		if domain != "" && (strings.HasSuffix(domain, ".cn") || domain == "baidu.com" || strings.HasSuffix(domain, ".baidu.com") || strings.HasSuffix(domain, ".qq.com") || strings.HasSuffix(domain, ".taobao.com") || strings.HasSuffix(domain, ".jd.com") || strings.HasSuffix(domain, ".bilibili.com")) {
			return SimulationResult{Outbound: "direct", MatchedRule: "builtin:geosite-cn", Action: "route"}
		}
		if hasIP && isCNProbeHintIP(parsedIP) {
			return SimulationResult{Outbound: "direct", MatchedRule: "builtin:geoip-cn", Action: "route"}
		}
	}

	return SimulationResult{Outbound: "proxy", MatchedRule: "route.final", Action: "route"}
}

func matchesRule(rule RoutingRule, domain string, ip netip.Addr, hasIP bool, sourceIP netip.Addr, hasSourceIP bool, in SimulationInput) bool {
	matched, hasCondition := evalRuleConditions(rule, domain, ip, hasIP, sourceIP, hasSourceIP, in)
	if !hasCondition {
		return false
	}
	if rule.Invert {
		return !matched
	}
	return matched
}

func evalRuleConditions(rule RoutingRule, domain string, ip netip.Addr, hasIP bool, sourceIP netip.Addr, hasSourceIP bool, in SimulationInput) (bool, bool) {
	hasCondition := false
	if len(rule.Domains) > 0 {
		hasCondition = true
		matched := false
		for _, d := range rule.Domains {
			if strings.EqualFold(strings.TrimSpace(d), domain) && domain != "" {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.DomainSuffix) > 0 {
		hasCondition = true
		matched := false
		for _, s := range rule.DomainSuffix {
			s = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "."))
			if domain != "" && (domain == s || strings.HasSuffix(domain, "."+s)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.DomainKeyword) > 0 {
		hasCondition = true
		matched := false
		for _, kw := range rule.DomainKeyword {
			if domain != "" && strings.Contains(domain, strings.ToLower(strings.TrimSpace(kw))) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.DomainRegex) > 0 {
		hasCondition = true
		matched := false
		for _, pat := range rule.DomainRegex {
			if re, err := regexp.Compile(strings.TrimSpace(pat)); err == nil && domain != "" && re.MatchString(domain) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.IPCIDR) > 0 {
		hasCondition = true
		matched := false
		if hasIP {
			for _, raw := range rule.IPCIDR {
				if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil && p.Contains(ip) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.SourceIPCIDR) > 0 {
		hasCondition = true
		matched := false
		if hasSourceIP {
			for _, raw := range rule.SourceIPCIDR {
				if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil && p.Contains(sourceIP) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if rule.IPIsPrivate {
		hasCondition = true
		if !hasIP || !(ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
			return false, hasCondition
		}
	}
	if len(rule.Network) > 0 {
		hasCondition = true
		matched := false
		for _, netName := range rule.Network {
			if in.Network != "" && strings.EqualFold(strings.TrimSpace(netName), strings.TrimSpace(in.Network)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.ProcessName) > 0 {
		hasCondition = true
		matched := false
		for _, p := range rule.ProcessName {
			if in.ProcessName != "" && strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(in.ProcessName)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.ProcessPath) > 0 {
		hasCondition = true
		matched := false
		for _, p := range rule.ProcessPath {
			if in.ProcessPath != "" && strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(in.ProcessPath)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.PackageName) > 0 {
		hasCondition = true
		matched := false
		for _, p := range rule.PackageName {
			if in.PackageName != "" && strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(in.PackageName)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.Port) > 0 {
		hasCondition = true
		matched := false
		for _, port := range rule.Port {
			if in.Port != 0 && port == in.Port {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.PortRange) > 0 {
		hasCondition = true
		matched := false
		if in.Port > 0 {
			for _, pr := range rule.PortRange {
				loStr, hiStr, ok := strings.Cut(strings.ReplaceAll(strings.TrimSpace(pr), "-", ":"), ":")
				if !ok {
					continue
				}
				lo, err1 := strconv.Atoi(strings.TrimSpace(loStr))
				hi, err2 := strconv.Atoi(strings.TrimSpace(hiStr))
				if err1 == nil && err2 == nil && in.Port >= lo && in.Port <= hi {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.Protocol) > 0 {
		hasCondition = true
		matched := false
		for _, proto := range rule.Protocol {
			if in.Protocol != "" && strings.EqualFold(strings.TrimSpace(proto), strings.TrimSpace(in.Protocol)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	if len(rule.Inbound) > 0 {
		hasCondition = true
		matched := false
		for _, ib := range rule.Inbound {
			if in.Inbound != "" && strings.EqualFold(strings.TrimSpace(ib), strings.TrimSpace(in.Inbound)) {
				matched = true
				break
			}
		}
		if !matched {
			return false, hasCondition
		}
	}
	return hasCondition, hasCondition
}

func isKnownAdDomain(domain string) bool {
	if domain == "" {
		return false
	}
	for _, suffix := range []string{"doubleclick.net", "googlesyndication.com", "googleadservices.com", "adservice.google.com", "pangolin-sdk-toutiao.com", "ads.youtube.com"} {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func isCNProbeHintIP(ip netip.Addr) bool {
	for _, cidr := range []string{"223.5.5.0/24", "114.114.114.0/24", "119.29.29.0/24"} {
		if p, err := netip.ParsePrefix(cidr); err == nil && p.Contains(ip) {
			return true
		}
	}
	return false
}
