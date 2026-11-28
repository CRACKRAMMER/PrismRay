// SPDX-License-Identifier: MPL-2.0

package config

import (
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
)

var (
	tailscaleCGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")
	tailscaleULAPrefix   = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// SystemTailscaleInfo describes an active host-level (external) Tailscale daemon/interface.
type SystemTailscaleInfo struct {
	Detected       bool     `json:"detected"`
	Interface      string   `json:"interface,omitempty"`
	IPv4           string   `json:"ipv4,omitempty"`
	IPv6           string   `json:"ipv6,omitempty"`
	MagicDNSActive bool     `json:"magic_dns_active"`
	SearchDomains  []string `json:"search_domains,omitempty"`
}

// EffectiveSearchDomains returns deduplicated DNS suffixes (always including "ts.net") for system MagicDNS.
func (s SystemTailscaleInfo) EffectiveSearchDomains() []string {
	seen := map[string]bool{"ts.net": true}
	out := []string{"ts.net"}
	for _, raw := range s.SearchDomains {
		clean := strings.ToLower(strings.Trim(strings.TrimSpace(raw), "."))
		if clean == "" || seen[clean] {
			continue
		}
		seen[clean] = true
		out = append(out, clean)
	}
	sort.Strings(out)
	return out
}

// SystemTailscaleDetector allows tests to inject deterministic host interface detection.
var SystemTailscaleDetector = detectSystemTailscaleHost

// DetectSystemTailscale inspects the local host for an active system Tailscale interface and MagicDNS resolver.
func DetectSystemTailscale() SystemTailscaleInfo {
	if SystemTailscaleDetector != nil {
		return SystemTailscaleDetector()
	}
	return SystemTailscaleInfo{}
}

type ifaceProbe struct {
	Name  string
	Up    bool
	Addrs []netip.Addr
}

func detectSystemTailscaleHost() SystemTailscaleInfo {
	if runtime.GOOS == "android" {
		return SystemTailscaleInfo{}
	}
	netIfs, err := net.Interfaces()
	if err != nil {
		return SystemTailscaleInfo{}
	}
	probes := make([]ifaceProbe, 0, len(netIfs))
	for _, iface := range netIfs {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, aErr := iface.Addrs()
		if aErr != nil {
			continue
		}
		parsed := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if addr, ok := netip.AddrFromSlice(ip); ok {
				parsed = append(parsed, addr.Unmap())
			}
		}
		probes = append(probes, ifaceProbe{
			Name:  iface.Name,
			Up:    iface.Flags&net.FlagUp != 0,
			Addrs: parsed,
		})
	}
	var resolvRaw string
	if runtime.GOOS != "windows" {
		if data, rErr := os.ReadFile("/etc/resolv.conf"); rErr == nil {
			resolvRaw = string(data)
		}
	}
	return analyzeSystemTailscale(probes, resolvRaw, runtime.GOOS)
}

func isLikelySystemTailscaleIface(name string, goos string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	if low == "" || strings.HasPrefix(low, "prismray") {
		return false
	}
	if strings.Contains(low, "tailscale") {
		return true
	}
	// macOS Tailscale runs on a utunX interface; require a Tailscale ULA or CGNAT match on Addrs.
	if goos == "darwin" && strings.HasPrefix(low, "utun") {
		return true
	}
	return false
}

func analyzeSystemTailscale(ifaces []ifaceProbe, resolvConf string, goos string) SystemTailscaleInfo {
	var info SystemTailscaleInfo
	for _, iface := range ifaces {
		if !iface.Up || !isLikelySystemTailscaleIface(iface.Name, goos) {
			continue
		}
		var v4, v6 string
		for _, addr := range iface.Addrs {
			if addr.Is4() && tailscaleCGNATPrefix.Contains(addr) && v4 == "" {
				v4 = addr.String()
			} else if addr.Is6() && tailscaleULAPrefix.Contains(addr) && v6 == "" {
				v6 = addr.String()
			}
		}
		if v4 != "" || v6 != "" {
			info.Detected = true
			info.Interface = iface.Name
			info.IPv4 = v4
			info.IPv6 = v6
			break
		}
	}

	if !info.Detected {
		return info
	}

	seenDomains := map[string]bool{}
	for _, line := range strings.Split(resolvConf, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			if strings.TrimSpace(fields[1]) == "100.100.100.100" {
				info.MagicDNSActive = true
			}
		case "search", "domain":
			for _, dom := range fields[1:] {
				clean := strings.ToLower(strings.Trim(strings.TrimSpace(dom), "."))
				if clean == "" {
					continue
				}
				if clean == "ts.net" || strings.HasSuffix(clean, ".ts.net") {
					info.MagicDNSActive = true
					if !seenDomains[clean] {
						seenDomains[clean] = true
						info.SearchDomains = append(info.SearchDomains, clean)
					}
				}
			}
		}
	}
	// On macOS/Windows resolv.conf may not list 100.100.100.100 even when Tailscale MagicDNS is active.
	if goos == "darwin" || goos == "windows" {
		info.MagicDNSActive = true
	}
	sort.Strings(info.SearchDomains)
	return info
}
