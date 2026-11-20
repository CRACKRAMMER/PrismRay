// SPDX-License-Identifier: MPL-2.0

package androiddns

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var defaultFallbackServers = []string{
	"223.5.5.5:53",
	"119.29.29.29:53",
	"8.8.8.8:53",
	"1.1.1.1:53",
}

var (
	mu            sync.RWMutex
	systemServers []string
	installed     bool
)

// ParseServerList normalizes comma/whitespace separated IP or host:port DNS addresses.
func ParseServerList(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	return NormalizeServers(fields)
}

// NormalizeServers deduplicates and formats DNS addresses as host:port (skipping loopback).
func NormalizeServers(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		host, port, err := net.SplitHostPort(s)
		if err != nil {
			host = strings.Trim(s, "[]")
			port = "53"
		}
		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		addr := net.JoinHostPort(ip.String(), port)
		if seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out, addr)
	}
	return out
}

// SetSystemServers updates the live Android network DNS servers reported by ConnectivityManager.
func SetSystemServers(servers []string) []string {
	clean := NormalizeServers(servers)
	mu.Lock()
	systemServers = clean
	mu.Unlock()
	return clean
}

// ActiveServers returns the ordered DNS upstream list (live Android DNS first, then public fallbacks).
func ActiveServers() []string {
	mu.RLock()
	sys := append([]string(nil), systemServers...)
	mu.RUnlock()

	combined := make([]string, 0, len(sys)+len(defaultFallbackServers))
	seen := make(map[string]bool, len(sys)+len(defaultFallbackServers))
	for _, s := range sys {
		if !seen[s] {
			seen[s] = true
			combined = append(combined, s)
		}
	}
	for _, s := range defaultFallbackServers {
		if !seen[s] {
			seen[s] = true
			combined = append(combined, s)
		}
	}
	return combined
}

// NewResolver creates a pure-Go DNS resolver that avoids /etc/resolv.conf (absent on Android).
func NewResolver(serversFn func() []string) *net.Resolver {
	if serversFn == nil {
		serversFn = ActiveServers
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			servers := serversFn()
			if len(servers) == 0 {
				servers = defaultFallbackServers
			}
			var lastErr error
			for _, addr := range servers {
				dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				d := &net.Dialer{Timeout: 2 * time.Second}
				conn, err := d.DialContext(dialCtx, network, addr)
				cancel()
				if err == nil {
					return conn, nil
				}
				lastErr = err
				if ctx.Err() != nil {
					break
				}
			}
			if lastErr == nil {
				lastErr = context.DeadlineExceeded
			}
			return nil, lastErr
		},
	}
}

// InstallDefaultResolver replaces net.DefaultResolver for Android pure-Go builds where /etc/resolv.conf does not exist.
func InstallDefaultResolver() []string {
	if envDNS := strings.TrimSpace(os.Getenv("PRISMRAY_ANDROID_DNS")); envDNS != "" {
		SetSystemServers(ParseServerList(envDNS))
	}
	mu.Lock()
	defer mu.Unlock()
	if !installed {
		net.DefaultResolver = NewResolver(ActiveServers)
		installed = true
	}
	return append([]string(nil), systemServers...)
}
