//go:build android || linux

// SPDX-License-Identifier: MPL-2.0

package androidvpn

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
	"github.com/xjasonlyu/tun2socks/v2/proxy"
	"github.com/xjasonlyu/tun2socks/v2/proxy/socks5"
)

const androidOtherAppUser = "__other__"

type flowKey struct {
	proto   int
	srcIP   netip.Addr
	srcPort uint16
	dstIP   netip.Addr
	dstPort uint16
}

type flowCacheEntry struct {
	pkg     string
	expires time.Time
}

// AppRoutingProxy is a custom tun2socks proxy that transparently forwards to sing-box's
// mixed port by default, and switches to authenticated per-package SOCKS5 connections
// whenever Android custom routing rules reference package_name entries.
type AppRoutingProxy struct {
	mu             sync.RWMutex
	mixedPort      int
	appSocksPort   int
	appSocksSecret string
	ownerSockPath  string
	watched        map[string]bool
	defaultClient  *socks5.Socks5
	appClients     map[string]*socks5.Socks5
	cacheMu        sync.Mutex
	flowCache      map[flowKey]flowCacheEntry
}

// NewAppRoutingProxy initializes a dynamic Android app-aware proxy wrapper.
func NewAppRoutingProxy() *AppRoutingProxy {
	return &AppRoutingProxy{
		watched:    map[string]bool{},
		appClients: map[string]*socks5.Socks5{},
		flowCache:  map[flowKey]flowCacheEntry{},
	}
}

// DefaultAppRoutingProxy backs the registered "prismray://" tun2socks protocol.
var DefaultAppRoutingProxy = NewAppRoutingProxy()

func init() {
	proxy.RegisterProtocol("prismray", func(_ *url.URL) (proxy.Proxy, error) {
		return DefaultAppRoutingProxy, nil
	})
}

// SetMixedPort updates the fallback mixed port while preserving per-app routing settings.
func (p *AppRoutingProxy) SetMixedPort(port int) {
	if port <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mixedPort == port && p.defaultClient != nil {
		return
	}
	p.mixedPort = port
	if client, err := socks5.New(fmt.Sprintf("127.0.0.1:%d", port), "", ""); err == nil {
		p.defaultClient = client
	}
}

// Update replaces the live per-app routing settings without restarting tun2socks.
func (p *AppRoutingProxy) Update(cfg AppRoutingConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if cfg.MixedPort > 0 && (cfg.MixedPort != p.mixedPort || p.defaultClient == nil) {
		p.mixedPort = cfg.MixedPort
		if client, err := socks5.New(fmt.Sprintf("127.0.0.1:%d", cfg.MixedPort), "", ""); err == nil {
			p.defaultClient = client
		}
	}

	nextWatched := make(map[string]bool, len(cfg.WatchedPackages))
	for _, raw := range cfg.WatchedPackages {
		if pkg := strings.TrimSpace(raw); pkg != "" {
			nextWatched[pkg] = true
		}
	}
	if cfg.AppSocksPort != p.appSocksPort || cfg.AppSocksSecret != p.appSocksSecret {
		p.appClients = map[string]*socks5.Socks5{}
	}
	p.appSocksPort = cfg.AppSocksPort
	p.appSocksSecret = strings.TrimSpace(cfg.AppSocksSecret)
	if strings.TrimSpace(cfg.OwnerSockPath) != "" {
		p.ownerSockPath = strings.TrimSpace(cfg.OwnerSockPath)
	}
	p.watched = nextWatched

	p.cacheMu.Lock()
	p.flowCache = map[flowKey]flowCacheEntry{}
	p.cacheMu.Unlock()
}

func (p *AppRoutingProxy) selectClient(md *M.Metadata, proto int) (*socks5.Socks5, error) {
	p.mu.RLock()
	defaultClient := p.defaultClient
	appPort := p.appSocksPort
	secret := p.appSocksSecret
	ownerSock := p.ownerSockPath
	hasWatched := len(p.watched) > 0
	p.mu.RUnlock()

	if !hasWatched || appPort <= 0 || secret == "" || ownerSock == "" || md == nil {
		if defaultClient == nil {
			return nil, fmt.Errorf("android tun2socks default proxy not configured")
		}
		return defaultClient, nil
	}

	// Skip owner lookup for hijacked DNS queries (UDP port 53) to avoid adding latency to DNS.
	if proto == syscall.IPPROTO_UDP && md.DstPort == 53 {
		if defaultClient != nil {
			return defaultClient, nil
		}
	}

	user := ""
	if md.SrcIP.IsValid() && md.DstIP.IsValid() {
		pkg := p.lookupPackageCached(ownerSock, proto, md.SrcIP, md.SrcPort, md.DstIP, md.DstPort)
		if pkg != "" {
			p.mu.RLock()
			matched := p.watched[pkg]
			p.mu.RUnlock()
			if matched {
				user = pkg
			}
		}
	}
	// Unmatched apps go straight to default mixedPort with zero SOCKS5 auth overhead.
	if user == "" {
		if defaultClient != nil {
			return defaultClient, nil
		}
		user = androidOtherAppUser
	}

	p.mu.RLock()
	cached := p.appClients[user]
	p.mu.RUnlock()
	if cached != nil {
		return cached, nil
	}

	client, err := socks5.New(fmt.Sprintf("127.0.0.1:%d", appPort), user, secret)
	if err != nil {
		if defaultClient != nil {
			return defaultClient, nil
		}
		return nil, err
	}
	p.mu.Lock()
	if p.appSocksPort == appPort && p.appSocksSecret == secret {
		p.appClients[user] = client
	}
	p.mu.Unlock()
	return client, nil
}

func (p *AppRoutingProxy) lookupPackageCached(ownerSock string, proto int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) string {
	key := flowKey{
		proto:   proto,
		srcIP:   srcIP.Unmap(),
		srcPort: srcPort,
		dstIP:   dstIP.Unmap(),
		dstPort: dstPort,
	}
	now := time.Now()

	p.cacheMu.Lock()
	if entry, ok := p.flowCache[key]; ok && now.Before(entry.expires) {
		p.cacheMu.Unlock()
		return entry.pkg
	}
	p.cacheMu.Unlock()

	pkg := QueryConnectionOwner(ownerSock, proto, key.srcIP, srcPort, key.dstIP, dstPort)

	p.cacheMu.Lock()
	if len(p.flowCache) >= 1024 {
		for k, v := range p.flowCache {
			if now.After(v.expires) {
				delete(p.flowCache, k)
			}
		}
		if len(p.flowCache) >= 1024 {
			p.flowCache = map[flowKey]flowCacheEntry{}
		}
	}
	p.flowCache[key] = flowCacheEntry{pkg: pkg, expires: now.Add(3 * time.Second)}
	p.cacheMu.Unlock()
	return pkg
}

// QueryConnectionOwner asks Kotlin ProxyVpnService's owner.sock for the Android package owning a flow.
func QueryConnectionOwner(ownerSockPath string, proto int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) string {
	if strings.TrimSpace(ownerSockPath) == "" {
		return ""
	}
	conn, err := net.DialTimeout("unix", ownerSockPath, 120*time.Millisecond)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(150 * time.Millisecond))

	line := fmt.Sprintf("%d,%s,%d,%s,%d\n", proto, srcIP.String(), srcPort, dstIP.String(), dstPort)
	if _, err := conn.Write([]byte(line)); err != nil {
		return ""
	}
	resp, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && len(resp) == 0 {
		return ""
	}
	return strings.TrimSpace(resp)
}

// DialContext implements tun2socks proxy.Proxy for TCP flows.
func (p *AppRoutingProxy) DialContext(ctx context.Context, md *M.Metadata) (net.Conn, error) {
	client, err := p.selectClient(md, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	return client.DialContext(ctx, md)
}

// DialUDP implements tun2socks proxy.Proxy for UDP flows.
func (p *AppRoutingProxy) DialUDP(md *M.Metadata) (net.PacketConn, error) {
	client, err := p.selectClient(md, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	return client.DialUDP(md)
}
