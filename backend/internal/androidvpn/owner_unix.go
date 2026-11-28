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
	"sync/atomic"
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
	txBytes        atomic.Int64
	rxBytes        atomic.Int64
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

var (
	ownerSockMu   sync.Mutex
	ownerSockPath string
	ownerSockConn net.Conn
	ownerSockRdr  *bufio.Reader
)

func closeOwnerConnLocked() {
	if ownerSockConn != nil {
		_ = ownerSockConn.Close()
		ownerSockConn = nil
		ownerSockRdr = nil
		ownerSockPath = ""
	}
}

// QueryConnectionOwner asks Kotlin ProxyVpnService's owner.sock for the Android package owning a flow,
// reusing a persistent multiplexed Unix domain socket connection across queries.
func QueryConnectionOwner(sockPath string, proto int, srcIP netip.Addr, srcPort uint16, dstIP netip.Addr, dstPort uint16) string {
	sockPath = strings.TrimSpace(sockPath)
	if sockPath == "" {
		return ""
	}
	line := fmt.Sprintf("%d,%s,%d,%s,%d\n", proto, srcIP.String(), srcPort, dstIP.String(), dstPort)

	ownerSockMu.Lock()
	defer ownerSockMu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		if ownerSockConn == nil || ownerSockPath != sockPath {
			closeOwnerConnLocked()
			conn, err := net.DialTimeout("unix", sockPath, 120*time.Millisecond)
			if err != nil {
				return ""
			}
			ownerSockConn = conn
			ownerSockRdr = bufio.NewReader(conn)
			ownerSockPath = sockPath
		}
		_ = ownerSockConn.SetDeadline(time.Now().Add(150 * time.Millisecond))
		if _, err := ownerSockConn.Write([]byte(line)); err != nil {
			closeOwnerConnLocked()
			continue
		}
		resp, err := ownerSockRdr.ReadString('\n')
		if err != nil {
			closeOwnerConnLocked()
			if len(resp) == 0 {
				continue
			}
		}
		return strings.TrimSpace(resp)
	}
	return ""
}

// TrafficTotals returns cumulative uploaded (tx) and downloaded (rx) byte counters
// observed across active tun2socks TCP and UDP flows.
func (p *AppRoutingProxy) TrafficTotals() (tx int64, rx int64) {
	return p.txBytes.Load(), p.rxBytes.Load()
}

// ResetTrafficTotals zeroes the cumulative byte counters for a fresh VPN session.
func (p *AppRoutingProxy) ResetTrafficTotals() {
	p.txBytes.Store(0)
	p.rxBytes.Store(0)
}

type countingConn struct {
	net.Conn
	tx *atomic.Int64
	rx *atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.rx.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.tx.Add(int64(n))
	}
	return n, err
}

func (c *countingConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (c *countingConn) CloseRead() error {
	if cr, ok := c.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

type countingPacketConn struct {
	net.PacketConn
	tx *atomic.Int64
	rx *atomic.Int64
}

func (c *countingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := c.PacketConn.ReadFrom(p)
	if n > 0 {
		c.rx.Add(int64(n))
	}
	return n, addr, err
}

func (c *countingPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	n, err := c.PacketConn.WriteTo(p, addr)
	if n > 0 {
		c.tx.Add(int64(n))
	}
	return n, err
}

// DialContext implements tun2socks proxy.Proxy for TCP flows.
func (p *AppRoutingProxy) DialContext(ctx context.Context, md *M.Metadata) (net.Conn, error) {
	client, err := p.selectClient(md, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	conn, err := client.DialContext(ctx, md)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, tx: &p.txBytes, rx: &p.rxBytes}, nil
}

// DialUDP implements tun2socks proxy.Proxy for UDP flows.
func (p *AppRoutingProxy) DialUDP(md *M.Metadata) (net.PacketConn, error) {
	client, err := p.selectClient(md, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, err
	}
	pc, err := client.DialUDP(md)
	if err != nil {
		return nil, err
	}
	return &countingPacketConn{PacketConn: pc, tx: &p.txBytes, rx: &p.rxBytes}, nil
}
