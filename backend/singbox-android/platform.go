// SPDX-License-Identifier: MPL-2.0
//go:build unix

package main

import (
	"context"
	stdjson "encoding/json"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

// androidNetIfRecord matches the JSON exported by Kotlin RuntimeIpc via Android ConnectivityManager.
type androidNetIfRecord struct {
	Name        string   `json:"name"`
	Index       int      `json:"index"`
	MTU         int      `json:"mtu"`
	Type        string   `json:"type"` // wifi | cellular | ethernet | other
	Addresses   []string `json:"addresses"`
	Gateways    []string `json:"gateways"`
	DNSServers  []string `json:"dns_servers"`
	IsDefault   bool     `json:"is_default"`
	Expensive   bool     `json:"expensive"`
	Constrained bool     `json:"constrained"`
}

type androidNetIfSnapshot struct {
	Interfaces []androidNetIfRecord `json:"interfaces"`
}

var _ adapter.PlatformInterface = (*androidPlatform)(nil)

type androidPlatform struct {
	protectPath    string
	netIfPath      string
	networkManager adapter.NetworkManager

	mu               sync.Mutex
	defaultInterface *control.Interface
	myInterfaces     []string
}

func newAndroidPlatform(protectPath, netIfPath string) *androidPlatform {
	return &androidPlatform{
		protectPath: strings.TrimSpace(protectPath),
		netIfPath:   strings.TrimSpace(netIfPath),
	}
}

func (p *androidPlatform) Initialize(networkManager adapter.NetworkManager) error {
	p.networkManager = networkManager
	return nil
}

func (p *androidPlatform) UsePlatformAutoDetectInterfaceControl() bool {
	return p.protectPath != ""
}

func (p *androidPlatform) AutoDetectInterfaceControl(fd int) error {
	if p.protectPath == "" {
		return nil
	}
	return protectFD(p.protectPath, fd)
}

func (p *androidPlatform) UsePlatformInterface() bool {
	return false
}

func (p *androidPlatform) OpenInterface(_ *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	return nil, os.ErrInvalid
}

func (p *androidPlatform) ProcessPlatformOptions(_ option.TunPlatformOptions) error {
	return nil
}

func (p *androidPlatform) UsePlatformDefaultInterfaceMonitor() bool {
	return true
}

func (p *androidPlatform) CreateDefaultInterfaceMonitor(log logger.Logger) tun.DefaultInterfaceMonitor {
	return &androidInterfaceMonitor{
		platform: p,
		logger:   log,
	}
}

func (p *androidPlatform) UsePlatformNetworkInterfaces() bool {
	return true
}

func (p *androidPlatform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	ifaces, defIface := p.loadInterfacesFromSnapshot()
	if len(ifaces) == 0 {
		ifaces, defIface = synthesizeFallbackInterfaces()
	}
	p.mu.Lock()
	if defIface != nil {
		cp := *defIface
		p.defaultInterface = &cp
	} else if len(ifaces) > 0 {
		for i := range ifaces {
			if ifaces[i].Flags&net.FlagLoopback == 0 {
				cp := ifaces[i].Interface
				p.defaultInterface = &cp
				break
			}
		}
	}
	p.mu.Unlock()
	return ifaces, nil
}

func parseInterfaceType(raw string) C.InterfaceType {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "wifi":
		return C.InterfaceTypeWIFI
	case "cellular":
		return C.InterfaceTypeCellular
	case "ethernet":
		return C.InterfaceTypeEthernet
	default:
		return C.InterfaceTypeOther
	}
}

func (p *androidPlatform) loadInterfacesFromSnapshot() ([]adapter.NetworkInterface, *control.Interface) {
	if p.netIfPath == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(p.netIfPath)
	if err != nil || len(raw) == 0 {
		return nil, nil
	}
	var snap androidNetIfSnapshot
	if err := stdjson.Unmarshal(raw, &snap); err != nil || len(snap.Interfaces) == 0 {
		return nil, nil
	}

	var out []adapter.NetworkInterface
	var defIface *control.Interface
	nextIdx := 2
	hasLoopback := false

	for _, rec := range snap.Interfaces {
		name := strings.TrimSpace(rec.Name)
		if name == "" || strings.HasPrefix(name, "tun") {
			continue
		}
		var prefixes []netip.Prefix
		for _, rawAddr := range rec.Addresses {
			rawAddr = strings.TrimSpace(rawAddr)
			if rawAddr == "" {
				continue
			}
			if pref, err := netip.ParsePrefix(rawAddr); err == nil {
				prefixes = append(prefixes, pref)
			} else if addr, aErr := netip.ParseAddr(rawAddr); aErr == nil {
				prefixes = append(prefixes, netip.PrefixFrom(addr.Unmap(), addr.Unmap().BitLen()))
			}
		}
		if len(prefixes) == 0 {
			continue
		}
		var gateways []netip.Addr
		for _, rawGW := range rec.Gateways {
			if gw, err := netip.ParseAddr(strings.TrimSpace(rawGW)); err == nil {
				gateways = append(gateways, gw.Unmap())
			}
		}
		idx := rec.Index
		if idx <= 0 {
			idx = nextIdx
			nextIdx++
		}
		mtu := rec.MTU
		if mtu <= 0 {
			mtu = 1500
		}
		flags := net.FlagUp | net.FlagRunning | net.FlagBroadcast | net.FlagMulticast
		if name == "lo" {
			hasLoopback = true
			flags = net.FlagUp | net.FlagRunning | net.FlagLoopback
		}
		ctrl := control.Interface{
			Index:     idx,
			MTU:       mtu,
			Name:      name,
			Addresses: prefixes,
			Flags:     flags,
		}
		ni := adapter.NetworkInterface{
			Interface:   ctrl,
			Type:        parseInterfaceType(rec.Type),
			DNSServers:  rec.DNSServers,
			Gateways:    gateways,
			Expensive:   rec.Expensive,
			Constrained: rec.Constrained,
		}
		out = append(out, ni)
		if rec.IsDefault && defIface == nil && name != "lo" {
			cp := ctrl
			defIface = &cp
		}
	}

	if len(out) > 0 && !hasLoopback {
		out = append(out, loopbackNetworkInterface())
	}
	return out, defIface
}

func loopbackNetworkInterface() adapter.NetworkInterface {
	return adapter.NetworkInterface{
		Interface: control.Interface{
			Index: 1,
			MTU:   65536,
			Name:  "lo",
			Addresses: []netip.Prefix{
				netip.MustParsePrefix("127.0.0.1/8"),
				netip.MustParsePrefix("::1/128"),
			},
			Flags: net.FlagUp | net.FlagRunning | net.FlagLoopback,
		},
		Type: C.InterfaceTypeOther,
	}
}

// synthesizeFallbackInterfaces discovers the active outbound local IP via unconnected UDP dial
// without touching netlink sockets (which Android 11+ SELinux blocks with EACCES).
func synthesizeFallbackInterfaces() ([]adapter.NetworkInterface, *control.Interface) {
	var prefixes []netip.Prefix
	if addr, ok := probeUDPOutboundLocalIP("udp4", "1.1.1.1:53"); ok {
		prefixes = append(prefixes, netip.PrefixFrom(addr, 24))
	}
	if addr, ok := probeUDPOutboundLocalIP("udp6", "[2606:4700:4700::1111]:53"); ok {
		prefixes = append(prefixes, netip.PrefixFrom(addr, 64))
	}
	if len(prefixes) == 0 {
		// Provide a minimal synthetic interface so netmon/tsnet still boots cleanly when offline.
		prefixes = []netip.Prefix{netip.MustParsePrefix("192.0.2.2/24")}
	}
	primary := control.Interface{
		Index:     2,
		MTU:       1500,
		Name:      "wlan0",
		Addresses: prefixes,
		Flags:     net.FlagUp | net.FlagRunning | net.FlagBroadcast | net.FlagMulticast,
	}
	ifaces := []adapter.NetworkInterface{
		{
			Interface: primary,
			Type:      C.InterfaceTypeWIFI,
		},
		loopbackNetworkInterface(),
	}
	cp := primary
	return ifaces, &cp
}

func probeUDPOutboundLocalIP(network, target string) (netip.Addr, bool) {
	d := net.Dialer{Timeout: 500 * time.Millisecond}
	conn, err := d.Dial(network, target)
	if err != nil {
		return netip.Addr{}, false
	}
	defer conn.Close()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return netip.Addr{}, false
	}
	addr, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsUnspecified() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	return addr, true
}

func (p *androidPlatform) UnderNetworkExtension() bool              { return false }
func (p *androidPlatform) NetworkExtensionIncludeAllNetworks() bool { return false }
func (p *androidPlatform) ClearDNSCache()                           {}
func (p *androidPlatform) RequestPermissionForWIFIState() error     { return nil }
func (p *androidPlatform) ReadWIFIState(_ context.Context) adapter.WIFIState {
	return adapter.WIFIState{}
}
func (p *androidPlatform) UsePlatformConnectionOwnerFinder() bool { return false }
func (p *androidPlatform) FindConnectionOwner(_ *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, os.ErrInvalid
}
func (p *androidPlatform) UsePlatformWIFIMonitor() bool  { return false }
func (p *androidPlatform) UsePlatformNotification() bool { return false }
func (p *androidPlatform) SendNotification(_ *adapter.Notification) error {
	return os.ErrInvalid
}
func (p *androidPlatform) CancelNotification(_ string, _ int32) error { return nil }
func (p *androidPlatform) MyInterfaceAddress() []netip.Addr           { return nil }
func (p *androidPlatform) UsePlatformNeighborResolver() bool          { return false }
func (p *androidPlatform) StartNeighborMonitor(_ adapter.NeighborUpdateListener) error {
	return os.ErrInvalid
}
func (p *androidPlatform) CloseNeighborMonitor(_ adapter.NeighborUpdateListener) error {
	return nil
}
func (p *androidPlatform) UsePlatformShell() bool    { return false }
func (p *androidPlatform) CheckPlatformShell() error { return os.ErrInvalid }
func (p *androidPlatform) OpenShellSession(_ *adapter.PlatformUser, _ string, _ []string, _ string, _ int32, _ int32) (adapter.ShellSession, error) {
	return nil, os.ErrInvalid
}
func (p *androidPlatform) LookupUser(_ string) (*adapter.PlatformUser, error) {
	return nil, os.ErrInvalid
}
func (p *androidPlatform) LookupSFTPServer() (string, error)     { return "", os.ErrInvalid }
func (p *androidPlatform) ReadSystemSSHHostKey() ([]byte, error) { return nil, os.ErrInvalid }
func (p *androidPlatform) TailscaleHostname() string             { return "" }
func (p *androidPlatform) UsePlatformBridge() bool               { return false }
func (p *androidPlatform) CreateBridge(_ adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, E.New("platform bridge unsupported")
}

var _ tun.DefaultInterfaceMonitor = (*androidInterfaceMonitor)(nil)

type androidInterfaceMonitor struct {
	platform  *androidPlatform
	logger    logger.Logger
	mu        sync.Mutex
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
	stopCh    chan struct{}
	closed    bool
}

func (m *androidInterfaceMonitor) Start() error {
	m.mu.Lock()
	m.stopCh = make(chan struct{})
	stopCh := m.stopCh
	m.mu.Unlock()

	if m.platform.networkManager != nil {
		if err := m.platform.networkManager.UpdateInterfaces(); err != nil && m.logger != nil {
			m.logger.Warn("initial android interface sync failed: ", err)
		}
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGUSR1)
	go func() {
		defer signal.Stop(sigCh)
		for {
			select {
			case <-stopCh:
				return
			case <-sigCh:
				m.refreshAndNotify()
			}
		}
	}()
	return nil
}

func (m *androidInterfaceMonitor) refreshAndNotify() {
	if m.platform.networkManager != nil {
		if err := m.platform.networkManager.UpdateInterfaces(); err != nil && m.logger != nil {
			m.logger.Warn("android interface refresh failed: ", err)
		}
	}
	def := m.DefaultInterface()
	m.mu.Lock()
	cbs := m.callbacks.Array()
	m.mu.Unlock()
	for _, cb := range cbs {
		cb(def, tun.FlagAndroidVPNUpdate)
	}
}

func (m *androidInterfaceMonitor) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		if m.stopCh != nil {
			close(m.stopCh)
		}
	}
	return nil
}

func (m *androidInterfaceMonitor) DefaultInterface() *control.Interface {
	m.platform.mu.Lock()
	defer m.platform.mu.Unlock()
	return m.platform.defaultInterface
}

func (m *androidInterfaceMonitor) OverrideAndroidVPN() bool { return false }
func (m *androidInterfaceMonitor) AndroidVPNEnabled() bool  { return false }

func (m *androidInterfaceMonitor) RegisterCallback(callback tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(callback)
}

func (m *androidInterfaceMonitor) UnregisterCallback(element *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(element)
}

func (m *androidInterfaceMonitor) RegisterMyInterface(interfaceName string) {
	m.platform.mu.Lock()
	defer m.platform.mu.Unlock()
	m.platform.myInterfaces = append(m.platform.myInterfaces, interfaceName)
}

func (m *androidInterfaceMonitor) MyInterfaces() []string {
	m.platform.mu.Lock()
	defer m.platform.mu.Unlock()
	return append([]string(nil), m.platform.myInterfaces...)
}
