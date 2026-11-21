//go:build android || linux

// SPDX-License-Identifier: MPL-2.0

package androidvpn

import (
	"bufio"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	M "github.com/xjasonlyu/tun2socks/v2/metadata"
)

func TestQueryConnectionOwnerAndAppRoutingSelection(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "owner.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix failed: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				if strings.HasPrefix(strings.TrimSpace(line), "6,172.19.0.1,45000,1.1.1.1,443") {
					_, _ = c.Write([]byte("com.android.vending\n"))
				} else {
					_, _ = c.Write([]byte("\n"))
				}
			}(conn)
		}
	}()

	pkg := QueryConnectionOwner(
		sockPath,
		syscall.IPPROTO_TCP,
		netip.MustParseAddr("172.19.0.1"),
		45000,
		netip.MustParseAddr("1.1.1.1"),
		443,
	)
	if pkg != "com.android.vending" {
		t.Fatalf("expected com.android.vending, got %q", pkg)
	}

	p := NewAppRoutingProxy()
	p.Update(AppRoutingConfig{
		MixedPort:       10808,
		AppSocksPort:    10899,
		AppSocksSecret:  "secret123",
		OwnerSockPath:   sockPath,
		WatchedPackages: []string{"com.android.vending"},
	})

	metaMatched := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("172.19.0.1"),
		SrcPort: 45000,
		DstIP:   netip.MustParseAddr("1.1.1.1"),
		DstPort: 443,
	}
	cMatched, err := p.selectClient(metaMatched, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("selectClient matched failed: %v", err)
	}
	if cMatched == p.defaultClient {
		t.Fatalf("expected matched app to route to dedicated appSocksPort client, not defaultClient")
	}
	if p.appClients["com.android.vending"] != cMatched {
		t.Fatalf("expected appClients[\"com.android.vending\"] to cache matched client")
	}

	metaOther := &M.Metadata{
		Network: M.TCP,
		SrcIP:   netip.MustParseAddr("172.19.0.1"),
		SrcPort: 45001,
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		DstPort: 443,
	}
	cOther, err := p.selectClient(metaOther, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("selectClient unmatched failed: %v", err)
	}
	if cOther != p.defaultClient {
		t.Fatalf("expected unmatched app to fall back to defaultClient (mixedPort)")
	}

	metaDNS := &M.Metadata{
		Network: M.UDP,
		SrcIP:   netip.MustParseAddr("172.19.0.1"),
		SrcPort: 53000,
		DstIP:   netip.MustParseAddr("172.19.0.2"),
		DstPort: 53,
	}
	cDNS, err := p.selectClient(metaDNS, syscall.IPPROTO_UDP)
	if err != nil {
		t.Fatalf("selectClient DNS failed: %v", err)
	}
	if cDNS != p.defaultClient {
		t.Fatalf("expected DNS UDP:53 to bypass owner lookup and use defaultClient (mixedPort)")
	}
}
