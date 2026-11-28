// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func TestLogRingBufferAndSecretRedaction(t *testing.T) {
	orch := New(Options{WorkDir: t.TempDir(), LogCapacity: 4})
	orch.registerSecrets(ApplyInput{
		ClashAPISecret: "clash-secret-token-xyz",
		Nodes: []*config.Node{
			{
				ID:       "n1",
				UUID:     "12345678-1234-1234-1234-1234567890ab",
				Password: "super-secret-pass!",
			},
		},
	})

	ch, unsub := orch.SubscribeLogs()
	defer unsub()

	for i := 0; i < 6; i++ {
		orch.AppendLog("sing-box", "", fmt.Sprintf("msg-%d uuid=12345678-1234-1234-1234-1234567890ab password=super-secret-pass! clash-secret-token-xyz", i))
	}

	hist := orch.LogHistory(10)
	if len(hist) != 4 {
		t.Fatalf("LogHistory len = %d, want 4", len(hist))
	}
	if !strings.Contains(hist[0].Message, "msg-2") || !strings.Contains(hist[3].Message, "msg-5") {
		t.Fatalf("unexpected ring buffer entries: %+v", hist)
	}
	for _, e := range hist {
		if strings.Contains(e.Message, "12345678-1234-1234-1234-1234567890ab") ||
			strings.Contains(e.Message, "super-secret-pass!") ||
			strings.Contains(e.Message, "clash-secret-token-xyz") {
			t.Fatalf("secret leaked in log message: %q", e.Message)
		}
		if !strings.Contains(e.Message, "[REDACTED]") {
			t.Fatalf("expected [REDACTED] placeholder in %q", e.Message)
		}
	}

	select {
	case got := <-ch:
		if strings.Contains(got.Message, "super-secret-pass!") {
			t.Fatalf("subscriber received unredacted secret: %q", got.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for log subscriber message")
	}
}

func startLocalSOCKS5Server(t *testing.T, hits *atomic.Int64) (string, int, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// SOCKS5 method negotiation
				hdr := make([]byte, 2)
				if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0x05 {
					return
				}
				methods := make([]byte, hdr[1])
				if _, err := io.ReadFull(c, methods); err != nil {
					return
				}
				_, _ = c.Write([]byte{0x05, 0x00}) // no auth

				// Request: VER CMD RSV ATYP ...
				req := make([]byte, 4)
				if _, err := io.ReadFull(c, req); err != nil || req[1] != 0x01 {
					return
				}
				var host string
				switch req[3] {
				case 0x01:
					ip := make([]byte, 4)
					if _, err := io.ReadFull(c, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				case 0x03:
					l := make([]byte, 1)
					if _, err := io.ReadFull(c, l); err != nil {
						return
					}
					d := make([]byte, l[0])
					if _, err := io.ReadFull(c, d); err != nil {
						return
					}
					host = string(d)
				case 0x04:
					ip := make([]byte, 16)
					if _, err := io.ReadFull(c, ip); err != nil {
						return
					}
					host = net.IP(ip).String()
				default:
					return
				}
				portBuf := make([]byte, 2)
				if _, err := io.ReadFull(c, portBuf); err != nil {
					return
				}
				port := int(binary.BigEndian.Uint16(portBuf))

				target, err := net.DialTimeout("tcp", net.JoinHostPort(host, strconv.Itoa(port)), 3*time.Second)
				if err != nil {
					_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
					return
				}
				defer target.Close()
				hits.Add(1)
				_, _ = c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

				errCh := make(chan error, 2)
				go func() {
					_, err := io.Copy(target, c)
					errCh <- err
				}()
				go func() {
					_, err := io.Copy(c, target)
					errCh <- err
				}()
				<-errCh
			}(conn)
		}
	}()

	addr := ln.Addr().(*net.TCPAddr)
	return addr.IP.String(), addr.Port, func() {
		cancel()
		_ = ln.Close()
	}
}

func TestOrchestratorDualCoreApplyHotSwitchAndProbe(t *testing.T) {
	sbBin := strings.TrimSpace(os.Getenv("SINGBOX_TEST_BINARY"))
	xrayBin := strings.TrimSpace(os.Getenv("XRAY_TEST_BINARY"))
	if sbBin == "" || xrayBin == "" {
		t.Skip("SINGBOX_TEST_BINARY and XRAY_TEST_BINARY not set")
	}

	http204Srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer http204Srv.Close()

	caPath := filepath.Join(t.TempDir(), "test-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: http204Srv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA pem: %v", err)
	}
	t.Setenv("SSL_CERT_FILE", caPath)

	rootPool := x509.NewCertPool()
	rootPool.AddCert(http204Srv.Certificate())

	var socksHits atomic.Int64
	socksHost, socksPort, stopSocks := startLocalSOCKS5Server(t, &socksHits)
	defer stopSocks()

	mixedPort, err := freePort()
	if err != nil {
		t.Fatalf("freePort mixed: %v", err)
	}
	clashPort, err := freePort()
	if err != nil {
		t.Fatalf("freePort clash: %v", err)
	}

	nNative := &config.Node{
		ID:         "socks-native",
		Name:       "SOCKS Native",
		Protocol:   config.ProtocolSocks,
		Address:    socksHost,
		Port:       socksPort,
		EnginePref: "sing-box",
	}
	nXray := &config.Node{
		ID:         "socks-xray",
		Name:       "SOCKS via Xray",
		Protocol:   config.ProtocolSocks,
		Address:    socksHost,
		Port:       socksPort,
		EnginePref: "xray",
	}
	nUnloaded := &config.Node{
		ID:         "socks-unloaded",
		Name:       "SOCKS Unloaded",
		Protocol:   config.ProtocolSocks,
		Address:    socksHost,
		Port:       socksPort,
		EnginePref: "sing-box",
	}

	orch := New(Options{
		WorkDir:       t.TempDir(),
		SingBoxBinary: sbBin,
		XrayBinary:    xrayBin,
	})
	defer orch.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	in := ApplyInput{
		Nodes: []*config.Node{nNative, nXray},
		Groups: []storage.Group{
			{
				ID:             "g-manual",
				Name:           "Manual",
				Strategy:       "selector",
				SelectedNodeID: nNative.ID,
				NodeIDs:        []string{nNative.ID, nXray.ID},
			},
		},
		Routing: ruleset.RoutingProfile{
			Mode:           "global",
			DomainStrategy: "prefer_ipv4",
			LocalDNS:       "127.0.0.1",
			RemoteDNS:      "1.1.1.1",
			LogLevel:       "warn",
		},
		ActiveNodeID:   nNative.ID,
		MixedPort:      mixedPort,
		ClashAPIPort:   clashPort,
		ClashAPISecret: "orch-test-secret",
		EnableTUN:      false,
	}

	st, err := orch.Apply(ctx, in)
	if err != nil {
		t.Fatalf("Apply failed: %v\nlogs: %+v", err, orch.LogHistory(50))
	}
	if !st.Running || !st.SingBoxRunning || !st.XrayRunning {
		t.Fatalf("expected both cores running, got %+v", st)
	}
	if st.ActiveTag != "node-socks-native" {
		t.Fatalf("unexpected active tag: %s", st.ActiveTag)
	}
	initialSBPID := st.SingBoxPID
	initialXrayPID := st.XrayPID

	// Verify HTTPS request flows through sing-box MixedPort -> SOCKS5 -> HTTPS 204
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mixedPort))
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy:             http.ProxyURL(proxyURL),
			TLSClientConfig:   &tls.Config{RootCAs: rootPool},
			DisableKeepAlives: true,
		},
		Timeout: 5 * time.Second,
	}
	resp, err := httpClient.Get(http204Srv.URL)
	if err != nil {
		t.Fatalf("HTTP GET via sing-box native outbound failed: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected HTTP status via native outbound: %d", resp.StatusCode)
	}

	// Zero-interruption hot-switch to the Xray-bridged outbound
	in2 := in
	in2.ActiveNodeID = nXray.ID
	st2, err := orch.Apply(ctx, in2)
	if err != nil {
		t.Fatalf("Apply hot-switch failed: %v", err)
	}
	if st2.SingBoxPID != initialSBPID || st2.XrayPID != initialXrayPID {
		t.Fatalf("hot-switch restarted processes! initial=(%d,%d) after=(%d,%d)", initialSBPID, initialXrayPID, st2.SingBoxPID, st2.XrayPID)
	}
	if st2.ActiveTag != "node-socks-xray" {
		t.Fatalf("expected active tag node-socks-xray, got %s", st2.ActiveTag)
	}

	hitsBefore := socksHits.Load()
	resp2, err := httpClient.Get(http204Srv.URL)
	if err != nil {
		t.Fatalf("HTTP GET via Xray coprocessor bridge failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNoContent || socksHits.Load() <= hitsBefore {
		t.Fatalf("expected request routed via Xray coprocessor to upstream SOCKS5, status=%d hitsBefore=%d hitsAfter=%d", resp2.StatusCode, hitsBefore, socksHits.Load())
	}

	// Probe mixed batch (live native + live Xray + unloaded sandbox) concurrently
	probeRes := orch.ProbeNodes(ctx, []*config.Node{nNative, nXray, nUnloaded}, http204Srv.URL, 5*time.Second)
	for _, id := range []string{nNative.ID, nXray.ID, nUnloaded.ID} {
		r, ok := probeRes[id]
		if !ok {
			t.Fatalf("missing probe result for %s", id)
		}
		if r.LatencyMS < 0 || r.Error != "" {
			for _, entry := range orch.LogHistory(50) {
				t.Logf("[%s/%s] %s", entry.Core, entry.Level, entry.Message)
			}
			t.Fatalf("probe failed for %s: %+v", id, r)
		}
	}

	if err := orch.Stop(); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if stAfter := orch.Status(); stAfter.Running || stAfter.SingBoxRunning || stAfter.XrayRunning {
		t.Fatalf("expected processes stopped, got %+v", stAfter)
	}
}

func TestAppendLogStripsANSIAndInfersLevel(t *testing.T) {
	o := New(Options{WorkDir: t.TempDir()})
	o.AppendLog("sing-box", "", "\x1b[36mINFO\x1b[0m [\x1b[38;5;184m1242490280\x1b[0m 28ms] inbound/mixed: accepted")
	o.AppendLog("sing-box", "", "[33mWARN[0m [38;5;184m9988[0m connection reset")
	o.AppendLog("sing-box", "", "\x1b[31mERROR\x1b[0m dial tcp timeout")

	logs := o.LogHistory(10)
	if len(logs) != 3 {
		t.Fatalf("expected 3 logs, got %d", len(logs))
	}
	if logs[0].Level != "info" || logs[0].Message != "INFO [1242490280 28ms] inbound/mixed: accepted" {
		t.Fatalf("unexpected log[0]: %+v", logs[0])
	}
	if logs[1].Level != "warn" || logs[1].Message != "WARN 9988 connection reset" {
		t.Fatalf("unexpected log[1]: %+v", logs[1])
	}
	if logs[2].Level != "error" || logs[2].Message != "ERROR dial tcp timeout" {
		t.Fatalf("unexpected log[2]: %+v", logs[2])
	}

	// Leading sing-box UTC/offset timestamp + level prefix should be stripped while preserving level inference.
	o.AppendLog("sing-box", "", "+0000 2026-11-26 18:06:01 ERROR [4283015988 64ms] connection: open connection failed")
	o.AppendLog("sing-box", "", "+0800 2026-11-27 02:06:01 WARN inbound/mixed: connection reset")
	logs2 := o.LogHistory(10)
	if len(logs2) != 5 {
		t.Fatalf("expected 5 logs, got %d", len(logs2))
	}
	if logs2[3].Level != "error" || logs2[3].Message != "[4283015988 64ms] connection: open connection failed" {
		t.Fatalf("unexpected log[3]: %+v", logs2[3])
	}
	if logs2[4].Level != "warn" || logs2[4].Message != "inbound/mixed: connection reset" {
		t.Fatalf("unexpected log[4]: %+v", logs2[4])
	}
}

func TestTopologyFingerprintDetectsHealthTransition(t *testing.T) {
	baseNode := func(lat int) *config.Node {
		return &config.Node{
			ID:       "n1",
			Name:     "Shard 1",
			Protocol: config.ProtocolSocks,
			Address:  "198.51.100.1",
			Port:     1080,
			Latency:  lat,
		}
	}
	makeInput := func(lat int) ApplyInput {
		return ApplyInput{
			Nodes: []*config.Node{baseNode(lat)},
			Groups: []storage.Group{
				{ID: "g-lb", Name: "LB", Strategy: "loadbalance", NodeIDs: []string{"n1"}},
			},
			Routing:       ruleset.DefaultRoutingProfile(),
			ActiveGroupID: "g-lb",
			MixedPort:     10808,
			ClashAPIPort:  9090,
		}
	}

	fpHealthy50, err := topologyFingerprint(makeInput(50), false)
	if err != nil {
		t.Fatalf("fpHealthy50: %v", err)
	}
	fpHealthy120, err := topologyFingerprint(makeInput(120), false)
	if err != nil {
		t.Fatalf("fpHealthy120: %v", err)
	}
	fpDead, err := topologyFingerprint(makeInput(-1), false)
	if err != nil {
		t.Fatalf("fpDead: %v", err)
	}

	if fpHealthy50 != fpHealthy120 {
		t.Fatalf("normal latency jitter between healthy values should NOT trigger topology reload")
	}
	if fpHealthy50 == fpDead {
		t.Fatalf("transition from healthy (50ms) to dead (-1) MUST change topologyFingerprint so LB evicts dead shard")
	}
}

func TestTopologyFingerprintDetectsFailoverAndActiveLBChanges(t *testing.T) {
	baseIn := func() ApplyInput {
		return ApplyInput{
			Nodes: []*config.Node{
				{ID: "n1", Name: "N1", Protocol: config.ProtocolSocks, Address: "198.51.100.1", Port: 1080, Latency: 20},
				{ID: "n2", Name: "N2", Protocol: config.ProtocolSocks, Address: "198.51.100.2", Port: 1080, Latency: 30},
			},
			Groups: []storage.Group{
				{ID: "g-fo", Name: "FO", Strategy: "failover", FailoverTrigger: "high_latency_or_unavailable", HighLatencyMS: 800, NodeIDs: []string{"n1", "n2"}},
				{ID: "g-lb", Name: "LB", Strategy: "loadbalance", NodeIDs: []string{"n1", "n2"}},
			},
			Routing:       ruleset.DefaultRoutingProfile(),
			ActiveGroupID: "g-fo",
			HighLatencyMS: 800,
			MixedPort:     10808,
			ClashAPIPort:  9090,
		}
	}
	fpBase, err := topologyFingerprint(baseIn(), false)
	if err != nil {
		t.Fatal(err)
	}

	inTrig := baseIn()
	inTrig.Groups[0].FailoverTrigger = "unavailable_only"
	fpTrig, _ := topologyFingerprint(inTrig, false)
	if fpBase == fpTrig {
		t.Fatalf("expected FailoverTrigger change to alter topologyFingerprint")
	}

	inLat := baseIn()
	inLat.HighLatencyMS = 450
	fpLat, _ := topologyFingerprint(inLat, false)
	if fpBase == fpLat {
		t.Fatalf("expected global HighLatencyMS change to alter topologyFingerprint")
	}

	inLB := baseIn()
	inLB.ActiveGroupID = "g-lb"
	fpLB, _ := topologyFingerprint(inLB, false)
	if fpBase == fpLB {
		t.Fatalf("expected switching ActiveGroupID to loadbalance group to alter topologyFingerprint")
	}
}
