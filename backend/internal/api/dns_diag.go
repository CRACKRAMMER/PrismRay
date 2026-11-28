// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
)

// DNSProbeStep represents one DNS resolution result for a given resolver path.
type DNSProbeStep struct {
	Name      string   `json:"name"`
	Server    string   `json:"server"`
	ViaProxy  bool     `json:"via_proxy"`
	LatencyMS int64    `json:"latency_ms"`
	IPs       []string `json:"ips"`
	Error     string   `json:"error,omitempty"`
}

// DNSDiagnosticsResponse aggregates DNS resolution, route simulation, and leak heuristics.
type DNSDiagnosticsResponse struct {
	Domain             string                   `json:"domain"`
	CheckedAt          string                   `json:"checked_at"`
	Running            bool                     `json:"running"`
	RoutingMode        string                   `json:"routing_mode"`
	HijackDNS          bool                     `json:"hijack_dns"`
	FakeIP             bool                     `json:"fake_ip"`
	Simulation         ruleset.SimulationResult `json:"simulation"`
	SystemResolver     DNSProbeStep             `json:"system_resolver"`
	LocalDNS           DNSProbeStep             `json:"local_dns"`
	RemoteDNS          DNSProbeStep             `json:"remote_dns"`
	TailscaleMagicNote string                   `json:"tailscale_magic_note,omitempty"`
	LeakStatus         string                   `json:"leak_status"` // "safe" | "warning" | "info"
	Notes              []string                 `json:"notes"`
}

func (s *Server) handleDiagnosticsDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Domain string `json:"domain"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	domain := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.Domain)), ".")
	if domain == "" {
		domain = "www.google.com"
	}
	if len(domain) > 253 || strings.ContainsAny(domain, " \t\r\n/\\:@") {
		http.Error(w, "invalid domain name", http.StatusBadRequest)
		return
	}

	profile, err := s.routingProfile()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	sim := ruleset.Simulate(profile, ruleset.SimulationInput{Domain: domain})
	orchStatus := s.ensureOrchestrator().Status()

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	var (
		sysRes    DNSProbeStep
		localRes  DNSProbeStep
		remoteRes DNSProbeStep
		wg        sync.WaitGroup
	)
	wg.Add(3)

	go func() {
		defer wg.Done()
		sysRes = probeSystemDNS(ctx, domain)
	}()
	go func() {
		defer wg.Done()
		localRes = s.probeConfiguredDNS(ctx, "local_dns", profile.LocalDNS, domain, 0)
	}()
	go func() {
		defer wg.Done()
		proxyPort := 0
		if orchStatus.Running && orchStatus.MixedPort > 0 {
			proxyPort = orchStatus.MixedPort
		}
		remoteRes = s.probeConfiguredDNS(ctx, "remote_dns", profile.RemoteDNS, domain, proxyPort)
	}()
	wg.Wait()

	magicNote := ""
	if tsCfg, tsErr := s.tailscaleConfig(false); tsErr == nil && tsCfg.Enabled {
		tsStatus := s.tailscaleRuntimeStatus(tsCfg, false)
		suffix := strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(tsStatus.MagicDNSSuffix)), "."), ".")
		if suffix != "" && (domain == suffix || strings.HasSuffix(domain, "."+suffix)) {
			magicNote = fmt.Sprintf("Matches Tailscale MagicDNS suffix (%s) -> routed to tailscale-ep", suffix)
		} else if strings.HasSuffix(domain, ".ts.net") {
			magicNote = "Matches Tailscale .ts.net domain -> routed to tailscale-ep"
		}
	}

	leakStatus, notes := evaluateDNSLeak(profile, orchStatus.Running, sim, sysRes, localRes, remoteRes, magicNote)

	writeJSON(w, http.StatusOK, DNSDiagnosticsResponse{
		Domain:             domain,
		CheckedAt:          time.Now().UTC().Format(time.RFC3339),
		Running:            orchStatus.Running,
		RoutingMode:        profile.Mode,
		HijackDNS:          profile.HijackDNSEnabled(),
		FakeIP:             profile.FakeIP,
		Simulation:         sim,
		SystemResolver:     sysRes,
		LocalDNS:           localRes,
		RemoteDNS:          remoteRes,
		TailscaleMagicNote: magicNote,
		LeakStatus:         leakStatus,
		Notes:              notes,
	})
}

func probeSystemDNS(ctx context.Context, domain string) DNSProbeStep {
	start := time.Now()
	step := DNSProbeStep{
		Name:   "system",
		Server: "OS Default Resolver",
		IPs:    []string{},
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", domain)
	step.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		step.Error = err.Error()
		return step
	}
	for _, ip := range ips {
		step.IPs = append(step.IPs, ip.Unmap().String())
	}
	return step
}

func (s *Server) probeConfiguredDNS(ctx context.Context, name, serverSpec, domain string, proxyPort int) DNSProbeStep {
	clean := strings.TrimSpace(serverSpec)
	low := strings.ToLower(clean)
	isDoH := strings.HasPrefix(low, "https://") || strings.HasPrefix(low, "h3://")
	isDoT := strings.HasPrefix(low, "tls://")
	step := DNSProbeStep{
		Name:     name,
		Server:   clean,
		ViaProxy: proxyPort > 0 && (isDoH || isDoT),
		IPs:      []string{},
	}
	if clean == "" {
		step.Error = "DNS server not configured"
		return step
	}

	start := time.Now()
	if low == "local" || strings.HasPrefix(low, "dhcp://") {
		sys := probeSystemDNS(ctx, domain)
		step.LatencyMS = time.Since(start).Milliseconds()
		step.IPs = sys.IPs
		step.Error = sys.Error
		return step
	}
	if isDoH {
		endpoint := clean
		if strings.HasPrefix(low, "h3://") {
			endpoint = "https://" + clean[len("h3://"):]
		}
		ips, err := s.queryDoH(ctx, endpoint, domain, proxyPort)
		step.LatencyMS = time.Since(start).Milliseconds()
		if err != nil {
			step.Error = err.Error()
			return step
		}
		step.IPs = ips
		return step
	}
	if isDoT {
		ips, err := queryDoT(ctx, clean, domain, proxyPort)
		step.LatencyMS = time.Since(start).Milliseconds()
		if err != nil {
			step.Error = err.Error()
			return step
		}
		step.IPs = ips
		return step
	}

	addr := clean
	if strings.Contains(addr, "://") {
		if u, err := url.Parse(addr); err == nil && u.Host != "" {
			addr = u.Host
		}
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "53")
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: func(dCtx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(dCtx, "udp", addr)
		},
	}
	ips, err := r.LookupNetIP(ctx, "ip", domain)
	step.LatencyMS = time.Since(start).Milliseconds()
	if err != nil {
		step.Error = err.Error()
		return step
	}
	for _, ip := range ips {
		step.IPs = append(step.IPs, ip.Unmap().String())
	}
	return step
}

func queryDoT(ctx context.Context, spec, domain string, proxyPort int) ([]string, error) {
	wireQuery, err := buildDNSAQuery(domain)
	if err != nil {
		return nil, err
	}
	target := strings.TrimPrefix(strings.TrimSpace(spec), "tls://")
	if idx := strings.IndexByte(target, '/'); idx >= 0 {
		target = target[:idx]
	}
	host := target
	if h, _, splitErr := net.SplitHostPort(target); splitErr == nil {
		host = h
	} else {
		target = net.JoinHostPort(strings.Trim(target, "[]"), "853")
		host = strings.Trim(host, "[]")
	}

	var rawConn net.Conn
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	if proxyPort > 0 {
		rawConn, err = dialViaLocalHTTPProxy(ctx, dialer, proxyPort, target)
	} else {
		rawConn, err = dialer.DialContext(ctx, "tcp", target)
	}
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(dl)
	} else {
		_ = rawConn.SetDeadline(time.Now().Add(6 * time.Second))
	}

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.BigEndian, uint16(len(wireQuery)))
	frame.Write(wireQuery)
	if _, err := tlsConn.Write(frame.Bytes()); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(tlsConn, lenBuf[:]); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if respLen <= 0 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DoT response length %d", respLen)
	}
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(tlsConn, respBuf); err != nil {
		return nil, err
	}
	return parseDNSAResponse(respBuf)
}

func dialViaLocalHTTPProxy(ctx context.Context, dialer *net.Dialer, proxyPort int, target string) (net.Conn, error) {
	cleanTarget := strings.TrimSpace(target)
	if cleanTarget == "" || strings.ContainsAny(cleanTarget, "\r\n\t \x00") {
		return nil, fmt.Errorf("invalid proxy CONNECT target")
	}
	if host, port, err := net.SplitHostPort(cleanTarget); err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("invalid proxy CONNECT host:port target")
	}
	conn, err := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", cleanTarget, cleanTarget)
	if _, err := io.WriteString(conn, connectReq); err != nil {
		conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT %s returned HTTP %d", target, resp.StatusCode)
	}
	return conn, nil
}

func (s *Server) queryDoH(ctx context.Context, endpoint, domain string, proxyPort int) ([]string, error) {
	wireQuery, err := buildDNSAQuery(domain)
	if err != nil {
		return nil, err
	}
	var client *http.Client
	if proxyPort > 0 {
		client = s.safeProxyHTTPClient(6*time.Second, proxyPort)
	} else {
		client = s.safeHTTPClient(6 * time.Second)
	}
	defer closeClientIdleConnections(client)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wireQuery))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "PrismRay/"+AppVersion)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, err
	}
	return parseDNSAResponse(raw)
}

func buildDNSAQuery(domain string) ([]byte, error) {
	var idBuf [2]byte
	_, _ = rand.Read(idBuf[:])
	var buf bytes.Buffer
	// Header: ID, Flags (RD=1 -> 0x0100), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
	buf.Write(idBuf[:])
	_ = binary.Write(&buf, binary.BigEndian, uint16(0x0100))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))
	_ = binary.Write(&buf, binary.BigEndian, uint16(0))

	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return nil, fmt.Errorf("invalid dns label %q", label)
		}
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0)
	// QTYPE=A (1), QCLASS=IN (1)
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	_ = binary.Write(&buf, binary.BigEndian, uint16(1))
	return buf.Bytes(), nil
}

func skipDNSName(msg []byte, offset int) (int, error) {
	for i := 0; i < 128; i++ {
		if offset >= len(msg) {
			return 0, fmt.Errorf("truncated dns name")
		}
		b := msg[offset]
		if b == 0 {
			return offset + 1, nil
		}
		if b&0xC0 == 0xC0 {
			if offset+1 >= len(msg) {
				return 0, fmt.Errorf("truncated dns pointer")
			}
			return offset + 2, nil
		}
		offset += int(b) + 1
	}
	return 0, fmt.Errorf("dns name compression loop")
}

func parseDNSAResponse(msg []byte) ([]string, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("short dns response")
	}
	rcode := msg[3] & 0x0F
	if rcode != 0 {
		return nil, fmt.Errorf("dns rcode %d", rcode)
	}
	qdCount := int(binary.BigEndian.Uint16(msg[4:6]))
	anCount := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	var err error
	for i := 0; i < qdCount; i++ {
		off, err = skipDNSName(msg, off)
		if err != nil {
			return nil, err
		}
		if off+4 > len(msg) {
			return nil, fmt.Errorf("truncated dns question")
		}
		off += 4
	}
	ips := []string{}
	seen := map[string]bool{}
	for i := 0; i < anCount; i++ {
		off, err = skipDNSName(msg, off)
		if err != nil {
			break
		}
		if off+10 > len(msg) {
			break
		}
		rtype := binary.BigEndian.Uint16(msg[off : off+2])
		rdLen := int(binary.BigEndian.Uint16(msg[off+8 : off+10]))
		off += 10
		if off+rdLen > len(msg) {
			break
		}
		if rtype == 1 && rdLen == 4 {
			ip := netip.AddrFrom4([4]byte{msg[off], msg[off+1], msg[off+2], msg[off+3]}).String()
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		} else if rtype == 28 && rdLen == 16 {
			var b16 [16]byte
			copy(b16[:], msg[off:off+16])
			ip := netip.AddrFrom16(b16).String()
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
		off += rdLen
	}
	return ips, nil
}

func evaluateDNSLeak(
	profile ruleset.RoutingProfile,
	running bool,
	sim ruleset.SimulationResult,
	sysRes, localRes, remoteRes DNSProbeStep,
	magicNote string,
) (string, []string) {
	notes := []string{}
	status := "safe"

	if magicNote != "" {
		notes = append(notes, magicNote)
	}

	if !running {
		status = "info"
		notes = append(notes, "Proxy core is currently stopped; DNS requests use the host network directly.")
		return status, notes
	}

	if !profile.HijackDNSEnabled() && profile.Mode != "direct" {
		status = "warning"
		notes = append(notes, "DNS hijacking (hijack_dns) is disabled; apps bypassing the proxy may leak DNS queries to local ISP resolvers.")
	} else {
		notes = append(notes, "DNS hijacking is enabled for TUN/intercepted traffic.")
	}

	if profile.FakeIP {
		fakePfx, err := netip.ParsePrefix(profile.FakeIPv4Range)
		matchedFake := false
		if err == nil {
			for _, raw := range sysRes.IPs {
				if addr, aErr := netip.ParseAddr(raw); aErr == nil && fakePfx.Contains(addr) {
					matchedFake = true
					break
				}
			}
		}
		if matchedFake {
			notes = append(notes, "FakeIP is active and system resolver returned an address inside "+profile.FakeIPv4Range+".")
		} else {
			notes = append(notes, "FakeIP is enabled in profile (proxy-path queries are resolved remotely by sing-box).")
		}
	}

	if sim.Outbound != "direct" && sim.Action == "route" {
		if remoteRes.Error != "" {
			status = "warning"
			notes = append(notes, "Remote DoH probe via proxy failed: "+remoteRes.Error)
		} else if len(remoteRes.IPs) > 0 && len(localRes.IPs) > 0 {
			remoteSet := map[string]bool{}
			for _, ip := range remoteRes.IPs {
				remoteSet[ip] = true
			}
			overlap := false
			for _, ip := range localRes.IPs {
				if remoteSet[ip] {
					overlap = true
					break
				}
			}
			if !overlap {
				notes = append(notes, "Local DNS and Remote DNS returned distinct IPs (expected for CDN geo-routing or when local ISP DNS differs); proxied connections will use Remote DNS.")
			} else {
				notes = append(notes, "Remote DNS resolved cleanly via active proxy.")
			}
		}
	}

	return status, notes
}
