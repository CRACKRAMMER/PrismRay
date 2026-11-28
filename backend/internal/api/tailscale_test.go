// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
)

func TestTailscaleRuntimeStatusStates(t *testing.T) {
	dir := t.TempDir()
	cfg := appconfig.Default()
	cfg.SetRuntimeDir(dir)
	srv := &Server{cfg: cfg}

	// 1. Disabled
	st := srv.tailscaleRuntimeStatus(ruleset.TailscaleConfig{Enabled: false, Hostname: "phone"}, false)
	if st.State != "disabled" {
		t.Fatalf("expected disabled, got %+v", st)
	}

	// 2. Enabled while core stopped
	st = srv.tailscaleRuntimeStatus(ruleset.TailscaleConfig{Enabled: true, Hostname: "phone"}, false)
	if st.State != "stopped" {
		t.Fatalf("expected stopped when core is not running, got %+v", st)
	}

	// 3. Enabled while core stopped after a tailscale startup fatal error
	orch := srv.ensureOrchestrator()
	orch.AppendLog("sing-box", "error", "FATAL[0000] start service: post-start endpoint/tailscale[tailscale-ep]: invalid auth key")
	st = srv.tailscaleRuntimeStatus(ruleset.TailscaleConfig{Enabled: true, Hostname: "phone"}, false)
	if st.State != "error" || st.LastError == "" {
		t.Fatalf("expected error state with last_error, got %+v", st)
	}

	// 4. Live snapshot parsing + PID & InstanceToken validation (sudo TUN support)
	snapPath := srv.tailscaleStatusPath()
	snap := tailscaleLiveSnapshot{
		PID:            4242,
		InstanceToken:  "tok-abc-123",
		BackendState:   "Running",
		Online:         true,
		SelfHostname:   "prismray-phone",
		SelfDNSName:    "prismray-phone.tail1234.ts.net.",
		TailscaleIPs:   []string{"100.88.12.34", "fd7a:115c:a1e0::12"},
		NetworkName:    "user@example.com",
		MagicDNSSuffix: "tail1234.ts.net",
		PeersOnline:    3,
		PeersTotal:     5,
		Peers: []TailscalePeerStatus{
			{Hostname: "archlinux", DNSName: "archlinux.tail1234.ts.net", OS: "linux", IPv4: "100.67.60.126", TailscaleIPs: []string{"100.67.60.126"}, Online: true},
			{Hostname: "macbook", DNSName: "macbook.tail1234.ts.net", OS: "macOS", IPv4: "100.67.60.200", TailscaleIPs: []string{"100.67.60.200"}, Online: false},
		},
		UpdatedAt: "2026-11-26T06:40:00Z",
	}
	raw, _ := json.Marshal(snap)
	if err := os.WriteFile(snapPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	// Mismatched PID and mismatched token must reject stale snapshot.
	if _, ok := readTailscaleLiveSnapshot(snapPath, 9999, "tok-wrong"); ok {
		t.Fatalf("expected mismatched PID & token snapshot to be ignored")
	}
	// Mismatched PID (e.g., sudo wrapper PID != sing-box child PID) MUST succeed when InstanceToken matches!
	parsedByToken, ok := readTailscaleLiveSnapshot(snapPath, 9999, "tok-abc-123")
	if !ok || parsedByToken.SelfHostname != "prismray-phone" || len(parsedByToken.Peers) != 2 {
		t.Fatalf("expected matching InstanceToken snapshot to parse despite different sudo PID, got ok=%v snap=%+v", ok, parsedByToken)
	}
	// Matching PID without token must still parse cleanly.
	parsed, ok := readTailscaleLiveSnapshot(snapPath, 4242, "")
	if !ok || parsed.SelfHostname != "prismray-phone" || len(parsed.TailscaleIPs) != 2 || len(parsed.Peers) != 2 || !parsed.Peers[0].Online || parsed.Peers[0].IPv4 != "100.67.60.126" {
		t.Fatalf("expected matching PID snapshot to parse, got ok=%v snap=%+v", ok, parsed)
	}

	// 5. Log auth URL extraction
	orch.AppendLog("sing-box", "info", "endpoint/tailscale[tailscale-ep]: Waiting for authentication: https://login.tailscale.com/a/abc123")
	authURL, _, _ := orch.TailscaleLogTelemetry()
	if authURL != "https://login.tailscale.com/a/abc123" {
		t.Fatalf("expected parsed auth URL, got %q", authURL)
	}

	if filepath.Base(snapPath) != "tailscale-status.json" {
		t.Fatalf("unexpected snapshot path: %s", snapPath)
	}
}
