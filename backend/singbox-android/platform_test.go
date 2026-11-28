// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing/service"
)

func TestAndroidPlatformLoadsSnapshotAndSkipsTun(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "android-netif.json")
	raw := `{
		"interfaces": [
			{"name":"tun0","index":9,"mtu":8500,"type":"other","addresses":["172.19.0.1/30"],"is_default":false},
			{"name":"wlan0","index":4,"mtu":1500,"type":"wifi","addresses":["192.168.1.42/24","2001:db8::42/64"],"gateways":["192.168.1.1"],"dns_servers":["223.5.5.5"],"is_default":true,"expensive":false}
		]
	}`
	if err := os.WriteFile(snapPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	p := newAndroidPlatform("", snapPath)
	ifaces, err := p.NetworkInterfaces()
	if err != nil {
		t.Fatalf("NetworkInterfaces failed: %v", err)
	}
	if len(ifaces) != 2 {
		t.Fatalf("expected wlan0 + synthetic lo (2 interfaces), got %d: %+v", len(ifaces), ifaces)
	}
	if ifaces[0].Name != "wlan0" || ifaces[0].Index != 4 || len(ifaces[0].Addresses) != 2 {
		t.Fatalf("unexpected primary interface: %+v", ifaces[0])
	}
	mon := p.CreateDefaultInterfaceMonitor(nil)
	def := mon.DefaultInterface()
	if def == nil || def.Name != "wlan0" || def.Index != 4 {
		t.Fatalf("expected default interface wlan0(4), got %+v", def)
	}
}

func TestAndroidPlatformSynthesizesFallbackWithoutSnapshot(t *testing.T) {
	p := newAndroidPlatform("", filepath.Join(t.TempDir(), "missing.json"))
	ifaces, err := p.NetworkInterfaces()
	if err != nil {
		t.Fatalf("fallback NetworkInterfaces failed: %v", err)
	}
	if len(ifaces) < 2 {
		t.Fatalf("expected synthesized primary + lo interfaces, got %+v", ifaces)
	}
	if def := p.CreateDefaultInterfaceMonitor(nil).DefaultInterface(); def == nil || def.Name == "" {
		t.Fatalf("expected non-nil synthesized default interface, got %+v", def)
	}
}

func TestProtectFDSendsSCMRightsAndChecksAck(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "protect.sock")
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	receivedFD := make(chan bool, 1)
	go func() {
		conn, aErr := ln.AcceptUnix()
		if aErr != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 8)
		oob := make([]byte, syscall.CmsgSpace(4))
		_, oobn, _, _, rErr := conn.ReadMsgUnix(buf, oob)
		if rErr != nil {
			_, _ = conn.Write([]byte{1})
			return
		}
		scms, pErr := syscall.ParseSocketControlMessage(oob[:oobn])
		ok := false
		if pErr == nil {
			for _, scm := range scms {
				if fds, fErr := syscall.ParseUnixRights(&scm); fErr == nil && len(fds) > 0 {
					ok = true
					for _, fd := range fds {
						_ = syscall.Close(fd)
					}
				}
			}
		}
		receivedFD <- ok
		if ok {
			_, _ = conn.Write([]byte{0})
		} else {
			_, _ = conn.Write([]byte{1})
		}
	}()

	f, err := os.CreateTemp(t.TempDir(), "fd-test")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if err := protectFD(sockPath, int(f.Fd())); err != nil {
		t.Fatalf("protectFD failed: %v", err)
	}
	select {
	case ok := <-receivedFD:
		if !ok {
			t.Fatal("protect server did not receive ancillary file descriptor")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for protect server")
	}
}

func TestSingBoxTailscaleEndpointStartsViaAndroidPlatform(t *testing.T) {
	dir := t.TempDir()
	snapPath := filepath.Join(dir, "android-netif.json")
	snap := `{"interfaces":[{"name":"wlan0","index":2,"mtu":1500,"type":"wifi","addresses":["192.168.1.50/24"],"gateways":["192.168.1.1"],"is_default":true}]}`
	if err := os.WriteFile(snapPath, []byte(snap), 0o600); err != nil {
		t.Fatal(err)
	}

	stateDir := filepath.Join(dir, "ts-state")
	cfgPath := filepath.Join(dir, "sing-box.json")
	cfgJSON := `{
		"log": {"level": "warn"},
		"dns": {
			"servers": [
				{"type": "udp", "tag": "local-dns", "server": "223.5.5.5"},
				{"type": "tailscale", "tag": "tailscale-dns", "endpoint": "tailscale-ep", "accept_default_resolvers": false}
			],
			"final": "local-dns"
		},
		"endpoints": [
			{
				"type": "tailscale",
				"tag": "tailscale-ep",
				"state_directory": "` + filepath.ToSlash(stateDir) + `",
				"hostname": "prismray-android-test",
				"ephemeral": true,
				"accept_routes": true
			}
		],
		"outbounds": [
			{"type": "direct", "tag": "direct"}
		],
		"route": {
			"default_domain_resolver": "local-dns",
			"final": "direct"
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	platform := newAndroidPlatform("", snapPath)
	ctx, cancel := context.WithCancel(service.ExtendContext(baseContext(platform)))
	defer cancel()

	options, err := loadOptions(ctx, cfgPath, true, true)
	if err != nil {
		t.Fatalf("loadOptions failed: %v", err)
	}
	instance, err := box.New(box.Options{
		Context: ctx,
		Options: options,
	})
	if err != nil {
		t.Fatalf("box.New failed: %v", err)
	}
	defer instance.Close()

	if err := instance.Start(); err != nil {
		t.Fatalf("sing-box Tailscale endpoint failed to start under androidPlatform: %v", err)
	}
	statusPath := filepath.Join(dir, "tailscale-status.json")
	stopTS := startTailscaleRuntime(ctx, instance, statusPath, "test-instance-token", "", "")
	defer stopTS()
	raw, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("expected tailscale status snapshot at %s: %v", statusPath, err)
	}
	var parsed tailscaleStatusSnapshot
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal tailscale status snapshot: %v (%s)", err, string(raw))
	}
	if parsed.PID != os.Getpid() || parsed.InstanceToken != "test-instance-token" || parsed.BackendState == "" || parsed.UpdatedAt == "" {
		t.Fatalf("unexpected tailscale status snapshot: %+v", parsed)
	}
}

func TestWriteStatusSnapshotAtomicRefusesSymlinkAndUses0600(t *testing.T) {
	dir := t.TempDir()
	statusPath := filepath.Join(dir, "ts-status.json")
	snap := tailscaleStatusSnapshot{
		PID:          os.Getpid(),
		BackendState: "Running",
		UpdatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeStatusSnapshotAtomic(statusPath, snap); err != nil {
		t.Fatalf("writeStatusSnapshotAtomic failed: %v", err)
	}
	info, err := os.Stat(statusPath)
	if err != nil {
		t.Fatalf("stat status snapshot: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected status snapshot permissions 0600, got %#o", info.Mode().Perm())
	}

	victimPath := filepath.Join(dir, "victim.txt")
	if err := os.WriteFile(victimPath, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(dir, "symlink-status.json")
	if err := os.Symlink(victimPath, symlinkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := writeStatusSnapshotAtomic(symlinkPath, snap); err == nil {
		t.Fatalf("expected writeStatusSnapshotAtomic to refuse symlink target")
	}
	victimData, err := os.ReadFile(victimPath)
	if err != nil || string(victimData) != "untouched" {
		t.Fatalf("expected symlink victim untouched, got %q (%v)", string(victimData), err)
	}
}
