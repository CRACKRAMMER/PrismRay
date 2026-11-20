// SPDX-License-Identifier: MPL-2.0
//go:build android || linux

package androidvpn

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

type fakeTunEngine struct {
	mu       sync.Mutex
	started  bool
	stopped  bool
	gotFD    int
	gotPort  int
	gotMTU   int
	notifyCh chan struct{}
}

func (f *fakeTunEngine) Start(tunFD int, mixedPort int, mtu int) error {
	f.mu.Lock()
	f.started = true
	f.gotFD = tunFD
	f.gotPort = mixedPort
	f.gotMTU = mtu
	f.mu.Unlock()
	_ = syscall.Close(tunFD)
	select {
	case f.notifyCh <- struct{}{}:
	default:
	}
	return nil
}

func (f *fakeTunEngine) Stop() {
	f.mu.Lock()
	f.stopped = true
	f.mu.Unlock()
}

func TestTunBridgeReceivesFDViaSCMRights(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "tun.sock")

	eng := &fakeTunEngine{notifyCh: make(chan struct{}, 1)}
	bridge := NewTunBridge(eng)
	defer bridge.Stop()

	if _, err := bridge.Listen(sockPath, 10808, 1500); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	rFile, wFile, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer rFile.Close()
	defer wFile.Close()

	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		t.Fatalf("ResolveUnixAddr: %v", err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		t.Fatalf("DialUnix: %v", err)
	}
	defer conn.Close()

	rights := syscall.UnixRights(int(rFile.Fd()))
	if _, _, err := conn.WriteMsgUnix([]byte{1}, rights, nil); err != nil {
		t.Fatalf("WriteMsgUnix: %v", err)
	}
	ack := make([]byte, 1)
	if _, err := conn.Read(ack); err != nil {
		t.Fatalf("Read ack: %v", err)
	}
	if ack[0] != 0 {
		t.Fatalf("expected ack 0, got %d", ack[0])
	}

	<-eng.notifyCh
	eng.mu.Lock()
	if !eng.started || eng.gotPort != 10808 || eng.gotMTU != 1500 || eng.gotFD < 0 {
		t.Fatalf("unexpected engine state: %+v", eng)
	}
	eng.mu.Unlock()

	if !bridge.Active() {
		t.Fatal("expected bridge.Active() == true")
	}

	bridge.Stop()
	eng.mu.Lock()
	if !eng.stopped {
		t.Fatal("expected engine.Stop() called on bridge.Stop()")
	}
	eng.mu.Unlock()
}
