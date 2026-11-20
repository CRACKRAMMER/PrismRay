// SPDX-License-Identifier: MPL-2.0
//go:build android || linux

package androidvpn

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// TunBridge listens on a private Unix domain socket for an Android VpnService TUN fd (SCM_RIGHTS)
// and drives the embedded tun2socks engine against the running sing-box mixed port.
type TunBridge struct {
	mu          sync.Mutex
	socketPath  string
	listener    *net.UnixListener
	mixedPort   int
	mtu         int
	engine      TunEngine
	engineAlive bool
	activeFD    int
	closed      bool
}

// NewTunBridge creates a TunBridge using the platform default TunEngine (tun2socks on Android).
func NewTunBridge(engine TunEngine) *TunBridge {
	if engine == nil {
		engine = defaultTunEngine()
	}
	return &TunBridge{
		engine:   engine,
		activeFD: -1,
		mtu:      1500,
	}
}

// Listen prepares the Unix socket to accept TUN file descriptors from Kotlin ProxyVpnService.
func (b *TunBridge) Listen(socketPath string, mixedPort int, mtu int) (string, error) {
	b.Stop()

	if socketPath == "" {
		return "", fmt.Errorf("tun socket path is required")
	}
	if mixedPort <= 0 {
		return "", fmt.Errorf("invalid mixed port: %d", mixedPort)
	}
	if mtu <= 0 {
		mtu = 1500
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return "", fmt.Errorf("prepare tun socket dir: %w", err)
	}
	_ = os.Remove(socketPath)

	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("resolve unix addr: %w", err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return "", fmt.Errorf("listen unix tun socket: %w", err)
	}
	_ = os.Chmod(socketPath, 0o600)

	b.mu.Lock()
	b.socketPath = socketPath
	b.listener = ln
	b.mixedPort = mixedPort
	b.mtu = mtu
	b.closed = false
	b.mu.Unlock()

	go b.acceptLoop(ln)
	return socketPath, nil
}

func (b *TunBridge) acceptLoop(ln *net.UnixListener) {
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			b.mu.Lock()
			closed := b.closed
			b.mu.Unlock()
			if closed {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		b.handleConn(conn)
	}
}

func (b *TunBridge) handleConn(conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	buf := make([]byte, 16)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		slog.Warn("android tun bridge read failed", "err", err)
		_, _ = conn.Write([]byte{1})
		return
	}
	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		slog.Warn("android tun bridge parse cmsg failed", "err", err)
		_, _ = conn.Write([]byte{1})
		return
	}
	var receivedFD = -1
	for _, scm := range scms {
		fds, fdErr := syscall.ParseUnixRights(&scm)
		if fdErr != nil {
			continue
		}
		for _, fd := range fds {
			if receivedFD < 0 {
				receivedFD = fd
			} else {
				_ = syscall.Close(fd)
			}
		}
	}
	if receivedFD < 0 {
		slog.Warn("android tun bridge received no file descriptor")
		_, _ = conn.Write([]byte{1})
		return
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = syscall.Close(receivedFD)
		_, _ = conn.Write([]byte{1})
		return
	}
	if b.engineAlive {
		b.engine.Stop()
		b.engineAlive = false
	}
	mixedPort := b.mixedPort
	mtu := b.mtu
	startErr := b.engine.Start(receivedFD, mixedPort, mtu)
	if startErr != nil {
		b.mu.Unlock()
		_ = syscall.Close(receivedFD)
		slog.Error("android tun2socks start failed", "err", startErr)
		_, _ = conn.Write([]byte{1})
		return
	}
	b.engineAlive = true
	b.activeFD = receivedFD
	b.mu.Unlock()

	slog.Info("android tun2socks engine started", "fd", receivedFD, "mixed_port", mixedPort, "mtu", mtu)
	_, _ = conn.Write([]byte{0})
}

// Active reports whether the embedded TUN forwarder is currently running.
func (b *TunBridge) Active() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.engineAlive
}

// SocketPath returns the current Unix socket path if listening.
func (b *TunBridge) SocketPath() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.socketPath
}

// Stop terminates tun2socks and closes the Unix socket listener.
func (b *TunBridge) Stop() {
	b.mu.Lock()
	b.closed = true
	ln := b.listener
	b.listener = nil
	sockPath := b.socketPath
	b.socketPath = ""
	alive := b.engineAlive
	b.engineAlive = false
	b.activeFD = -1
	b.mu.Unlock()

	if ln != nil {
		_ = ln.Close()
	}
	if sockPath != "" {
		_ = os.Remove(sockPath)
	}
	if alive {
		b.engine.Stop()
	}
}
