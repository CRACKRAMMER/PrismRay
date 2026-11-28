// SPDX-License-Identifier: MPL-2.0
//go:build unix

package main

import (
	"fmt"
	"net"
	"syscall"
	"time"
)

// protectFD sends a socket file descriptor to Kotlin ProxyVpnService's protect.sock via SCM_RIGHTS
// so Android VpnService.protect(fd) exempts Tailscale's WireGuard/DERP sockets from tun0 routing loops.
func protectFD(socketPath string, fd int) error {
	addr, err := net.ResolveUnixAddr("unix", socketPath)
	if err != nil {
		return fmt.Errorf("resolve protect socket: %w", err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return fmt.Errorf("dial protect socket: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	oob := syscall.UnixRights(fd)
	if _, _, err := conn.WriteMsgUnix([]byte{1}, oob, nil); err != nil {
		return fmt.Errorf("send protect fd: %w", err)
	}
	ack := make([]byte, 1)
	if _, err := conn.Read(ack); err != nil {
		return fmt.Errorf("read protect ack: %w", err)
	}
	if ack[0] != 0 {
		return fmt.Errorf("protect socket rejected fd (ack=%d)", ack[0])
	}
	return nil
}
