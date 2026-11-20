// SPDX-License-Identifier: MPL-2.0
//go:build !android && !linux

package androidvpn

import "fmt"

// TunBridge is a no-op stub on non-Linux/non-Android desktop platforms.
type TunBridge struct{}

func NewTunBridge(_ TunEngine) *TunBridge {
	return &TunBridge{}
}

func (b *TunBridge) Listen(_ string, _ int, _ int) (string, error) {
	return "", fmt.Errorf("android tun bridge is only supported on Android")
}

func (b *TunBridge) Active() bool { return false }

func (b *TunBridge) SocketPath() string { return "" }

func (b *TunBridge) Stop() {}
