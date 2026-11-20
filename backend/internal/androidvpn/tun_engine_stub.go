// SPDX-License-Identifier: MPL-2.0
//go:build !android

package androidvpn

type noopTunEngine struct{}

func defaultTunEngine() TunEngine {
	return &noopTunEngine{}
}

func (e *noopTunEngine) Start(_ int, _ int, _ int) error {
	return nil
}

func (e *noopTunEngine) Stop() {}
