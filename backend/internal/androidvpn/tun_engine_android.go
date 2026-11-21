// SPDX-License-Identifier: MPL-2.0
//go:build android

package androidvpn

import (
	"fmt"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

type tun2socksEngine struct{}

func defaultTunEngine() TunEngine {
	return &tun2socksEngine{}
}

func (e *tun2socksEngine) Start(tunFD int, mixedPort int, mtu int) error {
	if tunFD < 0 {
		return fmt.Errorf("invalid tun fd: %d", tunFD)
	}
	if mixedPort <= 0 {
		return fmt.Errorf("invalid mixed port: %d", mixedPort)
	}
	if mtu <= 0 {
		mtu = 1500
	}
	DefaultAppRoutingProxy.SetMixedPort(mixedPort)
	engine.Insert(&engine.Key{
		Device:     fmt.Sprintf("fd://%d", tunFD),
		Proxy:      "prismray://local",
		MTU:        mtu,
		LogLevel:   "warning",
		UDPTimeout: 60 * time.Second,
	})
	engine.Start()
	return nil
}

func (e *tun2socksEngine) Stop() {
	engine.Stop()
}
