// SPDX-License-Identifier: MPL-2.0

package androidvpn

// AppRoutingConfig describes live per-app custom rule authentication settings for Android tun2socks.
type AppRoutingConfig struct {
	MixedPort       int
	AppSocksPort    int
	AppSocksSecret  string
	OwnerSockPath   string
	WatchedPackages []string
}

// TunEngine forwards IP packets from an Android VpnService TUN file descriptor to local SOCKS5.
type TunEngine interface {
	Start(tunFD int, mixedPort int, mtu int) error
	Stop()
}
