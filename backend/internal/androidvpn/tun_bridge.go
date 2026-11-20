// SPDX-License-Identifier: MPL-2.0

package androidvpn

// TunEngine forwards IP packets from an Android VpnService TUN file descriptor to local SOCKS5.
type TunEngine interface {
	Start(tunFD int, mixedPort int, mtu int) error
	Stop()
}
