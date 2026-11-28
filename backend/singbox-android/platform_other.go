// SPDX-License-Identifier: MPL-2.0
//go:build !unix

package main

import "github.com/sagernet/sing-box/adapter"

func newAndroidPlatform(_, _ string) adapter.PlatformInterface {
	return nil
}
