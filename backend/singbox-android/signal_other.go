// SPDX-License-Identifier: MPL-2.0
//go:build !unix

package main

import (
	"os"
	"syscall"
)

func trapEarlyReloadSignals() func() {
	return func() {}
}

func serviceSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM}
}

func isReloadSignal(_ os.Signal) bool {
	return false
}
