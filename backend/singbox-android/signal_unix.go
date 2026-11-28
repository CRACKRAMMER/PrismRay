// SPDX-License-Identifier: MPL-2.0
//go:build unix

package main

import (
	"os"
	"os/signal"
	"syscall"
)

// trapEarlyReloadSignals ensures Android SIGUSR1 network-change notifications arriving before
// androidInterfaceMonitor.Start() cannot terminate the process with Go's default signal disposition.
func trapEarlyReloadSignals() func() {
	ch := make(chan os.Signal, 2)
	signal.Notify(ch, syscall.SIGUSR1)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-ch:
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}

func serviceSignals() []os.Signal {
	return []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP}
}

func isReloadSignal(sig os.Signal) bool {
	return sig == syscall.SIGHUP
}
