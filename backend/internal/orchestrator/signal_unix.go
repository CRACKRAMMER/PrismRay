// SPDX-License-Identifier: MPL-2.0
//go:build unix

package orchestrator

import "syscall"

// NotifyAndroidNetworkChanged signals the running Android sing-box wrapper (SIGUSR1)
// to refresh its platform network interface table after Wi-Fi / cellular transitions.
func (o *Orchestrator) NotifyAndroidNetworkChanged() {
	o.mu.RLock()
	proc := o.singBoxProc
	android := o.androidMode
	o.mu.RUnlock()
	if !android || proc == nil || proc.cmd == nil || proc.cmd.Process == nil {
		return
	}
	_ = proc.cmd.Process.Signal(syscall.SIGUSR1)
}
