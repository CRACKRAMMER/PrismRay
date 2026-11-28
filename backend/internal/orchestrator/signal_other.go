// SPDX-License-Identifier: MPL-2.0
//go:build !unix

package orchestrator

// NotifyAndroidNetworkChanged is a no-op on non-Unix hosts.
func (o *Orchestrator) NotifyAndroidNetworkChanged() {}
