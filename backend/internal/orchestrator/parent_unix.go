//go:build !linux && !windows

// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"os/exec"
	"syscall"
)

func bindParent(cmd *exec.Cmd) {}

func terminateGracefully(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}
