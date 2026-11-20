//go:build linux

// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"os/exec"
	"syscall"
)

func bindParent(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGTERM,
	}
}

func terminateGracefully(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(syscall.SIGTERM)
}
