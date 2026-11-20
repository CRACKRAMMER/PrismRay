//go:build windows

// SPDX-License-Identifier: MPL-2.0

package orchestrator

import "os/exec"

func bindParent(cmd *exec.Cmd) {}

func terminateGracefully(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
