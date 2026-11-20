// SPDX-License-Identifier: MPL-2.0
package process

import (
	"os/exec"
	"syscall"
)

func bindParent(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL} }
