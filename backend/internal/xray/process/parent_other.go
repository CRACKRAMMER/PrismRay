//go:build !linux

// SPDX-License-Identifier: MPL-2.0
package process

import "os/exec"

func bindParent(cmd *exec.Cmd) {}
