// SPDX-License-Identifier: MPL-2.0

package install

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// FindXrayBinary attempts to locate the xray executable.
// It checks:
// 1. Current working directory
// 2. PATH
// Returns the absolute path if found, or an error.
func FindXrayBinary() (string, error) {
	binaryName := "xray"
	if runtime.GOOS == "windows" {
		binaryName = "xray.exe"
	}

	// 1. Check current directory
	cwd, err := os.Getwd()
	if err == nil {
		localPath := filepath.Join(cwd, binaryName)
		if _, err := os.Stat(localPath); err == nil {
			return localPath, nil
		}
	}

	// 2. Check PATH
	path, err := exec.LookPath(binaryName)
	if err == nil {
		return filepath.Abs(path)
	}

	return "", fmt.Errorf("xray binary not found in CWD or PATH")
}
