//go:build !unix

// SPDX-License-Identifier: MPL-2.0

package main

import "os"

func statusSnapshotFileMode() os.FileMode {
	return 0o600
}

func chownFileFD(*os.File) {}

func chownPathToSudoInvoker(string) {}

func chownTreeToSudoInvoker(string) {}
