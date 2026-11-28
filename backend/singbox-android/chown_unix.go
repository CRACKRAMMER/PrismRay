//go:build unix

// SPDX-License-Identifier: MPL-2.0

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func sudoInvokerIDs() (int, int, bool) {
	if os.Geteuid() != 0 {
		return -1, -1, false
	}
	uidStr := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidStr := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidStr == "" {
		return -1, -1, false
	}
	uid, uErr := strconv.Atoi(uidStr)
	if uErr != nil || uid <= 0 {
		return -1, -1, false
	}
	gid := uid
	if gidStr != "" {
		if parsedGid, gErr := strconv.Atoi(gidStr); gErr == nil && parsedGid > 0 {
			gid = parsedGid
		}
	}
	return uid, gid, true
}

func statusSnapshotFileMode() os.FileMode {
	return 0o600
}

func chownFileFD(f *os.File) {
	if f == nil {
		return
	}
	uid, gid, ok := sudoInvokerIDs()
	if !ok {
		return
	}
	_ = f.Chown(uid, gid)
}

func chownPathToSudoInvoker(path string) {
	uid, gid, ok := sudoInvokerIDs()
	if !ok || strings.TrimSpace(path) == "" {
		return
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	_ = os.Lchown(path, uid, gid)
}

func chownTreeToSudoInvoker(root string) {
	uid, gid, ok := sudoInvokerIDs()
	if !ok || strings.TrimSpace(root) == "" {
		return
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 {
		return
	}
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d != nil && d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		_ = os.Lchown(p, uid, gid)
		return nil
	})
}
