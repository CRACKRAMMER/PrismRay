//go:build !linux && !darwin && !windows

// SPDX-License-Identifier: MPL-2.0

package tun

import (
	"context"
	"runtime"
)

// PrivilegeInfo reports whether TUN creation can run directly or requires elevation.
type PrivilegeInfo struct {
	OS                   string `json:"os"`
	SingBoxPath          string `json:"sing_box_path,omitempty"`
	HasCapAdmin          bool   `json:"has_cap_admin"`
	IsRoot               bool   `json:"is_root"`
	ReadyWithoutPassword bool   `json:"ready_without_password"`
	CanPkexec            bool   `json:"can_pkexec"`
	Detail               string `json:"detail,omitempty"`
}

// CheckPrivilege reports platform TUN privilege status on non-Linux systems.
func CheckPrivilege(singBoxBinary string) PrivilegeInfo {
	return PrivilegeInfo{
		OS:                   runtime.GOOS,
		SingBoxPath:          singBoxBinary,
		HasCapAdmin:          true,
		ReadyWithoutPassword: true,
		Detail:               "managed by OS native TUN/Wintun permissions",
	}
}

// AuthorizeWithPkexec is a no-op outside Linux.
func AuthorizeWithPkexec(_ context.Context, _ string) error {
	return nil
}

// HasMarkCapability reports false outside Linux (Windows/macOS do not use Linux SO_MARK).
func HasMarkCapability(_ string) bool {
	return false
}

// CleanupStaleRoutes is a no-op outside Linux.
func CleanupStaleRoutes(_ context.Context, _ []byte) error {
	return nil
}
