//go:build windows

// SPDX-License-Identifier: MPL-2.0

package tun

import (
	"context"
	"fmt"
	"runtime"
	"syscall"
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

func isWindowsAdmin() bool {
	shell32 := syscall.NewLazyDLL("shell32.dll")
	proc := shell32.NewProc("IsUserAnAdmin")
	if err := proc.Find(); err != nil {
		return false
	}
	ret, _, _ := proc.Call()
	return ret != 0
}

// CheckPrivilege checks whether the current Windows process is elevated (Administrator)
// so sing-box can create a Wintun adapter and configure system routes.
func CheckPrivilege(singBoxBinary string) PrivilegeInfo {
	admin := isWindowsAdmin()
	detail := "running with Windows Administrator privileges (Wintun ready)"
	if !admin {
		detail = "Windows TUN (Wintun) requires Administrator privileges; relaunch PrismRay as Administrator"
	}
	return PrivilegeInfo{
		OS:                   runtime.GOOS,
		SingBoxPath:          singBoxBinary,
		HasCapAdmin:          admin,
		IsRoot:               admin,
		ReadyWithoutPassword: admin,
		CanPkexec:            false,
		Detail:               detail,
	}
}

// AuthorizeWithPkexec is not applicable on Windows; elevation requires UAC relaunch as Administrator.
func AuthorizeWithPkexec(_ context.Context, _ string) error {
	if isWindowsAdmin() {
		return nil
	}
	return fmt.Errorf("Windows 开启 TUN 需要管理员权限，请右键 PrismRay 选择「以管理员身份运行」")
}

// HasMarkCapability reports false on Windows (no Linux SO_MARK).
func HasMarkCapability(_ string) bool {
	return false
}

// CleanupStaleRoutes is a no-op on Windows (Wintun tears down interface routes on exit).
func CleanupStaleRoutes(_ context.Context, _ []byte) error {
	return nil
}
