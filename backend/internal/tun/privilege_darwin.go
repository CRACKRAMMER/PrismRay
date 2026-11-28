//go:build darwin

// SPDX-License-Identifier: MPL-2.0

package tun

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

func hasSetuidRoot(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	fi, err := os.Stat(resolved)
	if err != nil || fi.IsDir() {
		return false
	}
	if fi.Mode()&os.ModeSetuid == 0 {
		return false
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Uid == 0
	}
	return false
}

// CheckPrivilege reports macOS utun privilege readiness without relying on unsafe setuid-root binaries.
func CheckPrivilege(singBoxBinary string) PrivilegeInfo {
	info := PrivilegeInfo{
		OS:          runtime.GOOS,
		SingBoxPath: singBoxBinary,
		IsRoot:      os.Geteuid() == 0,
	}
	if info.IsRoot {
		info.HasCapAdmin = true
		info.ReadyWithoutPassword = true
		info.Detail = "macOS kernel utun transparent proxy ready (running as root; intentionally does not register a System Settings VPN profile)"
		return info
	}
	if hasSetuidRoot(singBoxBinary) {
		// Legacy setuid-root sing-box is unsafe (world-executable root config reader/writer).
		// Require clearing the legacy setuid bit or using cached sudo password per session.
		if _, err := exec.LookPath("osascript"); err == nil {
			info.CanPkexec = true
		}
		info.Detail = "Detected legacy setuid-root sing-box; click Authorize to safely revoke setuid and use sudo cache for macOS utun"
		return info
	}
	info.Detail = "macOS kernel utun transparent proxy requires caching your administrator sudo password in Security settings or running as root"
	return info
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// AuthorizeWithPkexec on macOS no longer grants world-executable setuid-root (chmod 4755).
// If a legacy setuid-root sing-box binary is present, it revokes the setuid bit safely;
// otherwise it guides callers to use cached sudo credentials for TUN sessions.
func AuthorizeWithPkexec(ctx context.Context, singBoxBinary string) error {
	if strings.TrimSpace(singBoxBinary) == "" {
		return fmt.Errorf("sing-box binary path is empty")
	}
	resolved, err := filepath.EvalSymlinks(singBoxBinary)
	if err != nil {
		resolved = singBoxBinary
	}
	if filepath.Base(resolved) != "sing-box" {
		return fmt.Errorf("refusing privilege operation on non-sing-box binary %q", filepath.Base(resolved))
	}
	if _, err := os.Stat(resolved); err != nil {
		return fmt.Errorf("sing-box binary not found: %w", err)
	}
	if hasSetuidRoot(resolved) {
		if _, err := exec.LookPath("osascript"); err != nil {
			return fmt.Errorf("osascript not available to revoke legacy setuid-root bit")
		}
		quotedPath := shellSingleQuote(resolved)
		shellCmd := fmt.Sprintf("chmod 0755 %s", quotedPath)
		appleScript := fmt.Sprintf("do shell script %q with administrator privileges", shellCmd)
		cmd := exec.CommandContext(ctx, "osascript", "-e", appleScript)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to revoke legacy setuid bit: %s", strings.TrimSpace(string(out)))
		}
		return nil
	}
	return fmt.Errorf("为防止本地提权，macOS 已禁用对 sing-box 设置 setuid root；请在设置中缓存 sudo 密码后开启 TUN")
}

// HasMarkCapability reports false on macOS (no Linux SO_MARK).
func HasMarkCapability(_ string) bool {
	return false
}

// CleanupStaleRoutes is a no-op on macOS (utun routes are cleaned when utun fd closes).
func CleanupStaleRoutes(_ context.Context, _ []byte) error {
	return nil
}
