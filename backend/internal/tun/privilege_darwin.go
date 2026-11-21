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

// CheckPrivilege reports macOS utun privilege readiness (root or setuid-root sing-box).
func CheckPrivilege(singBoxBinary string) PrivilegeInfo {
	info := PrivilegeInfo{
		OS:          runtime.GOOS,
		SingBoxPath: singBoxBinary,
		IsRoot:      os.Geteuid() == 0,
	}
	if _, err := exec.LookPath("osascript"); err == nil {
		info.CanPkexec = true
	}
	if info.IsRoot {
		info.HasCapAdmin = true
		info.ReadyWithoutPassword = true
		info.Detail = "macOS kernel utun transparent proxy ready (running as root; intentionally does not register a System Settings VPN profile)"
		return info
	}
	if hasSetuidRoot(singBoxBinary) {
		info.HasCapAdmin = true
		info.ReadyWithoutPassword = true
		info.Detail = "macOS kernel utun transparent proxy ready via setuid-root sing-box (intentionally does not appear under System Settings → VPN)"
		return info
	}
	info.Detail = "macOS kernel utun transparent proxy requires one-time administrator authorization (setuid root) or cached sudo password"
	return info
}

func shellSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

// AuthorizeWithPkexec prompts the native macOS administrator dialog via osascript
// to grant setuid-root ownership on the sing-box binary for passwordless utun creation.
func AuthorizeWithPkexec(ctx context.Context, singBoxBinary string) error {
	if strings.TrimSpace(singBoxBinary) == "" {
		return fmt.Errorf("sing-box binary path is empty")
	}
	resolved, err := filepath.EvalSymlinks(singBoxBinary)
	if err != nil {
		resolved = singBoxBinary
	}
	if _, err := os.Stat(resolved); err != nil {
		return fmt.Errorf("sing-box binary not found: %w", err)
	}
	if _, err := exec.LookPath("osascript"); err != nil {
		return fmt.Errorf("osascript not available on macOS")
	}
	quotedPath := shellSingleQuote(resolved)
	shellCmd := fmt.Sprintf("chown root:wheel %s && chmod 4755 %s", quotedPath, quotedPath)
	appleScript := fmt.Sprintf("do shell script %q with administrator privileges", shellCmd)
	cmd := exec.CommandContext(ctx, "osascript", "-e", appleScript)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return fmt.Errorf("macOS authorization failed: %s", msg)
		}
		return fmt.Errorf("macOS authorization failed: %w", err)
	}
	return nil
}

// HasMarkCapability reports false on macOS (no Linux SO_MARK).
func HasMarkCapability(_ string) bool {
	return false
}

// CleanupStaleRoutes is a no-op on macOS (utun routes are cleaned when utun fd closes).
func CleanupStaleRoutes(_ context.Context, _ []byte) error {
	return nil
}
