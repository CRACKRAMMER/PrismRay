//go:build linux

// SPDX-License-Identifier: MPL-2.0

package tun

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func findAdminTool(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, candidate := range []string{
		filepath.Join("/sbin", name),
		filepath.Join("/usr/sbin", name),
		filepath.Join("/usr/bin", name),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate
		}
	}
	return ""
}

// CheckPrivilege evaluates Linux CAP_NET_ADMIN, UID 0, and pkexec availability for sing-box TUN.
func CheckPrivilege(singBoxBinary string) PrivilegeInfo {
	info := PrivilegeInfo{
		OS:          "linux",
		SingBoxPath: singBoxBinary,
		IsRoot:      os.Geteuid() == 0,
		CanPkexec:   findAdminTool("pkexec") != "",
	}
	if singBoxBinary != "" {
		if resolved, err := filepath.EvalSymlinks(singBoxBinary); err == nil {
			info.SingBoxPath = resolved
		}
		if hasRequiredTUNCaps(info.SingBoxPath) {
			info.HasCapAdmin = true
		}
	}
	info.ReadyWithoutPassword = info.IsRoot || info.HasCapAdmin
	switch {
	case info.IsRoot:
		info.Detail = "running as root"
	case info.HasCapAdmin:
		info.Detail = "sing-box has CAP_NET_ADMIN and CAP_NET_RAW"
	case info.SingBoxPath == "":
		info.Detail = "sing-box binary not configured"
	default:
		info.Detail = "CAP_NET_ADMIN / CAP_NET_RAW capability missing on sing-box"
	}
	return info
}

func readFileCapsLower(binaryPath string) string {
	if binaryPath == "" {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(binaryPath); err == nil {
		binaryPath = resolved
	}
	getcapBin := findAdminTool("getcap")
	if getcapBin == "" {
		return ""
	}
	out, err := exec.Command(getcapBin, binaryPath).CombinedOutput()
	if err != nil {
		return ""
	}
	return strings.ToLower(string(out))
}

func outputHasEffectiveCap(lowerOutput, capName string) bool {
	if lowerOutput == "" || capName == "" {
		return false
	}
	for _, tok := range strings.Fields(lowerOutput) {
		for _, sep := range []string{"=ep", "+ep"} {
			if idx := strings.Index(tok, sep); idx > 0 {
				caps := strings.Split(tok[:idx], ",")
				for _, c := range caps {
					if strings.TrimSpace(c) == capName {
						return true
					}
				}
			}
		}
	}
	return false
}

func hasRequiredTUNCaps(binaryPath string) bool {
	lower := readFileCapsLower(binaryPath)
	return outputHasEffectiveCap(lower, "cap_net_admin") && outputHasEffectiveCap(lower, "cap_net_raw")
}

// HasMarkCapability reports whether binaryPath (or current UID 0) can apply Linux SO_MARK without sudo.
func HasMarkCapability(binaryPath string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	return outputHasEffectiveCap(readFileCapsLower(binaryPath), "cap_net_admin")
}

// AuthorizeWithPkexec invokes pkexec setcap to grant CAP_NET_ADMIN, CAP_NET_RAW, and CAP_NET_BIND_SERVICE
// cleanly via the desktop Polkit prompt without persisting plaintext credentials.
func AuthorizeWithPkexec(ctx context.Context, singBoxBinary string) error {
	if strings.TrimSpace(singBoxBinary) == "" {
		return fmt.Errorf("sing-box binary path is required")
	}
	abs, err := filepath.Abs(singBoxBinary)
	if err != nil {
		return err
	}
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		realPath = abs
	}
	st, err := os.Stat(realPath)
	if err != nil || st.IsDir() {
		return fmt.Errorf("sing-box binary not found at %s", realPath)
	}
	if strings.HasPrefix(filepath.ToSlash(realPath), "/tmp/.mount_") {
		return fmt.Errorf("cannot set capabilities on read-only AppImage mount %s; stage sing-box into a persistent directory first", realPath)
	}
	pkexecBin := findAdminTool("pkexec")
	if pkexecBin == "" {
		return fmt.Errorf("pkexec is not available in this environment")
	}
	setcapBin := findAdminTool("setcap")
	if setcapBin == "" {
		setcapBin = "setcap"
	}
	cmd := exec.CommandContext(ctx, pkexecBin, setcapBin, "cap_net_admin,cap_net_raw,cap_net_bind_service+ep", realPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("pkexec authorization failed: %s", msg)
	}
	return nil
}

// CleanupStaleRoutes idempotently tears down leftover prismray0 TUN interface or
// iproute2 table 2178 / rule 7000 artifacts left behind by an unclean crash.
func CleanupStaleRoutes(ctx context.Context, sudoPassword []byte) error {
	ipBin := findAdminTool("ip")
	if ipBin == "" {
		return nil
	}
	linkExists := exec.CommandContext(ctx, ipBin, "link", "show", "prismray0").Run() == nil
	ruleOut, _ := exec.CommandContext(ctx, ipBin, "rule", "show").Output()
	ruleExists := bytes.Contains(ruleOut, []byte("2178"))
	if !linkExists && !ruleExists {
		return nil
	}

	cmds := [][]string{}
	if linkExists {
		cmds = append(cmds, []string{ipBin, "link", "del", "prismray0"})
	}
	if ruleExists {
		cmds = append(cmds,
			[]string{ipBin, "rule", "del", "table", "2178"},
			[]string{ipBin, "route", "flush", "table", "2178"},
		)
	}
	for _, argv := range cmds {
		if os.Geteuid() == 0 {
			_ = exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
			continue
		}
		if len(sudoPassword) > 0 {
			cmd := exec.CommandContext(ctx, "sudo", append([]string{"-S", "-p", ""}, argv...)...)
			buf := make([]byte, len(sudoPassword)+1)
			copy(buf, sudoPassword)
			buf[len(sudoPassword)] = '\n'
			cmd.Stdin = bytes.NewReader(buf)
			_ = cmd.Run()
			for i := range buf {
				buf[i] = 0
			}
			continue
		}
		// Fallback attempt without password in case passwordless sudo exists for ip.
		_ = exec.CommandContext(ctx, argv[0], argv[1:]...).Run()
	}
	return nil
}
