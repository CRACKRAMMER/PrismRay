// SPDX-License-Identifier: MPL-2.0

package autostart

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
)

const (
	linuxDesktopFileName = "prismray.desktop"
	macPlistFileName     = "com.crackrammer.prismray.plist"
	macLaunchLabel       = "com.crackrammer.prismray"
	windowsRunKey        = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	windowsRunValue      = "PrismRay"
)

// Status describes the current desktop launch-at-login configuration.
type Status struct {
	Supported  bool   `json:"supported"`
	Enabled    bool   `json:"enabled"`
	Minimized  bool   `json:"minimized"`
	Executable string `json:"executable,omitempty"`
	EntryPath  string `json:"entry_path,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Manager reads and updates OS-native desktop launch-at-login entries.
type Manager struct {
	GOOS        string
	ConfigHome  string
	HomeDir     string
	ResolveExec func() (string, error)
	RunCmd      func(name string, args ...string) (string, error)
}

func (m *Manager) goos() string {
	if strings.TrimSpace(m.GOOS) != "" {
		return strings.TrimSpace(m.GOOS)
	}
	return runtime.GOOS
}

func (m *Manager) configHome() (string, error) {
	if strings.TrimSpace(m.ConfigHome) != "" {
		return strings.TrimSpace(m.ConfigHome), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return xdg, nil
	}
	return os.UserConfigDir()
}

func (m *Manager) homeDir() (string, error) {
	if strings.TrimSpace(m.HomeDir) != "" {
		return strings.TrimSpace(m.HomeDir), nil
	}
	return os.UserHomeDir()
}

func (m *Manager) resolveExec() (string, error) {
	if m.ResolveExec != nil {
		return m.ResolveExec()
	}
	return DefaultResolveExecutable()
}

func (m *Manager) runCmd(name string, args ...string) (string, error) {
	if m.RunCmd != nil {
		return m.RunCmd(name, args...)
	}
	out, err := exec.Command(name, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// DefaultResolveExecutable returns the persistent desktop executable path,
// preferring $APPIMAGE on Linux so ephemeral /tmp/.mount_* paths are never persisted.
func DefaultResolveExecutable() (string, error) {
	if appimage := strings.TrimSpace(os.Getenv("APPIMAGE")); appimage != "" {
		return filepath.Clean(appimage), nil
	}
	if desktopExe := strings.TrimSpace(os.Getenv("PRISMRAY_DESKTOP_EXECUTABLE")); desktopExe != "" {
		cleaned := filepath.Clean(desktopExe)
		if isEphemeralAppImageMount(cleaned) {
			return "", fmt.Errorf("检测到临时 AppImage 挂载路径 (%s)，请设置或保留 APPIMAGE 环境变量后再启用开机自启动", cleaned)
		}
		return cleaned, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("无法解析可执行文件路径: %w", err)
	}
	if resolved, symErr := filepath.EvalSymlinks(exe); symErr == nil {
		exe = resolved
	}
	exe = filepath.Clean(exe)
	if isEphemeralAppImageMount(exe) {
		return "", fmt.Errorf("检测到临时 AppImage 挂载路径 (%s)，缺少 APPIMAGE 环境变量，无法写入持久自启动路径", exe)
	}
	base := strings.ToLower(filepath.Base(exe))
	if base == "prismray-server" || base == "prismray-server.exe" {
		dir := filepath.Dir(exe)
		candidates := []string{"prismray", "PrismRay"}
		if runtime.GOOS == "windows" {
			candidates = []string{"prismray.exe", "PrismRay.exe"}
		}
		for _, c := range candidates {
			p := filepath.Join(dir, c)
			if st, statErr := os.Stat(p); statErr == nil && !st.IsDir() {
				return p, nil
			}
		}
	}
	return exe, nil
}

func isEphemeralAppImageMount(path string) bool {
	return strings.HasPrefix(filepath.ToSlash(path), "/tmp/.mount_")
}

func (m *Manager) linuxEntryPath() (string, error) {
	cfgHome, err := m.configHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgHome, "autostart", linuxDesktopFileName), nil
}

func (m *Manager) darwinEntryPath() (string, error) {
	home, err := m.homeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents", macPlistFileName), nil
}

// Status returns the current desktop autostart status.
func (m *Manager) Status() Status {
	switch m.goos() {
	case "linux":
		entryPath, err := m.linuxEntryPath()
		if err != nil {
			return Status{Supported: false, Reason: err.Error()}
		}
		execPath, execErr := m.resolveExec()
		st := Status{
			Supported:  execErr == nil,
			Executable: execPath,
			EntryPath:  entryPath,
		}
		if execErr != nil {
			st.Reason = execErr.Error()
		}
		raw, readErr := os.ReadFile(entryPath)
		if readErr == nil {
			text := string(raw)
			if isLinuxDesktopEnabled(text) {
				st.Enabled = true
				st.Minimized = hasMinimizedFlag(extractDesktopExecLine(text))
			}
		} else if !errors.Is(readErr, os.ErrNotExist) {
			st.Reason = readErr.Error()
		}
		return st

	case "darwin":
		entryPath, err := m.darwinEntryPath()
		if err != nil {
			return Status{Supported: false, Reason: err.Error()}
		}
		execPath, execErr := m.resolveExec()
		st := Status{
			Supported:  execErr == nil,
			Executable: execPath,
			EntryPath:  entryPath,
		}
		if execErr != nil {
			st.Reason = execErr.Error()
		}
		raw, readErr := os.ReadFile(entryPath)
		if readErr == nil {
			st.Enabled = true
			st.Minimized = strings.Contains(string(raw), "<string>--minimized</string>")
		} else if !errors.Is(readErr, os.ErrNotExist) {
			st.Reason = readErr.Error()
		}
		return st

	case "windows":
		execPath, execErr := m.resolveExec()
		st := Status{
			Supported:  execErr == nil,
			Executable: execPath,
			EntryPath:  windowsRunKey + `\` + windowsRunValue,
		}
		if execErr != nil {
			st.Reason = execErr.Error()
		}
		out, cmdErr := m.runCmd("reg.exe", "query", windowsRunKey, "/v", windowsRunValue)
		if cmdErr == nil && strings.Contains(out, windowsRunValue) {
			st.Enabled = true
			st.Minimized = strings.Contains(out, "--minimized")
		}
		return st

	default:
		return Status{
			Supported: false,
			Reason:    fmt.Sprintf("当前平台 (%s) 暂不支持桌面开机自启动", m.goos()),
		}
	}
}

// Set enables or disables launch at login and returns the updated Status.
func (m *Manager) Set(enabled, minimized bool) (Status, error) {
	switch m.goos() {
	case "linux":
		entryPath, err := m.linuxEntryPath()
		if err != nil {
			return Status{Supported: false, Reason: err.Error()}, err
		}
		if !enabled {
			if err := os.Remove(entryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return m.Status(), err
			}
			return m.Status(), nil
		}
		execPath, err := m.resolveExec()
		if err != nil {
			return Status{Supported: false, EntryPath: entryPath, Reason: err.Error()}, err
		}
		content := buildLinuxDesktopFile(execPath, minimized)
		if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
			return m.Status(), err
		}
		if err := fileutil.WritePrivate(entryPath, []byte(content)); err != nil {
			return m.Status(), err
		}
		return m.Status(), nil

	case "darwin":
		entryPath, err := m.darwinEntryPath()
		if err != nil {
			return Status{Supported: false, Reason: err.Error()}, err
		}
		if !enabled {
			if err := os.Remove(entryPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				return m.Status(), err
			}
			return m.Status(), nil
		}
		execPath, err := m.resolveExec()
		if err != nil {
			return Status{Supported: false, EntryPath: entryPath, Reason: err.Error()}, err
		}
		content, err := buildMacOSPlist(execPath, minimized)
		if err != nil {
			return m.Status(), err
		}
		if err := os.MkdirAll(filepath.Dir(entryPath), 0o755); err != nil {
			return m.Status(), err
		}
		if err := fileutil.WritePrivate(entryPath, []byte(content)); err != nil {
			return m.Status(), err
		}
		return m.Status(), nil

	case "windows":
		if !enabled {
			out, err := m.runCmd("reg.exe", "delete", windowsRunKey, "/v", windowsRunValue, "/f")
			if err != nil && !strings.Contains(strings.ToLower(out), "unable to find") {
				return m.Status(), fmt.Errorf("%w: %s", err, out)
			}
			return m.Status(), nil
		}
		execPath, err := m.resolveExec()
		if err != nil {
			return Status{Supported: false, EntryPath: windowsRunKey + `\` + windowsRunValue, Reason: err.Error()}, err
		}
		val := fmt.Sprintf(`"%s"`, execPath)
		if minimized {
			val += " --minimized"
		}
		out, err := m.runCmd("reg.exe", "add", windowsRunKey, "/v", windowsRunValue, "/t", "REG_SZ", "/d", val, "/f")
		if err != nil {
			return m.Status(), fmt.Errorf("%w: %s", err, out)
		}
		return m.Status(), nil

	default:
		err := fmt.Errorf("当前平台 (%s) 暂不支持桌面开机自启动", m.goos())
		return Status{Supported: false, Reason: err.Error()}, err
	}
}

func escapeDesktopExecArg(arg string) string {
	var b strings.Builder
	b.Grow(len(arg) + 4)
	b.WriteByte('"')
	for i := 0; i < len(arg); i++ {
		c := arg[i]
		switch c {
		case '"', '$', '`', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '%':
			b.WriteString("%%")
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func buildLinuxDesktopFile(execPath string, minimized bool) string {
	execLine := escapeDesktopExecArg(execPath)
	if minimized {
		execLine += " --minimized"
	}
	return strings.Join([]string{
		"[Desktop Entry]",
		"Type=Application",
		"Version=1.0",
		"Name=PrismRay",
		"Comment=PrismRay Dual-Core Proxy Client",
		"Exec=" + execLine,
		"Icon=prismray",
		"Terminal=false",
		"StartupNotify=false",
		"X-GNOME-Autostart-enabled=true",
		"",
	}, "\n")
}

func extractDesktopExecLine(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "Exec=") {
			return strings.TrimPrefix(trimmed, "Exec=")
		}
	}
	return ""
}

func hasMinimizedFlag(execLine string) bool {
	return strings.Contains(execLine, "--minimized")
}

func isLinuxDesktopEnabled(content string) bool {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.EqualFold(trimmed, "Hidden=true") ||
			strings.EqualFold(trimmed, "X-GNOME-Autostart-enabled=false") {
			return false
		}
	}
	return extractDesktopExecLine(content) != ""
}

func buildMacOSPlist(execPath string, minimized bool) (string, error) {
	var execBuf bytes.Buffer
	if err := xml.EscapeText(&execBuf, []byte(execPath)); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString(`<dict>` + "\n")
	b.WriteString(`  <key>Label</key>` + "\n")
	b.WriteString(`  <string>` + macLaunchLabel + `</string>` + "\n")
	b.WriteString(`  <key>ProgramArguments</key>` + "\n")
	b.WriteString(`  <array>` + "\n")
	b.WriteString(`    <string>` + execBuf.String() + `</string>` + "\n")
	if minimized {
		b.WriteString(`    <string>--minimized</string>` + "\n")
	}
	b.WriteString(`  </array>` + "\n")
	b.WriteString(`  <key>RunAtLoad</key>` + "\n")
	b.WriteString(`  <true/>` + "\n")
	b.WriteString(`</dict>` + "\n")
	b.WriteString(`</plist>` + "\n")
	return b.String(), nil
}
