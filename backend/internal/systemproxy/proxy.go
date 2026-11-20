// SPDX-License-Identifier: MPL-2.0
package systemproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
)

type Setting struct {
	RestoreArgs []string `json:"restore_args,omitempty"`
	ApplyArgs   []string `json:"apply_args,omitempty"`
	Read        []string `json:"read"`
	Write       []string `json:"write"`
	Value       string   `json:"value"`
	Proxy       string   `json:"proxy"`
}
type Manager struct {
	Path       string
	Run        func([]string) (string, error)
	LookPath   func(string) (string, error)
	Desktop    string
	ConfigFile string
}

func (m *Manager) lookPathFn() func(string) (string, error) {
	if m.LookPath != nil {
		return m.LookPath
	}
	return exec.LookPath
}

func (m *Manager) effectiveLinuxDesktop() string {
	if strings.TrimSpace(m.Desktop) != "" {
		return strings.ToLower(strings.TrimSpace(m.Desktop))
	}
	if m.Run != nil {
		return ""
	}
	combined := strings.TrimSpace(os.Getenv("XDG_CURRENT_DESKTOP") + " " + os.Getenv("DESKTOP_SESSION"))
	if os.Getenv("KDE_FULL_SESSION") == "true" {
		combined += " kde"
	}
	return strings.ToLower(strings.TrimSpace(combined))
}

func isKDEDesktop(desktop string) bool {
	return strings.Contains(desktop, "kde") || strings.Contains(desktop, "plasma")
}

func isGNOMEDesktop(desktop string) bool {
	return desktop == "" ||
		strings.Contains(desktop, "gnome") ||
		strings.Contains(desktop, "unity") ||
		strings.Contains(desktop, "cinnamon") ||
		strings.Contains(desktop, "budgie") ||
		strings.Contains(desktop, "pantheon") ||
		strings.Contains(desktop, "mate")
}

func command(args []string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	if e != nil {
		return "", fmt.Errorf("%s failed: %w", args[0], e)
	}
	return strings.TrimSpace(string(b)), nil
}
func (m *Manager) run(a []string) (string, error) {
	if m.Run != nil {
		return m.Run(a)
	}
	return command(a)
}
func (m *Manager) Active() bool { _, e := os.Stat(m.Path); return e == nil }
func (m *Manager) Enable(port int) error {
	if m.Active() {
		return fmt.Errorf("system proxy already managed; restore it first")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port")
	}
	var settings []Setting
	switch runtime.GOOS {
	case "linux":
		desktop := m.effectiveLinuxDesktop()
		if isKDEDesktop(desktop) {
			var e error
			settings, e = m.kdeSettings(port)
			if e != nil {
				return e
			}
		} else if isGNOMEDesktop(desktop) {
			settings = gnomeProxySettings(port)
		} else {
			return fmt.Errorf("Linux 自动系统代理支持 KDE Plasma 与 GNOME 兼容桌面；当前桌面 (%s) 请手动设置代理或使用 TUN", desktop)
		}
	case "darwin":
		var e error
		settings, e = m.macSettings(port)
		if e != nil {
			return e
		}
	case "windows":
		var e error
		settings, e = m.windowsSettings(port)
		if e != nil {
			return e
		}
	default:
		return fmt.Errorf("unsupported operating system")
	}
	for i := range settings {
		if len(settings[i].Read) == 0 {
			continue
		}
		v, e := m.run(settings[i].Read)
		if e != nil {
			return e
		}
		settings[i].Value = v
	}
	sanitizeSelfLoopSnapshot(settings, port)
	b, e := json.Marshal(settings)
	if e != nil {
		return e
	}
	if e = fileutil.WritePrivate(m.Path, b); e != nil {
		return e
	}
	for _, s := range settings {
		args := s.ApplyArgs
		if len(args) == 0 {
			args = append(append([]string(nil), s.Write...), s.Proxy)
		}
		if _, e = m.run(args); e != nil {
			restoreErr := m.Restore()
			return fmt.Errorf("apply system proxy: %v; restore: %v", e, restoreErr)
		}
	}
	return nil
}
func (m *Manager) Restore() error {
	b, e := os.ReadFile(m.Path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil {
		return e
	}
	var settings []Setting
	if e = json.Unmarshal(b, &settings); e != nil {
		return e
	}
	for i := len(settings) - 1; i >= 0; i-- {
		s := settings[i]
		if len(s.Write) == 0 && len(s.RestoreArgs) == 0 {
			return fmt.Errorf("invalid proxy snapshot")
		}
		args := s.RestoreArgs
		if len(args) == 0 {
			args = append(append([]string(nil), s.Write...), s.Value)
		}
		if _, e = m.run(args); e != nil {
			return e
		}
	}
	return os.Remove(m.Path)
}

// sanitizeSelfLoopSnapshot clears stale self-pointing proxy snapshots (e.g. GNOME gsettings or
// KDE kioslaverc left at manual 127.0.0.1:<port> after an unclean shutdown) so Restore resets
// the system back to direct ('none' / 0) instead of re-applying our own dead proxy port.
func sanitizeSelfLoopSnapshot(settings []Setting, port int) {
	portStr := fmt.Sprint(port)
	selfHTTP := fmt.Sprintf("http://127.0.0.1:%d", port)

	var gnomeHost, gnomePort string
	gnomeModeIdx := -1
	var kdeHTTP string
	kdeTypeIdx := -1

	for i, s := range settings {
		if len(s.Read) >= 4 && s.Read[0] == "gsettings" && s.Read[1] == "get" {
			schema, key := s.Read[2], s.Read[3]
			val := strings.Trim(strings.TrimSpace(s.Value), "'\"")
			switch {
			case schema == "org.gnome.system.proxy" && key == "mode":
				gnomeModeIdx = i
			case schema == "org.gnome.system.proxy.http" && key == "host":
				gnomeHost = val
			case schema == "org.gnome.system.proxy.http" && key == "port":
				gnomePort = val
			}
		}
		if len(s.Read) > 0 && strings.HasPrefix(s.Read[0], "kreadconfig") {
			for j := 0; j < len(s.Read)-1; j++ {
				if s.Read[j] == "--key" {
					switch s.Read[j+1] {
					case "ProxyType":
						kdeTypeIdx = i
					case "httpProxy":
						kdeHTTP = strings.TrimSpace(s.Value)
					}
				}
			}
		}
	}

	if gnomeModeIdx >= 0 && strings.Trim(strings.TrimSpace(settings[gnomeModeIdx].Value), "'\"") == "manual" &&
		gnomeHost == "127.0.0.1" && gnomePort == portStr {
		settings[gnomeModeIdx].Value = "'none'"
	}
	if kdeTypeIdx >= 0 && strings.TrimSpace(settings[kdeTypeIdx].Value) == "1" && kdeHTTP == selfHTTP {
		settings[kdeTypeIdx].Value = "0"
	}
}
