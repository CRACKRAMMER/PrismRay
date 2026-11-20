// SPDX-License-Identifier: MPL-2.0

package autostart

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDefaultResolveExecutablePrefersAppImageAndRejectsTmpMount(t *testing.T) {
	t.Setenv("APPIMAGE", "/home/user/My Apps/PrismRay.AppImage")
	t.Setenv("PRISMRAY_DESKTOP_EXECUTABLE", "/tmp/.mount_PrismRabc123/usr/bin/prismray")

	got, err := DefaultResolveExecutable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Clean("/home/user/My Apps/PrismRay.AppImage")
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}

	t.Setenv("APPIMAGE", "")
	t.Setenv("PRISMRAY_DESKTOP_EXECUTABLE", "/tmp/.mount_PrismRabc123/usr/bin/prismray")
	if _, err := DefaultResolveExecutable(); err == nil {
		t.Fatal("expected error when PRISMRAY_DESKTOP_EXECUTABLE points inside /tmp/.mount_ without APPIMAGE")
	}
}

func TestLinuxAutostartLifecycle(t *testing.T) {
	cfgHome := t.TempDir()
	appImagePath := `/home/alice/My Apps/PrismRay "100%".AppImage`

	mgr := &Manager{
		GOOS:       "linux",
		ConfigHome: cfgHome,
		ResolveExec: func() (string, error) {
			return appImagePath, nil
		},
	}

	initial := mgr.Status()
	if !initial.Supported || initial.Enabled || initial.Executable != appImagePath {
		t.Fatalf("unexpected initial status: %+v", initial)
	}

	enabled, err := mgr.Set(true, false)
	if err != nil {
		t.Fatalf("enable failed: %v", err)
	}
	if !enabled.Enabled || enabled.Minimized {
		t.Fatalf("expected enabled=true minimized=false, got %+v", enabled)
	}

	raw, err := os.ReadFile(enabled.EntryPath)
	if err != nil {
		t.Fatalf("read desktop entry failed: %v", err)
	}
	wantExec := `Exec="/home/alice/My Apps/PrismRay \"100%%\".AppImage"`
	if !strings.Contains(string(raw), wantExec) {
		t.Fatalf("expected escaped Exec line %q in:\n%s", wantExec, string(raw))
	}

	minEnabled, err := mgr.Set(true, true)
	if err != nil {
		t.Fatalf("enable minimized failed: %v", err)
	}
	if !minEnabled.Enabled || !minEnabled.Minimized {
		t.Fatalf("expected enabled=true minimized=true, got %+v", minEnabled)
	}

	disabled, err := mgr.Set(false, false)
	if err != nil {
		t.Fatalf("disable failed: %v", err)
	}
	if disabled.Enabled {
		t.Fatalf("expected disabled status, got %+v", disabled)
	}
	if _, statErr := os.Stat(disabled.EntryPath); !os.IsNotExist(statErr) {
		t.Fatalf("expected desktop entry removed, statErr=%v", statErr)
	}
}

func TestDarwinAutostartLifecycle(t *testing.T) {
	home := t.TempDir()
	mgr := &Manager{
		GOOS:    "darwin",
		HomeDir: home,
		ResolveExec: func() (string, error) {
			return "/Applications/PrismRay & Tools.app/Contents/MacOS/prismray", nil
		},
	}

	st, err := mgr.Set(true, true)
	if err != nil {
		t.Fatalf("macOS enable failed: %v", err)
	}
	if !st.Enabled || !st.Minimized {
		t.Fatalf("expected macOS enabled+minimized, got %+v", st)
	}
	raw, err := os.ReadFile(st.EntryPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "PrismRay &amp; Tools.app") || !strings.Contains(string(raw), "<string>--minimized</string>") {
		t.Fatalf("unexpected plist contents:\n%s", string(raw))
	}

	stOff, err := mgr.Set(false, false)
	if err != nil {
		t.Fatal(err)
	}
	if stOff.Enabled {
		t.Fatalf("expected disabled after Set(false), got %+v", stOff)
	}
}

func TestWindowsAutostartLifecycle(t *testing.T) {
	var cmds [][]string
	registryPresent := false
	registryVal := ""

	mgr := &Manager{
		GOOS: "windows",
		ResolveExec: func() (string, error) {
			return `C:\Program Files\PrismRay\prismray.exe`, nil
		},
		RunCmd: func(name string, args ...string) (string, error) {
			cmds = append(cmds, append([]string{name}, args...))
			if len(args) > 0 && args[0] == "query" {
				if !registryPresent {
					return "ERROR: The system was unable to find the specified registry key or value.", os.ErrNotExist
				}
				return "    PrismRay    REG_SZ    " + registryVal, nil
			}
			if len(args) > 0 && args[0] == "add" {
				registryPresent = true
				for i := 0; i < len(args)-1; i++ {
					if args[i] == "/d" {
						registryVal = args[i+1]
					}
				}
				return "The operation completed successfully.", nil
			}
			if len(args) > 0 && args[0] == "delete" {
				registryPresent = false
				registryVal = ""
				return "The operation completed successfully.", nil
			}
			return "", nil
		},
	}

	st, err := mgr.Set(true, true)
	if err != nil {
		t.Fatalf("windows enable failed: %v", err)
	}
	if !st.Enabled || !st.Minimized {
		t.Fatalf("expected windows enabled+minimized, got %+v", st)
	}
	wantAdd := []string{"reg.exe", "add", windowsRunKey, "/v", "PrismRay", "/t", "REG_SZ", "/d", `"C:\Program Files\PrismRay\prismray.exe" --minimized`, "/f"}
	if !reflect.DeepEqual(cmds[0], wantAdd) {
		t.Fatalf("expected reg add %v, got %v", wantAdd, cmds[0])
	}

	stOff, err := mgr.Set(false, false)
	if err != nil {
		t.Fatalf("windows disable failed: %v", err)
	}
	if stOff.Enabled {
		t.Fatalf("expected windows disabled, got %+v", stOff)
	}
}
