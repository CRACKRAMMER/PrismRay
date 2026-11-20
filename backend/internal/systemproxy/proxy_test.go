// SPDX-License-Identifier: MPL-2.0
package systemproxy

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProxyFailureRestoresSnapshot(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("GNOME adapter")
	}
	values := map[string]string{}
	failed := false
	m := Manager{Path: filepath.Join(t.TempDir(), "snapshot.json")}
	m.Run = func(a []string) (string, error) {
		key := strings.Join(a[2:4], " ")
		if a[1] == "get" {
			v := "'original'"
			if a[3] == "port" {
				v = "8080"
			}
			values[key] = v
			return v, nil
		}
		if a[4] == "'manual'" && !failed {
			failed = true
			return "", fmt.Errorf("simulated failure")
		}
		values[key] = a[4]
		return "", nil
	}
	if e := m.Enable(10809); e == nil {
		t.Fatal("missing apply error")
	}
	if _, e := os.Stat(m.Path); !os.IsNotExist(e) {
		t.Fatal("recovery did not remove snapshot")
	}
	for k, v := range values {
		if v != "'original'" && v != "8080" {
			t.Fatalf("%s was not restored: %s", k, v)
		}
	}
}

func TestKDEPlasma6EnableAndRestoreMock(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux KDE adapter")
	}
	store := map[string]string{
		"ProxyType":  "0",
		"httpProxy":  "http://127.0.0.1:8888",
		"httpsProxy": "http://127.0.0.1:8888",
		"ftpProxy":   "http://127.0.0.1:8888",
		"socksProxy": "http://127.0.0.1:8888",
		"NoProxyFor": "localhost,127.0.0.0/8,::1",
	}
	var calls []string
	m := Manager{
		Path:       filepath.Join(t.TempDir(), "kde-snapshot.json"),
		Desktop:    "KDE",
		ConfigFile: "kioslaverc",
		LookPath: func(name string) (string, error) {
			switch name {
			case "kreadconfig6", "kwriteconfig6", "dbus-send":
				return "/usr/bin/" + name, nil
			default:
				return "", fmt.Errorf("not installed: %s", name)
			}
		},
		Run: func(a []string) (string, error) {
			calls = append(calls, strings.Join(a, " "))
			switch a[0] {
			case "kreadconfig6":
				for i := 0; i < len(a)-1; i++ {
					if a[i] == "--key" {
						return store[a[i+1]], nil
					}
				}
			case "kwriteconfig6":
				for i := 0; i < len(a)-1; i++ {
					if a[i] == "--key" {
						store[a[i+1]] = a[len(a)-1]
						return "", nil
					}
				}
			case "dbus-send":
				return "", nil
			}
			return "", fmt.Errorf("unexpected cmd: %v", a)
		},
	}

	if err := m.Enable(10808); err != nil {
		t.Fatalf("KDE Enable failed: %v", err)
	}
	if store["ProxyType"] != "1" || store["httpProxy"] != "http://127.0.0.1:10808" || store["socksProxy"] != "socks://127.0.0.1:10808" {
		t.Fatalf("unexpected KDE applied state: %+v", store)
	}
	if !strings.Contains(strings.Join(calls, "\n"), "org.kde.KIO.Scheduler.reparseSlaveConfiguration") {
		t.Fatalf("expected KIO D-Bus reload signal, got calls: %v", calls)
	}

	if err := m.Restore(); err != nil {
		t.Fatalf("KDE Restore failed: %v", err)
	}
	if store["ProxyType"] != "0" || store["httpProxy"] != "http://127.0.0.1:8888" || store["socksProxy"] != "http://127.0.0.1:8888" {
		t.Fatalf("KDE proxy settings were not restored verbatim: %+v", store)
	}
	if _, err := os.Stat(m.Path); !os.IsNotExist(err) {
		t.Fatalf("expected snapshot removed after restore, stat err=%v", err)
	}
}

func TestKDERealBinaryIsolatedFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux KDE adapter")
	}
	if _, err := exec.LookPath("kwriteconfig6"); err != nil {
		t.Skip("kwriteconfig6 not installed")
	}
	if _, err := exec.LookPath("kreadconfig6"); err != nil {
		t.Skip("kreadconfig6 not installed")
	}

	tmpDir := t.TempDir()
	kioFile := filepath.Join(tmpDir, "kioslaverc")
	initial := "[Proxy Settings]\nNoProxyFor=localhost,127.0.0.0/8,::1\nProxyType=0\nhttpProxy=http://127.0.0.1:8888\nhttpsProxy=http://127.0.0.1:8888\nftpProxy=http://127.0.0.1:8888\nsocksProxy=http://127.0.0.1:8888\n"
	if err := os.WriteFile(kioFile, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	m := Manager{
		Path:       filepath.Join(tmpDir, "system-proxy.json"),
		Desktop:    "KDE",
		ConfigFile: kioFile,
		LookPath: func(name string) (string, error) {
			if name == "kreadconfig6" || name == "kwriteconfig6" {
				return exec.LookPath(name)
			}
			// Do not touch live user D-Bus or host GNOME gsettings during unit tests.
			return "", fmt.Errorf("isolated in test: %s", name)
		},
	}

	if err := m.Enable(10808); err != nil {
		t.Fatalf("real kwriteconfig6 Enable failed: %v", err)
	}
	readKey := func(k string) string {
		out, err := exec.Command("kreadconfig6", "--file", kioFile, "--group", "Proxy Settings", "--key", k).Output()
		if err != nil {
			t.Fatalf("kreadconfig6 %s failed: %v", k, err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := readKey("ProxyType"); got != "1" {
		t.Fatalf("expected ProxyType=1, got %q", got)
	}
	if got := readKey("httpProxy"); got != "http://127.0.0.1:10808" {
		t.Fatalf("expected httpProxy=http://127.0.0.1:10808, got %q", got)
	}
	if got := readKey("socksProxy"); got != "socks://127.0.0.1:10808" {
		t.Fatalf("expected socksProxy=socks://127.0.0.1:10808, got %q", got)
	}

	if err := m.Restore(); err != nil {
		t.Fatalf("real kwriteconfig6 Restore failed: %v", err)
	}
	if got := readKey("ProxyType"); got != "0" {
		t.Fatalf("expected restored ProxyType=0, got %q", got)
	}
	if got := readKey("httpProxy"); got != "http://127.0.0.1:8888" {
		t.Fatalf("expected restored httpProxy=http://127.0.0.1:8888, got %q", got)
	}
}

func TestSelfLoopSnapshotSanitizedOnEnableAndRestore(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux systemproxy test")
	}
	gsettings := map[string]string{
		"org.gnome.system.proxy mode":       "'manual'",
		"org.gnome.system.proxy.http host":  "'127.0.0.1'",
		"org.gnome.system.proxy.http port":  "10808",
		"org.gnome.system.proxy.https host": "'127.0.0.1'",
		"org.gnome.system.proxy.https port": "10808",
		"org.gnome.system.proxy.socks host": "'127.0.0.1'",
		"org.gnome.system.proxy.socks port": "10808",
	}
	kdeStore := map[string]string{
		"ProxyType":  "1",
		"httpProxy":  "http://127.0.0.1:10808",
		"httpsProxy": "http://127.0.0.1:10808",
		"ftpProxy":   "http://127.0.0.1:10808",
		"socksProxy": "socks://127.0.0.1:10808",
		"NoProxyFor": "localhost,127.0.0.0/8,::1",
	}

	m := Manager{
		Path:       filepath.Join(t.TempDir(), "system-proxy.json"),
		Desktop:    "KDE",
		ConfigFile: "kioslaverc",
		LookPath: func(name string) (string, error) {
			switch name {
			case "kreadconfig6", "kwriteconfig6", "gsettings":
				return "/usr/bin/" + name, nil
			default:
				return "", fmt.Errorf("missing: %s", name)
			}
		},
		Run: func(a []string) (string, error) {
			switch a[0] {
			case "gsettings":
				key := a[2] + " " + a[3]
				if a[1] == "get" {
					return gsettings[key], nil
				}
				if a[1] == "set" {
					gsettings[key] = a[4]
					return "", nil
				}
			case "kreadconfig6":
				for i := 0; i < len(a)-1; i++ {
					if a[i] == "--key" {
						return kdeStore[a[i+1]], nil
					}
				}
			case "kwriteconfig6":
				for i := 0; i < len(a)-1; i++ {
					if a[i] == "--key" {
						kdeStore[a[i+1]] = a[len(a)-1]
						return "", nil
					}
				}
			}
			return "", nil
		},
	}

	if err := m.Enable(10808); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore failed: %v", err)
	}
	if gsettings["org.gnome.system.proxy mode"] != "'none'" {
		t.Fatalf("expected self-looped GNOME gsettings mode to restore to 'none', got %q", gsettings["org.gnome.system.proxy mode"])
	}
	if kdeStore["ProxyType"] != "0" {
		t.Fatalf("expected self-looped KDE ProxyType to restore to \"0\", got %q", kdeStore["ProxyType"])
	}
}
