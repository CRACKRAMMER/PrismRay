// SPDX-License-Identifier: MPL-2.0

package process

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func script(t *testing.T, content string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX child fixture")
	}
	path := filepath.Join(t.TempDir(), "fake-xray")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nif [ \"$2\" = \"-test\" ]; then exit 0; fi\n"+content), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}
func waitStopped(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for m.Status() != "stopped" {
		if time.Now().After(deadline) {
			t.Fatal("child exit was not observed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func TestUnexpectedExitCanRestart(t *testing.T) {
	m := NewManager("unused")
	m.SetBinaryPath(script(t, "exit 7\n"))
	t.Cleanup(func() { m.Stop() })
	for i := 0; i < 2; i++ {
		if err := m.Start(); err != nil {
			t.Fatal(err)
		}
		waitStopped(t, m)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
}
func TestLifecycleAndLogBroadcast(t *testing.T) {
	m := NewManager("unused")
	m.SetBinaryPath(script(t, "echo ready\nexec sleep 30\n"))
	t.Cleanup(func() { m.Stop() })
	a, b := m.SubscribeLogs(), m.SubscribeLogs()
	defer m.UnsubscribeLogs(a)
	defer m.UnsubscribeLogs(b)
	if err := m.Start(); err != nil {
		t.Fatal(err)
	}
	for _, ch := range []chan string{a, b} {
		select {
		case got := <-ch:
			if got != "[INFO] ready" {
				t.Fatal(got)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("missing broadcast")
		}
	}
	if err := m.Start(); err == nil {
		t.Fatal("duplicate start accepted")
	}
	if err := m.Restart(); err != nil {
		t.Fatal(err)
	}
	if m.Status() != "running" {
		t.Fatal("restart failed")
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	if m.Status() != "stopped" {
		t.Fatal("still running")
	}
}

func TestInvalidConfigDoesNotStartChild(t *testing.T) {
	m := NewManager("invalid")
	m.SetBinaryPath(script(t, "exit 7\n"))
	// This fixture rejects validation itself rather than merely exiting at runtime.
	path := m.process.binaryPath
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 2\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(); err == nil {
		m.Stop()
		t.Fatal("invalid config accepted")
	}
	if m.Status() != "stopped" {
		t.Fatal("invalid child marked running")
	}
}
