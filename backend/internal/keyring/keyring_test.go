// SPDX-License-Identifier: MPL-2.0

package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFallbackKeySlotLifecycle(t *testing.T) {
	slot := filepath.Join(t.TempDir(), "nested", ".device.key")
	store := New(Options{
		Service:          "io.prismray.test",
		Account:          "default",
		FallbackPath:     slot,
		DisableOSKeyring: true,
	})

	if _, found, err := store.Load(); err != nil || found {
		t.Fatalf("expected missing key before creation, found=%v err=%v", found, err)
	}

	first, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate failed: %v", err)
	}
	if len(first) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(first))
	}

	second, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("second LoadOrCreate failed: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("LoadOrCreate returned different key on reload")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(slot)
		if err != nil {
			t.Fatalf("stat fallback key file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("expected 0600 permissions, got %v", info.Mode().Perm())
		}
	}

	if err := store.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, found, err := store.Load(); err != nil || found {
		t.Fatalf("expected key deleted, found=%v err=%v", found, err)
	}
}

func TestSaveRejectsInvalidKeyLength(t *testing.T) {
	slot := filepath.Join(t.TempDir(), ".device.key")
	store := New(Options{FallbackPath: slot, DisableOSKeyring: true})
	if err := store.Save([]byte("too-short")); err == nil {
		t.Fatal("expected error when saving non-32-byte key")
	}
}
