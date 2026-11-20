// SPDX-License-Identifier: MPL-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
)

func TestResolveDesktopKeyringAccount(t *testing.T) {
	cfgRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgRoot)
	t.Setenv("HOME", cfgRoot)

	userCfgDir, err := os.UserConfigDir()
	if err != nil {
		t.Fatal(err)
	}
	defaultDB := filepath.Join(userCfgDir, "prismray", "prismray.db")
	if got := resolveDesktopKeyringAccount(authservice.ModeDesktop, defaultDB); got != "desktop" {
		t.Fatalf("expected standard desktop account 'desktop', got %q", got)
	}

	tmpDB1 := filepath.Join(t.TempDir(), "prismray.db")
	tmpDB2 := filepath.Join(t.TempDir(), "prismray.db")
	acc1 := resolveDesktopKeyringAccount(authservice.ModeDesktop, tmpDB1)
	acc2 := resolveDesktopKeyringAccount(authservice.ModeDesktop, tmpDB2)
	if !strings.HasPrefix(acc1, "desktop-") || len(acc1) != 24 {
		t.Fatalf("unexpected hashed account format: %q", acc1)
	}
	if acc1 == acc2 {
		t.Fatalf("distinct db paths should not collide on keyring account: %q == %q", acc1, acc2)
	}
	if resolveDesktopKeyringAccount(authservice.ModeDesktop, tmpDB1) != acc1 {
		t.Fatal("account hashing must be deterministic")
	}
	if got := resolveDesktopKeyringAccount(authservice.ModeAndroid, tmpDB1); got != authservice.ModeAndroid {
		t.Fatalf("expected android mode account unchanged, got %q", got)
	}
}
