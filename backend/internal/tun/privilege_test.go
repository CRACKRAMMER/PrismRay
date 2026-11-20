// SPDX-License-Identifier: MPL-2.0

package tun

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCheckPrivilegeAndCleanupIdempotent(t *testing.T) {
	infoEmpty := CheckPrivilege("")
	if infoEmpty.OS != runtime.GOOS {
		t.Fatalf("unexpected OS %q", infoEmpty.OS)
	}
	if runtime.GOOS == "linux" && os.Geteuid() != 0 && infoEmpty.ReadyWithoutPassword {
		t.Fatal("empty unprivileged Linux binary should not report ReadyWithoutPassword")
	}

	fakeBin := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	infoFake := CheckPrivilege(fakeBin)
	if infoFake.SingBoxPath == "" {
		t.Fatal("expected resolved SingBoxPath")
	}

	if err := CleanupStaleRoutes(context.Background(), nil); err != nil {
		t.Fatalf("idempotent CleanupStaleRoutes returned error: %v", err)
	}

	if runtime.GOOS == "linux" {
		if err := AuthorizeWithPkexec(context.Background(), ""); err == nil {
			t.Fatal("expected error for empty sing-box binary path")
		}
		if err := AuthorizeWithPkexec(context.Background(), filepath.Join(t.TempDir(), "missing")); err == nil {
			t.Fatal("expected error for missing sing-box binary path")
		}
		if outputHasEffectiveCap("/usr/bin/sing-box cap_net_bind_service,cap_net_admin=ep", "cap_net_raw") {
			t.Fatal("expected cap_net_raw to report false when absent")
		}
		if !outputHasEffectiveCap("/usr/bin/sing-box cap_net_bind_service,cap_net_admin,cap_net_raw=ep", "cap_net_raw") {
			t.Fatal("expected cap_net_raw to report true when present in =ep set")
		}
	}
}
