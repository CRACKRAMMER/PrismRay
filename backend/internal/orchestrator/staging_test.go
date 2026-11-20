// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsEphemeralMountPath(t *testing.T) {
	if !IsEphemeralMountPath("/tmp/.mount_prismrJpiibM/usr/bin/sing-box") {
		t.Fatal("expected /tmp/.mount_* path to be detected as ephemeral")
	}
	if !IsEphemeralMountPath("/Applications/PrismRay.app/Contents/MacOS/sing-box") {
		t.Fatal("expected macOS .app bundle path to require persistent staging")
	}
	if !IsEphemeralMountPath("/Volumes/PrismRay/PrismRay.app/Contents/MacOS/sing-box") {
		t.Fatal("expected macOS DMG /Volumes path to require persistent staging")
	}
	if IsEphemeralMountPath("/usr/bin/sing-box") {
		t.Fatal("expected /usr/bin/sing-box not to be ephemeral")
	}
	appDir := t.TempDir()
	t.Setenv("APPDIR", appDir)
	if !IsEphemeralMountPath(filepath.Join(appDir, "usr", "bin", "sing-box")) {
		t.Fatal("expected path under APPDIR to be detected as ephemeral")
	}
}

func TestStageEphemeralCorePreservesInodeWhenUnchangedAndUpdatesWhenChanged(t *testing.T) {
	appDir := t.TempDir()
	t.Setenv("APPDIR", appDir)

	src := filepath.Join(appDir, "usr", "bin", "sing-box")
	if err := os.MkdirAll(filepath.Dir(src), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	if err := os.WriteFile(src, []byte("sing-box-v1"), 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	dataDir := t.TempDir()
	staged1, err := StageEphemeralCore(src, dataDir, "sing-box")
	if err != nil {
		t.Fatalf("first StageEphemeralCore failed: %v", err)
	}
	wantDst := filepath.Join(dataDir, "cores", "sing-box", "bundled", "sing-box")
	if staged1 != wantDst {
		t.Fatalf("expected staged path %q, got %q", wantDst, staged1)
	}
	info1, err := os.Stat(staged1)
	if err != nil {
		t.Fatalf("stat staged1: %v", err)
	}
	if info1.Mode().Perm()&0o111 == 0 {
		t.Fatalf("expected staged binary to be executable, got mode %v", info1.Mode())
	}

	// Re-staging identical binary must keep the exact same file untouched (preserving setcap xattrs).
	staged2, err := StageEphemeralCore(src, dataDir, "sing-box")
	if err != nil {
		t.Fatalf("second StageEphemeralCore failed: %v", err)
	}
	info2, err := os.Stat(staged2)
	if err != nil {
		t.Fatalf("stat staged2: %v", err)
	}
	if !os.SameFile(info1, info2) {
		t.Fatal("expected identical binary re-stage to preserve existing file inode and capabilities")
	}

	// Updating bundled binary replaces staged file atomically.
	if err := os.WriteFile(src, []byte("sing-box-v2-updated"), 0o755); err != nil {
		t.Fatalf("update src: %v", err)
	}
	staged3, err := StageEphemeralCore(src, dataDir, "sing-box")
	if err != nil {
		t.Fatalf("third StageEphemeralCore failed: %v", err)
	}
	gotBytes, err := os.ReadFile(staged3)
	if err != nil {
		t.Fatalf("read staged3: %v", err)
	}
	if string(gotBytes) != "sing-box-v2-updated" {
		t.Fatalf("expected updated staged contents, got %q", string(gotBytes))
	}
}
