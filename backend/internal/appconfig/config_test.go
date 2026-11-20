// SPDX-License-Identifier: MPL-2.0

package appconfig

import (
	"path/filepath"
	"testing"
)

func TestMergeStoredKeepsBootstrapAddressAndStorage(t *testing.T) {
	bootstrap := Default()
	bootstrap.Server.Port = 2178
	bootstrap.Storage.DatabasePath = "/var/lib/prismray/prismray.db"
	bootstrap.Storage.NodesFile = bootstrap.Storage.DatabasePath

	stored := Default()
	stored.Server.Port = 8181
	stored.Storage.DatabasePath = "old.db"
	stored.Storage.NodesFile = "old.db"
	stored.SingBox.MixedPort = 2080
	stored.Xray.SocksPort = 2080

	merged := MergeStored(bootstrap, stored)
	if merged.Server.Port != 2178 || merged.Storage.DatabasePath != bootstrap.Storage.DatabasePath {
		t.Fatalf("bootstrap settings were overridden: %+v", merged)
	}
	if merged.SingBox.MixedPort != 2080 || merged.Xray.SocksPort != 2080 {
		t.Fatalf("stored runtime settings were not applied: %+v", merged)
	}
}

func TestLoadDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.SingBox.ConfigPath != "sing-box.json" || cfg.Xray.ConfigPath != "xray-sidecar.json" {
		t.Fatalf("unexpected default core config paths: %+v", cfg)
	}
	if cfg.SingBox.ClashAPIPort != 9090 || cfg.Storage.DatabasePath != "prismray.db" {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadCreatesNestedConfigDirAndPreservesRuntimeDir(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "prismray", "settings.json")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load nested config failed: %v", err)
	}
	cfg.Storage.DatabasePath = filepath.Join(filepath.Dir(path), "prismray.db")
	if cfg.RuntimeDir() != filepath.Dir(path) {
		t.Fatalf("expected RuntimeDir fallback to %q, got %q", filepath.Dir(path), cfg.RuntimeDir())
	}

	runDir := filepath.Join(root, "share", "prismray")
	cfg.SetRuntimeDir(runDir)
	if cfg.RuntimeDir() != runDir {
		t.Fatalf("expected RuntimeDir %q, got %q", runDir, cfg.RuntimeDir())
	}

	stored := Default()
	stored.SingBox.MixedPort = 2080
	merged := MergeStored(cfg, stored)
	if merged.RuntimeDir() != runDir {
		t.Fatalf("MergeStored dropped runtimeDir: got %q, want %q", merged.RuntimeDir(), runDir)
	}
}
