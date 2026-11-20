// SPDX-License-Identifier: MPL-2.0

package install

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPreservesProjectFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"README.md", "LICENSE", "settings.json", "nodes.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(t.TempDir(), "release.zip")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for _, name := range []string{"xray", "geoip.dat", "geosite.dat", "README.md", "LICENSE", "settings.json", "nodes.json", "../xray", "nested/xray"} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := extractZip(path, dir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"README.md", "LICENSE", "settings.json", "nodes.json", "xray", "geoip.dat", "geosite.dat"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		expected := name
		if name != "xray" && name != "geoip.dat" && name != "geosite.dat" {
			expected = "original"
		}
		if string(b) != expected {
			t.Fatalf("%s was overwritten", name)
		}
	}
}
