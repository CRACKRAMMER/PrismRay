// SPDX-License-Identifier: MPL-2.0

package fileutil

import (
	"os"
	"path/filepath"
)

// WritePrivate replaces the destination only after writing and syncing a private
// temporary file in the same directory. Existing files also receive mode 0600.
func WritePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f, err := os.CreateTemp(dir, ".prismray-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
