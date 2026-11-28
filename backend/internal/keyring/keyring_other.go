//go:build !windows

// SPDX-License-Identifier: MPL-2.0

package keyring

import "encoding/base64"

func protectFileKey(key []byte) (string, error) {
	return base64.RawStdEncoding.EncodeToString(key) + "\n", nil
}

func unprotectFileKey(raw string) ([]byte, error) {
	return decodeKeyString(raw)
}
