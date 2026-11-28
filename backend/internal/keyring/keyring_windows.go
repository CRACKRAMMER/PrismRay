//go:build windows

// SPDX-License-Identifier: MPL-2.0

package keyring

import (
	"encoding/base64"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

const dpapiPrefix = "dpapi:"

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32DLL         = syscall.NewLazyDLL("crypt32.dll")
	kernel32DLL        = syscall.NewLazyDLL("kernel32.dll")
	procCryptProtect   = crypt32DLL.NewProc("CryptProtectData")
	procCryptUnprotect = crypt32DLL.NewProc("CryptUnprotectData")
	procLocalFree      = kernel32DLL.NewProc("LocalFree")
)

func protectFileKey(key []byte) (string, error) {
	if len(key) == 0 {
		return "", fmt.Errorf("empty key")
	}
	inBlob := dataBlob{cbData: uint32(len(key)), pbData: &key[0]}
	var outBlob dataBlob
	// CRYPTPROTECT_UI_FORBIDDEN = 0x1
	r1, _, err := procCryptProtect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0x1,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r1 == 0 {
		return "", fmt.Errorf("CryptProtectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	sealed := unsafe.Slice(outBlob.pbData, outBlob.cbData)
	return dpapiPrefix + base64.RawStdEncoding.EncodeToString(sealed) + "\n", nil
}

func unprotectFileKey(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if !strings.HasPrefix(trimmed, dpapiPrefix) {
		// Backward-compatible migration for legacy plaintext .device.key files.
		return decodeKeyString(trimmed)
	}
	cipherBytes, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(trimmed, dpapiPrefix))
	if err != nil || len(cipherBytes) == 0 {
		return nil, fmt.Errorf("decode DPAPI key: %w", err)
	}
	inBlob := dataBlob{cbData: uint32(len(cipherBytes)), pbData: &cipherBytes[0]}
	var outBlob dataBlob
	r1, _, err := procCryptUnprotect.Call(
		uintptr(unsafe.Pointer(&inBlob)),
		0,
		0,
		0,
		0,
		0x1,
		uintptr(unsafe.Pointer(&outBlob)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(outBlob.pbData)))
	plain := append([]byte(nil), unsafe.Slice(outBlob.pbData, outBlob.cbData)...)
	if len(plain) != keySize {
		return nil, fmt.Errorf("invalid DPAPI key size %d", len(plain))
	}
	return plain, nil
}
