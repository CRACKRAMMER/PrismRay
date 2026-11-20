// SPDX-License-Identifier: MPL-2.0

package orchestrator

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// IsEphemeralMountPath reports whether p resides inside an ephemeral or immutable
// application bundle mount (Linux AppImage /tmp/.mount_* or $APPDIR, or macOS
// /Volumes/* DMG and *.app/Contents/* signed bundle), where modifying permissions
// (setcap / chown+setuid) fails, breaks code signatures, or vanishes on restart.
func IsEphemeralMountPath(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(p))
	if strings.HasPrefix(clean, "/tmp/.mount_") {
		return true
	}
	if strings.HasPrefix(clean, "/Volumes/") || strings.Contains(clean, ".app/Contents/") {
		return true
	}
	if appDir := strings.TrimSpace(os.Getenv("APPDIR")); appDir != "" {
		appClean := strings.TrimRight(filepath.ToSlash(filepath.Clean(appDir)), "/")
		if appClean != "" && (clean == appClean || strings.HasPrefix(clean, appClean+"/")) {
			return true
		}
	}
	return false
}

// StageEphemeralCore copies a bundled core executable out of an ephemeral
// read-only mount (e.g. a Linux AppImage FUSE mount) into a persistent writable
// directory under <dataDir>/cores/<coreName>/bundled/<basename>.
//
// If the destination already exists with an identical SHA-256 digest, it is
// reused untouched so previously granted Linux capabilities (setcap) persist
// across restarts without re-prompting.
func StageEphemeralCore(srcPath, dataDir, coreName string) (string, error) {
	if !IsEphemeralMountPath(srcPath) {
		return srcPath, nil
	}
	return stageCoreBinary(srcPath, dataDir, coreName)
}

func stageCoreBinary(srcPath, dataDir, coreName string) (string, error) {
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" || dataDir == "." {
		if userData, err := os.UserCacheDir(); err == nil && userData != "" {
			dataDir = filepath.Join(userData, "prismray")
		} else {
			return "", fmt.Errorf("cannot stage ephemeral core %s without a persistent data directory", srcPath)
		}
	}
	if absDataDir, err := filepath.Abs(dataDir); err == nil && absDataDir != "" {
		dataDir = absDataDir
	}

	baseName := filepath.Base(srcPath)
	if baseName == "" || baseName == "." || baseName == string(filepath.Separator) {
		baseName = coreName
	}
	dstDir := filepath.Join(dataDir, "cores", coreName, "bundled")
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("create staged core dir %s: %w", dstDir, err)
	}
	dstPath := filepath.Join(dstDir, baseName)

	srcHash, err := fileSHA256Hex(srcPath)
	if err != nil {
		return "", fmt.Errorf("hash bundled core %s: %w", srcPath, err)
	}
	if dstInfo, statErr := os.Stat(dstPath); statErr == nil && !dstInfo.IsDir() {
		if dstHash, hashErr := fileSHA256Hex(dstPath); hashErr == nil && dstHash == srcHash {
			// Avoid touching mode/xattrs when already executable so Linux file capabilities stay intact.
			if dstInfo.Mode().Perm()&0o111 == 0 {
				_ = os.Chmod(dstPath, 0o755)
			}
			return dstPath, nil
		}
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", dstPath, os.Getpid())
	src, err := os.Open(srcPath)
	if err != nil {
		return "", fmt.Errorf("open bundled core %s: %w", srcPath, err)
	}
	defer src.Close()

	dst, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return "", fmt.Errorf("create staged core %s: %w", tmpPath, err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("copy bundled core %s -> %s: %w", srcPath, dstPath, err)
	}
	if err := dst.Chmod(0o755); err != nil {
		_ = dst.Close()
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("chmod staged core %s: %w", tmpPath, err)
	}
	if err := dst.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("close staged core %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, dstPath); err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("install staged core %s: %w", dstPath, err)
	}
	return dstPath, nil
}

func fileSHA256Hex(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
