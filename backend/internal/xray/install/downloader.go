// SPDX-License-Identifier: MPL-2.0

package install

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

const (
	releaseBaseURL = "https://github.com/XTLS/Xray-core/releases/latest/download"
)

// assetName returns the correct Xray release asset name for the current OS/arch.
func assetName() string {
	os_ := runtime.GOOS
	arch := runtime.GOARCH

	switch {
	case os_ == "linux" && arch == "amd64":
		return "Xray-linux-64.zip"
	case os_ == "linux" && arch == "arm64":
		return "Xray-linux-arm64-v8a.zip"
	case os_ == "darwin" && arch == "amd64":
		return "Xray-macos-64.zip"
	case os_ == "darwin" && arch == "arm64":
		return "Xray-macos-arm64-v8a.zip"
	case os_ == "windows" && arch == "amd64":
		return "Xray-windows-64.zip"
	case os_ == "windows" && arch == "arm64":
		return "Xray-windows-arm64-v8a.zip"
	default:
		return fmt.Sprintf("Xray-%s-%s.zip", os_, arch)
	}
}

// DownloadXray downloads and extracts the latest Xray-core binary into destDir.
// Returns the absolute path to the xray binary.
func DownloadXray(destDir string) (string, error) {
	return DownloadXrayVersion(destDir, "latest")
}
func DownloadXrayVersion(destDir, version string) (string, error) {
	return DownloadXrayVersionWithClient(nil, destDir, version)
}

// DownloadXrayVersionWithClient downloads and verifies the requested Xray-core binary using client.
func DownloadXrayVersionWithClient(client *http.Client, destDir, version string) (string, error) {
	base := releaseBaseURL
	if version != "latest" {
		if !regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`).MatchString(version) {
			return "", fmt.Errorf("invalid release version")
		}
		base = "https://github.com/XTLS/Xray-core/releases/download/" + version
	}
	asset := assetName()
	url := base + "/" + asset

	// Create temp file for the zip
	tmpFile, err := os.CreateTemp("", "xray-*.zip")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Download
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to download xray from %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed with status %d", resp.StatusCode)
	}

	hash := sha256.New()
	size, copyErr := io.Copy(io.MultiWriter(tmpFile, hash), io.LimitReader(resp.Body, (256<<20)+1))
	if copyErr != nil || size > 256<<20 {
		return "", fmt.Errorf("download failed or exceeds 256 MiB")
	}
	digestResponse, digestErr := client.Get(url + ".dgst")
	if digestErr != nil {
		return "", fmt.Errorf("checksum unavailable: %w", digestErr)
	}
	defer digestResponse.Body.Close()
	if digestResponse.StatusCode != 200 {
		return "", fmt.Errorf("checksum HTTP %d", digestResponse.StatusCode)
	}
	digest, digestErr := io.ReadAll(io.LimitReader(digestResponse.Body, 16384))
	if digestErr != nil {
		return "", digestErr
	}
	expected := ""
	for _, line := range strings.Split(string(digest), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "sha256") || strings.Contains(lower, "sha2-256") {
			matches := regexp.MustCompile(`[a-fA-F0-9]{64}`).FindAllString(line, -1)
			if len(matches) > 0 {
				expected = strings.ToLower(matches[len(matches)-1])
			}
		}
	}
	if expected == "" || expected != hex.EncodeToString(hash.Sum(nil)) {
		return "", fmt.Errorf("SHA-256 checksum mismatch or missing")
	}
	if err := tmpFile.Sync(); err != nil {
		return "", fmt.Errorf("failed to save download: %w", err)
	}
	tmpFile.Close()

	// Ensure dest dir exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create dest dir: %w", err)
	}

	// Extract zip
	if err := extractZip(tmpFile.Name(), destDir); err != nil {
		return "", fmt.Errorf("failed to extract zip: %w", err)
	}

	// Determine binary name
	binaryName := "xray"
	if runtime.GOOS == "windows" {
		binaryName = "xray.exe"
	}
	binPath := filepath.Join(destDir, binaryName)

	// Make binary executable (unix)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(binPath, 0755); err != nil {
			return "", fmt.Errorf("failed to chmod: %w", err)
		}
	}

	return filepath.Abs(binPath)
}

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Security: prevent path traversal
		name := filepath.Base(f.Name)
		// Release archives also contain README/LICENSE files. Never overwrite the
		// application's source, configuration or licensing files during installation.
		if strings.ContainsAny(f.Name, "/\\") || strings.Contains(f.Name, "..") {
			continue
		}
		if name != "xray" && name != "xray.exe" && name != "geoip.dat" && name != "geosite.dat" {
			continue
		}

		fpath := filepath.Join(destDir, name)
		if f.FileInfo().IsDir() {
			continue
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
