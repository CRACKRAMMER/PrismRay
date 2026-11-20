// SPDX-License-Identifier: MPL-2.0

package install

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

const releasesAPI = "https://api.github.com/repos/SagerNet/sing-box/releases"

var (
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
	digestPattern  = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type release struct {
	TagName string         `json:"tag_name"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Digest             string `json:"digest"`
}

func releaseAssetName(version, osName, arch string) string {
	ext := "tar.gz"
	if osName == "windows" {
		ext = "zip"
	}
	return fmt.Sprintf("sing-box-%s-%s-%s.%s", version, osName, arch, ext)
}

func targetBinaryName(osName string) string {
	if osName == "windows" {
		return "sing-box.exe"
	}
	return "sing-box"
}

// Download fetches, SHA-256 verifies, and extracts the requested sing-box binary
// (returning binaryPath, resolvedVersionTag, error).
func Download(ctx context.Context, destination, requestedVersion string) (string, string, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	version := strings.TrimPrefix(requestedVersion, "v")
	latest := requestedVersion == "" || requestedVersion == "latest"
	if !latest && !versionPattern.MatchString(version) {
		return "", "", fmt.Errorf("invalid sing-box version")
	}

	endpoint := releasesAPI + "/latest"
	if !latest {
		endpoint = releasesAPI + "/tags/v" + version
	}
	metadata, err := fetchRelease(ctx, client, endpoint)
	if err != nil {
		return "", "", err
	}
	if latest {
		version = strings.TrimPrefix(metadata.TagName, "v")
	}
	if !versionPattern.MatchString(version) {
		return "", "", fmt.Errorf("invalid sing-box release version %q", metadata.TagName)
	}

	assetName := releaseAssetName(version, runtime.GOOS, runtime.GOARCH)
	asset, err := findReleaseAsset(metadata.Assets, assetName)
	if err != nil {
		return "", "", err
	}
	archivePath, err := downloadVerified(ctx, client, asset)
	if err != nil {
		return "", "", err
	}
	defer os.Remove(archivePath)
	if err = os.MkdirAll(destination, 0700); err != nil {
		return "", "", err
	}

	binaryName := targetBinaryName(runtime.GOOS)
	binary := filepath.Join(destination, binaryName)
	if err = extractBinary(archivePath, binary, binaryName); err != nil {
		return "", "", err
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(binary, 0755); err != nil {
			return "", "", err
		}
	}
	return binary, "v" + version, nil
}

func fetchRelease(ctx context.Context, client *http.Client, endpoint string) (release, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return release{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	res, err := client.Do(req)
	if err != nil {
		return release{}, fmt.Errorf("resolve sing-box release: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return release{}, fmt.Errorf("resolve sing-box release: HTTP %d", res.StatusCode)
	}
	var metadata release
	if err = json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(&metadata); err != nil {
		return release{}, fmt.Errorf("decode sing-box release metadata: %w", err)
	}
	return metadata, nil
}

func findReleaseAsset(assets []releaseAsset, name string) (releaseAsset, error) {
	for _, candidate := range assets {
		if candidate.Name != name {
			continue
		}
		if candidate.BrowserDownloadURL == "" {
			return releaseAsset{}, fmt.Errorf("sing-box release asset URL missing for %s", name)
		}
		digest := strings.TrimPrefix(strings.ToLower(candidate.Digest), "sha256:")
		if !digestPattern.MatchString(digest) {
			return releaseAsset{}, fmt.Errorf("sing-box release has no SHA-256 digest for %s", name)
		}
		candidate.Digest = digest
		return candidate, nil
	}
	return releaseAsset{}, fmt.Errorf("sing-box release asset unavailable for %s", name)
}

func downloadVerified(ctx context.Context, client *http.Client, asset releaseAsset) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, asset.BrowserDownloadURL, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sing-box download HTTP %d", res.StatusCode)
	}
	pattern := "sing-box-*.tar.gz"
	if strings.HasSuffix(strings.ToLower(asset.Name), ".zip") {
		pattern = "sing-box-*.zip"
	}
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	path := f.Name()
	hash := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, hash), io.LimitReader(res.Body, (256<<20)+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n > 256<<20 {
		os.Remove(path)
		return "", fmt.Errorf("sing-box download failed or exceeds 256 MiB")
	}
	if hex.EncodeToString(hash.Sum(nil)) != asset.Digest {
		os.Remove(path)
		return "", fmt.Errorf("sing-box SHA-256 mismatch")
	}
	return path, nil
}

func extractBinary(archivePath, destination, expectedBinary string) error {
	if expectedBinary == "" {
		expectedBinary = targetBinaryName(runtime.GOOS)
	}
	if strings.HasSuffix(strings.ToLower(archivePath), ".zip") {
		return extractZipBinary(archivePath, destination, expectedBinary)
	}
	return extractTarGzBinary(archivePath, destination, expectedBinary)
}

func extractTarGzBinary(archivePath, destination, expectedBinary string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeReg || filepath.Base(header.Name) != expectedBinary {
			continue
		}
		return writeExtractedBinary(tr, destination)
	}
	return fmt.Errorf("%s binary missing from tar archive", expectedBinary)
}

func extractZipBinary(archivePath, destination, expectedBinary string) error {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, entry := range zr.File {
		if entry.FileInfo().IsDir() || filepath.Base(entry.Name) != expectedBinary {
			continue
		}
		rc, err := entry.Open()
		if err != nil {
			return err
		}
		writeErr := writeExtractedBinary(rc, destination)
		_ = rc.Close()
		return writeErr
	}
	return fmt.Errorf("%s binary missing from zip archive", expectedBinary)
}

func writeExtractedBinary(src io.Reader, destination string) error {
	_ = os.Remove(destination)
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(src, 128<<20))
	closeErr := out.Close()
	if copyErr != nil || closeErr != nil {
		_ = os.Remove(destination)
		return fmt.Errorf("extract sing-box: %v %v", copyErr, closeErr)
	}
	return nil
}
