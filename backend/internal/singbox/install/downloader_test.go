// SPDX-License-Identifier: MPL-2.0

package install

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFindReleaseAssetUsesGitHubDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	asset, err := findReleaseAsset([]releaseAsset{{
		Name:               "sing-box-1.14.0-linux-amd64.tar.gz",
		BrowserDownloadURL: "https://example.invalid/sing-box.tar.gz",
		Digest:             "sha256:" + digest,
	}}, "sing-box-1.14.0-linux-amd64.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	if asset.Digest != digest {
		t.Fatalf("normalized digest = %q", asset.Digest)
	}
}

func TestFindReleaseAssetRejectsMissingDigest(t *testing.T) {
	_, err := findReleaseAsset([]releaseAsset{{
		Name:               "sing-box-1.14.0-linux-amd64.tar.gz",
		BrowserDownloadURL: "https://example.invalid/sing-box.tar.gz",
	}}, "sing-box-1.14.0-linux-amd64.tar.gz")
	if err == nil || !strings.Contains(err.Error(), "no SHA-256 digest") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDownloadVerifiedUsesReleaseDigest(t *testing.T) {
	body := []byte("verified sing-box archive")
	sum := sha256.Sum256(body)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()

	path, err := downloadVerified(context.Background(), server.Client(), releaseAsset{
		Name:               "sing-box-1.14.0-linux-amd64.tar.gz",
		BrowserDownloadURL: server.URL,
		Digest:             hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	downloaded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(downloaded) != string(body) {
		t.Fatal("downloaded archive content changed")
	}
}

func TestDownloadVerifiedRejectsMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("tampered"))
	}))
	defer server.Close()

	_, err := downloadVerified(context.Background(), server.Client(), releaseAsset{
		Name:               "sing-box-1.14.0-linux-amd64.tar.gz",
		BrowserDownloadURL: server.URL,
		Digest:             strings.Repeat("0", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReleaseAssetNameAndWindowsZipExtraction(t *testing.T) {
	if got := releaseAssetName("1.14.0", "windows", "amd64"); got != "sing-box-1.14.0-windows-amd64.zip" {
		t.Fatalf("unexpected windows asset name: %q", got)
	}
	if got := releaseAssetName("1.14.0", "darwin", "arm64"); got != "sing-box-1.14.0-darwin-arm64.tar.gz" {
		t.Fatalf("unexpected darwin asset name: %q", got)
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("sing-box-1.14.0-windows-amd64/sing-box.exe")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("MZ-stub-sing-box")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zipBytes := buf.Bytes()
	sum := sha256.Sum256(zipBytes)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(zipBytes)
	}))
	defer server.Close()

	archivePath, err := downloadVerified(context.Background(), server.Client(), releaseAsset{
		Name:               "sing-box-1.14.0-windows-amd64.zip",
		BrowserDownloadURL: server.URL,
		Digest:             hex.EncodeToString(sum[:]),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(archivePath)

	dest := filepath.Join(t.TempDir(), "sing-box.exe")
	if err := extractBinary(archivePath, dest, "sing-box.exe"); err != nil {
		t.Fatalf("extract windows zip failed: %v", err)
	}
	data, err := os.ReadFile(dest)
	if err != nil || string(data) != "MZ-stub-sing-box" {
		t.Fatalf("extracted binary mismatch: %q (%v)", string(data), err)
	}
}
