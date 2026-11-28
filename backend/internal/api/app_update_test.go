// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
)

func TestCompareSemver(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"v1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.0", "1.1.0", -1},
		{"1.2.0", "1.1.9", 1},
		{"1.0.0-rc.1", "1.0.0", -1},
		{"1.0.0", "1.0.0-rc.1", 1},
		{"1.0.0-beta.2", "1.0.0-beta.10", -1},
	}
	for _, tc := range cases {
		if got := compareSemver(tc.a, tc.b); got != tc.want {
			t.Fatalf("compareSemver(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestPickRecommendedAsset(t *testing.T) {
	assets := []AppUpdateAsset{
		{Name: "prismray-linux-x64-full.AppImage", DownloadURL: "https://example.com/full.AppImage"},
		{Name: "prismray-linux-x64-lite.AppImage", DownloadURL: "https://example.com/lite.AppImage"},
		{Name: "prismray-1.1.0-1-x86_64.pkg.tar.zst", DownloadURL: "https://example.com/arch.pkg.tar.zst"},
		{Name: "prismray-windows-x64-full.exe", DownloadURL: "https://example.com/full.exe"},
		{Name: "prismray-macos-arm64-full.dmg", DownloadURL: "https://example.com/full.dmg"},
		{Name: "prismray-android-arm64.apk", DownloadURL: "https://example.com/app.apk"},
		{Name: "prismray-headless-linux-arm64.tar.gz", DownloadURL: "https://example.com/headless-arm64.tar.gz"},
	}

	if a, _ := pickRecommendedAsset(assets, "android", "arm64", authservice.ModeAndroid, false); a == nil || a.Name != "prismray-android-arm64.apk" {
		t.Fatalf("android asset mismatch: %+v", a)
	}
	if a, _ := pickRecommendedAsset(assets, "darwin", "arm64", authservice.ModeDesktop, false); a == nil || a.Name != "prismray-macos-arm64-full.dmg" {
		t.Fatalf("darwin asset mismatch: %+v", a)
	}
	if a, _ := pickRecommendedAsset(assets, "windows", "amd64", authservice.ModeDesktop, false); a == nil || a.Name != "prismray-windows-x64-full.exe" {
		t.Fatalf("windows asset mismatch: %+v", a)
	}
	if a, hint := pickRecommendedAsset(assets, "linux", "amd64", authservice.ModeDesktop, true); a == nil || a.Name != "prismray-1.1.0-1-x86_64.pkg.tar.zst" || hint != "" {
		t.Fatalf("arch asset/hint mismatch: %+v %q", a, hint)
	}
	if a, _ := pickRecommendedAsset(assets, "linux", "amd64", authservice.ModeDesktop, false); a == nil || a.Name != "prismray-linux-x64-full.AppImage" {
		t.Fatalf("linux desktop asset mismatch: %+v", a)
	}
	if a, _ := pickRecommendedAsset(assets, "linux", "arm64", authservice.ModeWeb, false); a == nil || a.Name != "prismray-headless-linux-arm64.tar.gz" {
		t.Fatalf("headless asset mismatch: %+v", a)
	}
}

func TestHandleAppUpdateCheckWithMockGitHub(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/CRACKRAMMER/PrismRay/releases/latest":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"tag_name": "v1.2.0",
				"name": "PrismRay v1.2.0",
				"body": "Added Android full TUN and QR scanner",
				"html_url": "https://github.com/CRACKRAMMER/PrismRay/releases/tag/v1.2.0",
				"published_at": "2026-11-20T05:00:00Z",
				"assets": [
					{"name": "prismray-linux-x64-full.AppImage", "browser_download_url": "https://example.com/appimage", "size": 12345}
				]
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	prevBase := githubAPIBase
	prevVer := AppVersion
	githubAPIBase = ts.URL
	AppVersion = "1.0.0"
	safeHTTPAllowLoopbackForTest.Store(true)
	defer func() {
		safeHTTPAllowLoopbackForTest.Store(false)
		githubAPIBase = prevBase
		AppVersion = prevVer
	}()

	s := NewServer(nil, nil, nil, nil)
	s.SetMode(authservice.ModeDesktop)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/app/update-check", nil)
	s.handleAppUpdateCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var got AppUpdateCheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !got.HasUpdate || got.Status != "update_available" || got.LatestVersion != "1.2.0" {
		t.Fatalf("unexpected update result: %+v", got)
	}
}

func TestHandleAppUpdateCheckNoPublishedRelease(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.NotFound(w, nil)
	}))
	defer ts.Close()

	prevBase := githubAPIBase
	githubAPIBase = ts.URL
	safeHTTPAllowLoopbackForTest.Store(true)
	defer func() {
		safeHTTPAllowLoopbackForTest.Store(false)
		githubAPIBase = prevBase
	}()

	s := NewServer(nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/app/update-check", nil)
	s.handleAppUpdateCheck(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on 404 fallback, got %d", rec.Code)
	}
	var got AppUpdateCheckResult
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got.HasUpdate || got.Status != "no_published_release" {
		t.Fatalf("expected no_published_release, got %+v", got)
	}
}
