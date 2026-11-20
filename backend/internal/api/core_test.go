// SPDX-License-Identifier: MPL-2.0

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestCoreStatusReportsSingBoxAvailability(t *testing.T) {
	s := testServer(t, "")
	readStatus := func() bool {
		t.Helper()
		response := request(s, http.MethodGet, "/api/cores", "")
		if response.Code != http.StatusOK {
			t.Fatalf("core status returned %d: %s", response.Code, response.Body.String())
		}
		var body struct {
			SingBox struct {
				Installed bool `json:"installed"`
			} `json:"sing_box"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		return body.SingBox.Installed
	}
	if readStatus() {
		t.Fatal("missing sing-box was reported as installed")
	}
	binary := filepath.Join(t.TempDir(), "sing-box")
	if err := os.WriteFile(binary, []byte("fixture"), 0700); err != nil {
		t.Fatal(err)
	}
	s.SetSingBoxPath(binary)
	if !readStatus() {
		t.Fatal("executable sing-box was reported as missing")
	}
}

func TestAndroidModeLocksCoresToNativeLibraryDir(t *testing.T) {
	nativeDir := t.TempDir()
	nativeSB := filepath.Join(nativeDir, "libsingbox.so")
	nativeXR := filepath.Join(nativeDir, "libxray.so")
	if err := os.WriteFile(nativeSB, []byte("elf-sb"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nativeXR, []byte("elf-xr"), 0755); err != nil {
		t.Fatal(err)
	}

	staleDir := t.TempDir()
	staleSB := filepath.Join(staleDir, "sing-box")
	if err := os.WriteFile(staleSB, []byte("stale"), 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PRISMRAY_NATIVE_LIB_DIR", nativeDir)

	s := testServer(t, "")
	s.SetMode("android")
	// Even if a stale /data/user/0/... path was previously configured, Android must resolve libsingbox.so.
	s.SetSingBoxPath(staleSB)

	gotSB, err := s.ensureOrchestrator().ResolveSingBoxBinary()
	if err != nil {
		t.Fatalf("ResolveSingBoxBinary failed: %v", err)
	}
	if gotSB != nativeSB {
		t.Fatalf("expected Android native libsingbox.so %q, got %q", nativeSB, gotSB)
	}

	resp := request(s, http.MethodPost, "/api/cores", `{"core":"sing-box","version":"latest","download":true}`)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200 on Android core install lock, got %d: %s", resp.Code, resp.Body.String())
	}
	var payload struct {
		Version      string `json:"version"`
		ActiveBinary string `json:"active_binary"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Version != "bundled" || payload.ActiveBinary != nativeSB {
		t.Fatalf("unexpected Android core install response: %+v", payload)
	}
}
