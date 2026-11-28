// SPDX-License-Identifier: MPL-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCoreControlServerAuthAndSanitize(t *testing.T) {
	if isLoopbackListenAddr("0.0.0.0:12345") {
		t.Fatalf("expected non-loopback address rejected")
	}
	if !isLoopbackListenAddr("127.0.0.1:0") {
		t.Fatalf("expected 127.0.0.1:0 accepted")
	}

	for _, bad := range []string{"", ".", "..", "../secret", "a/b", `a\b`} {
		if _, err := sanitizeTaildropFileName(bad); err == nil {
			t.Fatalf("expected %q rejected by sanitizeTaildropFileName", bad)
		}
	}
	if clean, err := sanitizeTaildropFileName("report.pdf"); err != nil || clean != "report.pdf" {
		t.Fatalf("unexpected clean filename: %q err=%v", clean, err)
	}
	if clean, err := sanitizeTaildropFileName("100%_report.pdf"); err != nil || clean != "100%_report.pdf" {
		t.Fatalf("unexpected percent filename: %q err=%v", clean, err)
	}

	cs := &coreControlServer{
		token:     "ctrl-secret-token",
		lastInbox: taildropInboxSnapshot{Files: []taildropFileSnapshot{}},
	}
	cs.UpdateStatus(tailscaleStatusSnapshot{
		PID:          123,
		BackendState: "Running",
		Online:       true,
		SelfHostname: "test-host",
	})
	h := cs.handler()

	// Missing token -> 401
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tailscale/status", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", rec.Code)
	}

	// Valid token -> 200 with ControlAvailable=true
	req := httptest.NewRequest(http.MethodGet, "/tailscale/status", nil)
	req.Header.Set("Authorization", "Bearer ctrl-secret-token")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid token, got %d", rec.Code)
	}
	var snap tailscaleStatusSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snap); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if !snap.ControlAvailable || snap.SelfHostname != "test-host" || !snap.Online {
		t.Fatalf("unexpected status snapshot: %+v", snap)
	}
}
