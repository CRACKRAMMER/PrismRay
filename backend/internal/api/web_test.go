// SPDX-License-Identifier: MPL-2.0
package api

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeadlessWebRoot(t *testing.T) {
	s := testServer(t, "")
	directory := t.TempDir()
	os.Mkdir(filepath.Join(directory, "assets"), 0700)
	os.WriteFile(filepath.Join(directory, "index.html"), []byte("<h1>PrismRay</h1>"), 0600)
	os.WriteFile(filepath.Join(directory, "assets/app.js"), []byte("window.test=true"), 0600)
	os.WriteFile(filepath.Join(directory, "settings.json"), []byte("private"), 0600)
	outside := filepath.Join(t.TempDir(), "private.js")
	os.WriteFile(outside, []byte("secret"), 0600)
	if err := os.Symlink(outside, filepath.Join(directory, "assets/leak.js")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetWebDir(directory); err != nil {
		t.Fatal(err)
	}
	defer s.Shutdown(context.Background())
	for _, path := range []string{"/", "/assets/app.js"} {
		w := request(s, "GET", path, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	for _, path := range []string{"/settings.json", "/assets/", "/assets/leak.js", "/.git/config"} {
		w := request(s, "GET", path, "")
		if w.Code == 200 || strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("exposed %s", path)
		}
	}
	r := httptest.NewRequest("POST", "/api/subscription/import", strings.NewReader(`{"content":"trojan://test@example.invalid:443"}`))
	r.Header.Set("Origin", "http://127.0.0.1:2178")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	r = httptest.NewRequest("GET", "/api/nodes", nil)
	r.Header.Set("Origin", "http://untrusted.invalid")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("unexpected origin allowed")
	}
}
