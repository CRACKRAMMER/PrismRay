// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/process"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/stats"
)

func freeTestPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func resolveRealSingBox(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SINGBOX_TEST_BINARY"); p != "" {
		return p
	}
	candidate := filepath.Join("..", "..", "cores", "sing-box", "v1.14.0", "sing-box")
	if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
		abs, _ := filepath.Abs(candidate)
		return abs
	}
	t.Skip("SINGBOX_TEST_BINARY not available")
	return ""
}

func testServer(t *testing.T, singBoxBin string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := appconfig.Default()
	cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
	cfg.SingBox.BinaryPath = singBoxBin
	cfg.SingBox.MixedPort = freeTestPort(t)
	cfg.SingBox.ClashAPIPort = freeTestPort(t)
	store, err := storage.NewStore(cfg.Storage.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	s := NewServer(process.NewManager(filepath.Join(dir, "xray.json")), store, stats.NewClient("", "127.0.0.1:0"), cfg)
	if singBoxBin != "" {
		s.SetSingBoxPath(singBoxBin)
	}
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

func request(s *Server, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestConnectSwitchesNodesInOneOperation(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	nodes := []*config.Node{
		{ID: "node-a", Name: "Node A", Protocol: config.ProtocolVLESS, Address: "198.51.100.1", Port: 443, UUID: "11111111-1111-1111-1111-111111111111", Security: "tls", Sni: "a.example"},
		{ID: "node-b", Name: "Node B", Protocol: config.ProtocolTrojan, Address: "198.51.100.2", Port: 443, Password: "pass", Security: "tls", Sni: "b.example"},
	}
	for _, n := range nodes {
		if err := s.store.Add(n); err != nil {
			t.Fatal(err)
		}
	}

	for _, id := range []string{"node-a", "node-b"} {
		w := request(s, "POST", "/api/process/connect", `{"node_id":"`+id+`"}`)
		if w.Code != http.StatusOK {
			t.Fatalf("connect %s failed: %d %s", id, w.Code, w.Body.String())
		}
		stResp := request(s, "GET", "/api/process/status", "")
		var status map[string]any
		if err := json.Unmarshal(stResp.Body.Bytes(), &status); err != nil {
			t.Fatal(err)
		}
		if status["status"] != "running" || status["active_node_id"] != id {
			t.Fatalf("expected running on %s, got %v", id, status)
		}
	}

	if w := request(s, "POST", "/api/process/stop", ""); w.Code != http.StatusOK {
		t.Fatalf("stop failed: %d %s", w.Code, w.Body.String())
	}
}

func TestStartupErrorsReachClient(t *testing.T) {
	dir := t.TempDir()
	badScript := filepath.Join(dir, "bad-sing-box")
	if err := os.WriteFile(badScript, []byte("#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"sing-box version 1.14.0\"; exit 0; fi\necho \"fatal bind diagnostic\" >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	s := testServer(t, badScript)
	if err := s.store.Add(&config.Node{ID: "n1", Name: "N1", Protocol: config.ProtocolSocks, Address: "127.0.0.1", Port: 1080}); err != nil {
		t.Fatal(err)
	}
	if err := s.store.AddListener(&config.ListenConfig{ID: "l1", Name: "L1", Protocol: "mixed", Address: "127.0.0.1", Port: 18888, Enabled: true, NodeIDs: []string{"n1"}}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		path string
		body string
	}{
		{"/api/process/connect", `{"node_id":"n1"}`},
		{"/api/listeners/apply", `{}`},
	} {
		w := request(s, "POST", tc.path, tc.body)
		if w.Code < 400 {
			t.Fatalf("expected error on %s, got %d", tc.path, w.Code)
		}
		if len(w.Body.String()) == 0 {
			t.Fatalf("expected diagnostic error message on %s", tc.path)
		}
	}
}

func TestOriginPolicy(t *testing.T) {
	s := testServer(t, "")
	for _, tc := range []struct {
		origin string
		want   int
	}{
		{"http://localhost:1420", http.StatusOK},
		{"https://evil.example", http.StatusForbidden},
	} {
		r := httptest.NewRequest("GET", "/api/nodes", nil)
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("origin %s: expected %d, got %d", tc.origin, tc.want, w.Code)
		}
	}
}

func TestInvalidCandidatePreservesRunningNode(t *testing.T) {
	sbBin := resolveRealSingBox(t)
	s := testServer(t, sbBin)

	good := `{"node":{"id":"node-good","name":"Good","protocol":"vless","address":"198.51.100.1","port":443,"uuid":"11111111-1111-1111-1111-111111111111","tls":{"enabled":true,"server_name":"good.example"}}}`
	if w := request(s, "POST", "/api/process/connect", good); w.Code != http.StatusOK {
		t.Fatalf("good connect failed: %d %s", w.Code, w.Body.String())
	}

	invalid := `{"node":{"id":"node-bad","name":"Bad","protocol":"unknown-proto","address":"","port":0}}`
	if w := request(s, "POST", "/api/process/connect", invalid); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid candidate, got %d (%s)", w.Code, w.Body.String())
	}

	stResp := request(s, "GET", "/api/process/status", "")
	var status map[string]any
	_ = json.Unmarshal(stResp.Body.Bytes(), &status)
	if status["status"] != "running" || status["active_node_id"] != "node-good" {
		t.Fatalf("expected original node-good to keep running, got %v", status)
	}
}
