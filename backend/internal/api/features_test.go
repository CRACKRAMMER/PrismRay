// SPDX-License-Identifier: MPL-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	authservice "github.com/CRACKRAMMER/PrismRay/backend/internal/auth"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/process"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/xray/stats"
)

func newDesktopTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := appconfig.Default()
	cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
	store, err := storage.NewStore(cfg.Storage.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	authMgr, err := authservice.NewWithOptions(store, authservice.Options{
		Mode:    authservice.ModeDesktop,
		Keyring: keyring.New(keyring.Options{Service: "test", Account: "desktop", FallbackPath: filepath.Join(dir, ".device.key"), DisableOSKeyring: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(process.NewManager(filepath.Join(dir, "xray.json")), store, stats.NewClient("", "127.0.0.1:0"), cfg)
	_ = authMgr
	s.SetMode(authservice.ModeDesktop)
	s.SetSettingsPath(filepath.Join(dir, "settings.json"))
	t.Cleanup(func() { _ = s.Shutdown(context.Background()) })
	return s
}

func TestDesktopTokenProtectsAPI(t *testing.T) {
	s := newDesktopTestServer(t)
	s.SetDesktopToken("secret")

	if w := request(s, "GET", "/api/nodes", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d", w.Code)
	}

	r := httptest.NewRequest("GET", "/api/nodes", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 with Bearer token, got %d", w.Code)
	}

	if w := request(s, "GET", "/api/nodes?token=secret", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("REST endpoint must reject query token, got %d", w.Code)
	}

	wsAllowed := httptest.NewRequest("GET", "/api/connections?token=secret", nil)
	wsRec := httptest.NewRecorder()
	s.Handler().ServeHTTP(wsRec, wsAllowed)
	if wsRec.Code == http.StatusUnauthorized {
		t.Fatalf("WS connection endpoint should accept ?token= query auth")
	}
}

func TestSubscriptionRefreshDedupeAndFailurePreservesNodes(t *testing.T) {
	s := newDesktopTestServer(t)
	safeHTTPAllowLoopbackForTest.Store(true)
	t.Cleanup(func() { safeHTTPAllowLoopbackForTest.Store(false) })
	var mode atomic.Int32
	remote := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch mode.Load() {
		case 0:
			w.Header().Set("Subscription-Userinfo", "upload=1; download=2; total=100; expire=2000000000")
			_, _ = w.Write([]byte("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&sni=a.example#Edge-A\nhysteria2://secret@5.6.7.8:443?sni=b.example#Edge-Hy2\n"))
		case 1:
			_, _ = w.Write([]byte("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&sni=a.example#Edge-A\nhysteria2://secret@5.6.7.8:443?sni=b.example#Edge-Hy2\n"))
		default:
			http.Error(w, "upstream down", http.StatusInternalServerError)
		}
	}))
	defer remote.Close()

	v := Subscription{ID: "sub-a", Name: "group", URL: remote.URL}
	if err := s.refreshSubscription(context.Background(), &v); err != nil {
		t.Fatalf("initial refresh failed: %v", err)
	}
	if v.UploadBytes != 1 || v.DownloadBytes != 2 || v.TotalBytes != 100 || v.ExpireUnix != 2000000000 {
		t.Fatalf("userinfo not parsed into SubscriptionRecord: %+v", v)
	}
	nodes := s.store.ListBySubscription("sub-a")
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	nodes[0].UserAlias = "My Custom Alias"
	nodes[0].Favorite = true
	if err := s.store.Update(nodes[0]); err != nil {
		t.Fatal(err)
	}

	mode.Store(1)
	if err := s.refreshSubscription(context.Background(), &v); err != nil {
		t.Fatalf("second refresh failed: %v", err)
	}
	nodesAfter := s.store.ListBySubscription("sub-a")
	if len(nodesAfter) != 2 || nodesAfter[0].UserAlias != "My Custom Alias" || !nodesAfter[0].Favorite {
		t.Fatalf("expected dedupe + user override preservation, got %+v", nodesAfter)
	}

	mode.Store(2)
	if err := s.refreshSubscription(context.Background(), &v); err == nil {
		t.Fatalf("expected upstream 500 failure")
	}
	if got := len(s.store.ListBySubscription("sub-a")); got != 2 {
		t.Fatalf("expected existing 2 nodes preserved on refresh failure, got %d", got)
	}
}

func TestPreferencesValidationAndPersistence(t *testing.T) {
	s := newDesktopTestServer(t)

	for _, invalid := range []string{
		`{"mode":"bogus","log_level":"warning","domain_strategy":"IPIfNonMatch"}`,
		`{"mode":"rule","log_level":"trace","domain_strategy":"IPIfNonMatch"}`,
		`{"mode":"rule","log_level":"warning","domain_strategy":"Bogus"}`,
	} {
		if w := request(s, "PUT", "/api/preferences", invalid); w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for invalid preference %s, got %d", invalid, w.Code)
		}
	}

	valid := `{"mode":"global","log_level":"info","dns_servers":["1.1.1.1"],"domain_strategy":"AsIs"}`
	if w := request(s, "PUT", "/api/preferences", valid); w.Code != http.StatusOK {
		t.Fatalf("expected 200 for valid preference, got %d (%s)", w.Code, w.Body.String())
	}
	getResp := request(s, "GET", "/api/preferences", "")
	if getResp.Code != http.StatusOK {
		t.Fatalf("expected 200 GET preferences, got %d", getResp.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(getResp.Body.Bytes(), &got)
	if got["mode"] != "global" {
		t.Fatalf("expected persisted mode=global, got %v", got)
	}
}

func TestSettingsSaveDoesNotMutateLiveConfig(t *testing.T) {
	s := newDesktopTestServer(t)
	origPort := s.cfg.SingBox.MixedPort

	nextCfg := *s.cfg
	nextCfg.SingBox.MixedPort = 20808
	b, _ := json.Marshal(nextCfg)
	w := request(s, "PUT", "/api/settings", string(b))
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 saving settings, got %d: %s", w.Code, w.Body.String())
	}
	if s.cfg.SingBox.MixedPort != origPort {
		t.Fatalf("saving settings mutated live server config port %d -> %d", origPort, s.cfg.SingBox.MixedPort)
	}
	if _, err := os.Stat(s.settingsPath); err != nil {
		t.Fatalf("expected settings saved to disk: %v", err)
	}

	nextCfg.Server.Host = "0.0.0.0"
	b, _ = json.Marshal(nextCfg)
	if w = request(s, "PUT", "/api/settings", string(b)); w.Code != http.StatusBadRequest {
		t.Fatalf("expected non-loopback host rejected with 400, got %d", w.Code)
	}
}

func TestHealthRejectsPlainHTTPBeforeLaunching(t *testing.T) {
	s := newDesktopTestServer(t)
	if _, err := s.probe(context.Background(), &config.Node{ID: "n1", Protocol: config.ProtocolVLESS}, "http://example.com"); err == nil {
		t.Fatalf("expected http:// probe URL to be rejected")
	}
	w := request(s, http.MethodPost, "/api/nodes/probe", `{"url":"http://example.com"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for plain http probe, got %d", w.Code)
	}
}

func TestStructuredImportAndRefresh(t *testing.T) {
	s := newDesktopTestServer(t)
	yamlContent := "proxies:\n  - name: sg-hy2\n    type: hysteria2\n    server: 1.2.3.4\n    port: 443\n    password: pass\n    sni: a.example\n    skip-cert-verify: true\n  - name: bad-unknown\n    type: bogusproto\n    server: 1.1.1.1\n    port: 443\n"
	payload, _ := json.Marshal(map[string]string{"content": yamlContent})
	w := request(s, "POST", "/api/subscription/import", string(payload))
	if w.Code != http.StatusOK {
		t.Fatalf("expected resilient import 200, got %d (%s)", w.Code, w.Body.String())
	}
	var body struct {
		Imported int            `json:"imported"`
		Skipped  []any          `json:"skipped"`
		Warnings []string       `json:"warnings"`
		Nodes    []*config.Node `json:"nodes"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Imported != 1 || len(body.Skipped) != 1 || len(body.Warnings) == 0 {
		t.Fatalf("unexpected resilient import report: %+v", body)
	}

	// Unknown-only subscription still returns 400 error
	unknownPayload, _ := json.Marshal(map[string]string{"content": "unknownproto://abc@1.2.3.4:443#bad"})
	if w := request(s, "POST", "/api/subscription/import", string(unknownPayload)); w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 when 0 nodes valid, got %d", w.Code)
	}
}
