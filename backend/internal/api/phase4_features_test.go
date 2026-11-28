// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func newTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.NewStore(filepath.Join(dir, "prismray.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	cfg := appconfig.Default()
	cfg.Storage.DatabasePath = filepath.Join(dir, "prismray.db")
	srv := NewServer(nil, store, nil, cfg)
	t.Cleanup(func() {
		if srv.connHub != nil {
			srv.connHub.Stop()
		}
	})
	return srv
}

func TestPhase4EncryptedBackupRoundTripAndLegacyCompat(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// Seed a node so backup payload is non-empty.
	node := &config.Node{
		ID:       "node-enc-1",
		Name:     "Tokyo-Test",
		Protocol: config.ProtocolVLESS,
		Address:  "203.0.113.10",
		Port:     443,
		UUID:     "11111111-1111-4111-8111-111111111111",
	}
	if err := srv.store.Add(node); err != nil {
		t.Fatalf("add node: %v", err)
	}

	// Short passphrase must be rejected.
	shortReq := httptest.NewRequest(http.MethodPost, "/api/backup/export", strings.NewReader(`{"passphrase":"short"}`))
	shortRec := httptest.NewRecorder()
	h.ServeHTTP(shortRec, shortReq)
	if shortRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short passphrase, got %d: %s", shortRec.Code, shortRec.Body.String())
	}

	// Valid passphrase produces v5 Argon2id + AES-256-GCM envelope.
	passphrase := "PrismRay-Strong-Passphrase-2026!"
	expReq := httptest.NewRequest(http.MethodPost, "/api/backup/export", strings.NewReader(`{"passphrase":"`+passphrase+`"}`))
	expRec := httptest.NewRecorder()
	h.ServeHTTP(expRec, expReq)
	if expRec.Code != http.StatusOK {
		t.Fatalf("expected 200 exporting encrypted backup, got %d: %s", expRec.Code, expRec.Body.String())
	}
	var env EncryptedBackupEnvelope
	if err := json.Unmarshal(expRec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.Format != encryptedBackupFormat || env.Version != encryptedBackupVersion || env.KDF != "argon2id" {
		t.Fatalf("unexpected envelope metadata: %+v", env)
	}
	if strings.Contains(expRec.Body.String(), "Tokyo-Test") {
		t.Fatalf("encrypted backup leaked plaintext node name")
	}

	// Remove node so we verify restore actually repopulates it.
	if err := srv.store.Delete(node.ID); err != nil {
		t.Fatalf("delete node: %v", err)
	}

	// Missing passphrase must fail with 400.
	noPassReq := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(expRec.Body.Bytes()))
	noPassRec := httptest.NewRecorder()
	h.ServeHTTP(noPassRec, noPassReq)
	if noPassRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without passphrase, got %d", noPassRec.Code)
	}

	// Wrong passphrase must fail with 400.
	wrongReq := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(expRec.Body.Bytes()))
	wrongReq.Header.Set("X-Backup-Passphrase", "wrong-passphrase-123")
	wrongRec := httptest.NewRecorder()
	h.ServeHTTP(wrongRec, wrongReq)
	if wrongRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong passphrase, got %d", wrongRec.Code)
	}

	// Wrapped payload with correct passphrase restores node cleanly.
	wrapped, _ := json.Marshal(map[string]any{
		"passphrase": passphrase,
		"envelope":   env,
	})
	okReq := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(wrapped))
	okRec := httptest.NewRecorder()
	h.ServeHTTP(okRec, okReq)
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected 200 restoring encrypted backup, got %d: %s", okRec.Code, okRec.Body.String())
	}
	if got := srv.store.Get(node.ID); got == nil || got.Name != "Tokyo-Test" {
		t.Fatalf("restored node missing or corrupted: %+v", got)
	}

	// Legacy plaintext v4 backup remains fully compatible.
	plainReq := httptest.NewRequest(http.MethodGet, "/api/backup", nil)
	plainRec := httptest.NewRecorder()
	h.ServeHTTP(plainRec, plainReq)
	if plainRec.Code != http.StatusOK {
		t.Fatalf("legacy GET /api/backup failed: %d", plainRec.Code)
	}
	impReq := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(plainRec.Body.Bytes()))
	impRec := httptest.NewRecorder()
	h.ServeHTTP(impRec, impReq)
	if impRec.Code != http.StatusOK {
		t.Fatalf("legacy plaintext v4 restore failed: %d: %s", impRec.Code, impRec.Body.String())
	}
}

func TestPhase4MultiProfilesCRUDAndSwitch(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// Default list should always contain "default".
	listReq := httptest.NewRequest(http.MethodGet, "/api/profiles", nil)
	listRec := httptest.NewRecorder()
	h.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /api/profiles failed: %d", listRec.Code)
	}
	var listResp struct {
		ActiveID string                  `json:"active_id"`
		Profiles []RoutingProfileSummary `json:"profiles"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("decode profiles: %v", err)
	}
	if listResp.ActiveID != "default" || len(listResp.Profiles) != 1 {
		t.Fatalf("unexpected initial profiles: %+v", listResp)
	}

	// Cannot delete the last remaining profile.
	delLastReq := httptest.NewRequest(http.MethodDelete, "/api/profiles/default", nil)
	delLastRec := httptest.NewRecorder()
	h.ServeHTTP(delLastRec, delLastReq)
	if delLastRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 deleting last profile, got %d", delLastRec.Code)
	}

	// Create "Travel" profile with travel template (global mode).
	createReq := httptest.NewRequest(http.MethodPost, "/api/profiles", strings.NewReader(`{"name":"Travel","template":"travel"}`))
	createRec := httptest.NewRecorder()
	h.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusOK {
		t.Fatalf("POST /api/profiles failed: %d: %s", createRec.Code, createRec.Body.String())
	}
	var createResp struct {
		CreatedID string                  `json:"created_id"`
		ActiveID  string                  `json:"active_id"`
		Profiles  []RoutingProfileSummary `json:"profiles"`
	}
	if err := json.Unmarshal(createRec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if createResp.CreatedID == "" || len(createResp.Profiles) != 2 {
		t.Fatalf("unexpected create response: %+v", createResp)
	}

	// Activate "Travel" profile and verify active routing becomes global.
	actReq := httptest.NewRequest(http.MethodPost, "/api/profiles/"+createResp.CreatedID+"/activate", nil)
	actRec := httptest.NewRecorder()
	h.ServeHTTP(actRec, actReq)
	if actRec.Code != http.StatusOK {
		t.Fatalf("POST activate failed: %d: %s", actRec.Code, actRec.Body.String())
	}
	rp, err := srv.routingProfile()
	if err != nil {
		t.Fatalf("routingProfile: %v", err)
	}
	if rp.Mode != "global" || rp.BypassCN {
		t.Fatalf("expected travel template (mode=global, bypass_cn=false), got mode=%s bypass_cn=%v", rp.Mode, rp.BypassCN)
	}

	// Rename active profile.
	putReq := httptest.NewRequest(http.MethodPut, "/api/profiles/"+createResp.CreatedID, strings.NewReader(`{"name":"Business Travel"}`))
	putRec := httptest.NewRecorder()
	h.ServeHTTP(putRec, putReq)
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT profile failed: %d: %s", putRec.Code, putRec.Body.String())
	}

	// Delete active profile falls back cleanly to "default".
	delReq := httptest.NewRequest(http.MethodDelete, "/api/profiles/"+createResp.CreatedID, nil)
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE profile failed: %d: %s", delRec.Code, delRec.Body.String())
	}
	if srv.activeRoutingProfileID() != "default" {
		t.Fatalf("expected fallback to default profile, got %s", srv.activeRoutingProfileID())
	}
}

func TestPhase4TrafficLedgerAccumulateFlushQueryClear(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()
	ledger := srv.ensureTrafficLedger()

	now := time.Now().UTC()
	ledger.RecordAt(now, 1000, 4000, 200, 800)
	// Query before flush must include in-memory deltas.
	q1, err := ledger.Query("24h", now)
	if err != nil {
		t.Fatalf("Query before flush: %v", err)
	}
	if q1.Totals.ProxyUp != 1000 || q1.Totals.ProxyDown != 4000 || q1.Totals.DirectUp != 200 || q1.Totals.DirectDown != 800 {
		t.Fatalf("unexpected pre-flush totals: %+v", q1.Totals)
	}
	if len(q1.Buckets) != 24 {
		t.Fatalf("expected 24 hourly buckets, got %d", len(q1.Buckets))
	}

	// Flush to SQLite, record another delta, verify both combine cleanly via HTTP API.
	if err := ledger.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	ledger.RecordAt(now, 500, 1000, 100, 200)
	req := httptest.NewRequest(http.MethodGet, "/api/traffic/history?range=7d", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/traffic/history failed: %d", rec.Code)
	}
	var resp TrafficHistoryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode traffic history: %v", err)
	}
	if len(resp.Buckets) != 7 || resp.Totals.ProxyUp != 1500 || resp.Totals.ProxyDown != 5000 || resp.Totals.DirectUp != 300 || resp.Totals.DirectDown != 1000 {
		t.Fatalf("unexpected 7d history totals: %+v", resp.Totals)
	}

	// Clear history via DELETE.
	delReq := httptest.NewRequest(http.MethodDelete, "/api/traffic/history", nil)
	delRec := httptest.NewRecorder()
	h.ServeHTTP(delRec, delReq)
	if delRec.Code != http.StatusOK {
		t.Fatalf("DELETE /api/traffic/history failed: %d", delRec.Code)
	}
	qAfter, _ := ledger.Query("24h", now)
	if qAfter.Totals.ProxyDown != 0 || qAfter.Totals.DirectDown != 0 {
		t.Fatalf("expected zeroed totals after clear, got %+v", qAfter.Totals)
	}
}

func TestPhase4SubscriptionRegexFilterDiffAndRefreshAll(t *testing.T) {
	prevLoopback := safeHTTPAllowLoopbackForTest.Swap(true)
	defer safeHTTPAllowLoopbackForTest.Store(prevLoopback)

	srv := newTestServer(t)
	h := srv.Handler()

	// Seed a local mock subscription server.
	version := 1
	subServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version == 1 {
			_, _ = w.Write([]byte(strings.Join([]string{
				"vless://11111111-1111-4111-8111-111111111111@203.0.113.1:443#HK-Fast-01",
				"vless://22222222-2222-4222-8222-222222222222@203.0.113.2:443#US-Info-Expire",
				"vless://33333333-3333-4333-8333-333333333333@203.0.113.3:443#JP-Fast-02",
			}, "\n")))
			return
		}
		_, _ = w.Write([]byte(strings.Join([]string{
			"vless://11111111-1111-4111-8111-111111111111@203.0.113.1:443#HK-Fast-01",
			"vless://44444444-4444-4444-8444-444444444444@203.0.113.4:443#SG-Fast-03",
		}, "\n")))
	}))
	defer subServer.Close()

	// Invalid regex must be rejected on create.
	badReq := httptest.NewRequest(http.MethodPost, "/api/subscriptions", strings.NewReader(`{"name":"Bad","url":"`+subServer.URL+`","include_regex":"[unclosed"}`))
	badRec := httptest.NewRecorder()
	h.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid regex, got %d", badRec.Code)
	}

	// Create valid subscription with include_regex + exclude_regex.
	addBody, _ := json.Marshal(map[string]any{
		"id":            "sub-regex",
		"name":          "Filtered Sub",
		"url":           subServer.URL,
		"include_regex": "Fast",
		"exclude_regex": "Expire",
	})
	addReq := httptest.NewRequest(http.MethodPost, "/api/subscriptions", bytes.NewReader(addBody))
	addRec := httptest.NewRecorder()
	h.ServeHTTP(addRec, addReq)
	if addRec.Code != http.StatusOK {
		t.Fatalf("POST /api/subscriptions failed: %d: %s", addRec.Code, addRec.Body.String())
	}

	// First refresh: imports HK-Fast-01 and JP-Fast-02, filters out US-Info-Expire.
	ref1 := httptest.NewRequest(http.MethodPost, "/api/subscriptions/sub-regex/refresh", nil)
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, ref1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first refresh failed: %d: %s", rec1.Code, rec1.Body.String())
	}
	var r1 SubscriptionRefreshResponse
	if err := json.Unmarshal(rec1.Body.Bytes(), &r1); err != nil {
		t.Fatalf("decode refresh1: %v", err)
	}
	if r1.ImportedCount != 2 || r1.Diff == nil || r1.Diff.Added != 2 || r1.Diff.FilteredOut != 1 {
		t.Fatalf("unexpected first refresh result: imported=%d diff=%+v", r1.ImportedCount, r1.Diff)
	}

	// Second refresh via /refresh-all: JP-Fast-02 removed, SG-Fast-03 added (or ID slot renamed).
	version = 2
	refAll := httptest.NewRequest(http.MethodPost, "/api/subscriptions/refresh-all", nil)
	recAll := httptest.NewRecorder()
	h.ServeHTTP(recAll, refAll)
	if recAll.Code != http.StatusOK {
		t.Fatalf("refresh-all failed: %d: %s", recAll.Code, recAll.Body.String())
	}
	var allResp struct {
		Total     int              `json:"total"`
		Succeeded int              `json:"succeeded"`
		Failed    int              `json:"failed"`
		Diff      SubscriptionDiff `json:"diff"`
	}
	if err := json.Unmarshal(recAll.Body.Bytes(), &allResp); err != nil {
		t.Fatalf("decode refresh-all: %v", err)
	}
	if allResp.Total != 1 || allResp.Succeeded != 1 || allResp.Failed != 0 {
		t.Fatalf("unexpected refresh-all summary: %+v", allResp)
	}
}

func TestPhase4CustomRuleSetDeleteAndSHA256SumsParser(t *testing.T) {
	srv := newTestServer(t)
	h := srv.Handler()

	// Built-in rule set CAN be deleted and restored cleanly.
	delBuiltin := httptest.NewRequest(http.MethodDelete, "/api/rulesets/builtin-geosite-cn", nil)
	recBuiltin := httptest.NewRecorder()
	h.ServeHTTP(recBuiltin, delBuiltin)
	if recBuiltin.Code != http.StatusOK {
		t.Fatalf("expected 200 deleting built-in ruleset, got %d: %s", recBuiltin.Code, recBuiltin.Body.String())
	}
	var afterDelBuiltin []ruleset.RuleSetSpec
	if err := json.Unmarshal(recBuiltin.Body.Bytes(), &afterDelBuiltin); err != nil {
		t.Fatalf("decode afterDelBuiltin: %v", err)
	}
	for _, spec := range afterDelBuiltin {
		if spec.ID == "builtin-geosite-cn" {
			t.Fatalf("expected builtin-geosite-cn to be removed after delete")
		}
	}
	restoreBuiltin := httptest.NewRequest(http.MethodPost, "/api/rulesets/restore-builtins", nil)
	recRestore := httptest.NewRecorder()
	h.ServeHTTP(recRestore, restoreBuiltin)
	if recRestore.Code != http.StatusOK {
		t.Fatalf("expected 200 restoring built-in rulesets, got %d: %s", recRestore.Code, recRestore.Body.String())
	}
	var afterRestore []ruleset.RuleSetSpec
	if err := json.Unmarshal(recRestore.Body.Bytes(), &afterRestore); err != nil {
		t.Fatalf("decode afterRestore: %v", err)
	}
	restoredFound := false
	for _, spec := range afterRestore {
		if spec.ID == "builtin-geosite-cn" {
			restoredFound = true
			break
		}
	}
	if !restoredFound {
		t.Fatalf("expected builtin-geosite-cn to reappear after restore-builtins")
	}

	// Merge-importing a loadbalance group must succeed, and full-restoring a nodes-only selective backup
	// must preserve the existing routing profile and groups.
	seedNode := &config.Node{
		ID:       "node-lb-1",
		Name:     "LB-Test-1",
		Protocol: config.ProtocolVLESS,
		Address:  "203.0.113.55",
		Port:     443,
		UUID:     "22222222-2222-4222-8222-222222222222",
	}
	if err := srv.store.Add(seedNode); err != nil {
		t.Fatalf("add seedNode: %v", err)
	}
	mergeLB := httptest.NewRequest(http.MethodPost, "/api/backup?mode=merge", strings.NewReader(`{
		"version": 4,
		"groups": [{
			"id": "grp-lb-merge",
			"name": "LB Merge",
			"strategy": "loadbalance",
			"load_balance_shards": 6,
			"node_ids": ["node-lb-1"]
		}]
	}`))
	recMergeLB := httptest.NewRecorder()
	h.ServeHTTP(recMergeLB, mergeLB)
	if recMergeLB.Code != http.StatusOK {
		t.Fatalf("expected 200 merge-importing loadbalance group, got %d: %s", recMergeLB.Code, recMergeLB.Body.String())
	}
	customProf := ruleset.DefaultRoutingProfile()
	customProf.Mode = "global"
	customProf.RemoteDNS = "tls://1.1.1.1:853"
	if err := srv.saveRoutingProfile(customProf); err != nil {
		t.Fatalf("saveRoutingProfile: %v", err)
	}
	selExp := httptest.NewRequest(http.MethodGet, "/api/backup?include=nodes", nil)
	recSelExp := httptest.NewRecorder()
	h.ServeHTTP(recSelExp, selExp)
	if recSelExp.Code != http.StatusOK {
		t.Fatalf("selective GET /api/backup?include=nodes failed: %d", recSelExp.Code)
	}
	selRestore := httptest.NewRequest(http.MethodPost, "/api/backup", bytes.NewReader(recSelExp.Body.Bytes()))
	recSelRestore := httptest.NewRecorder()
	h.ServeHTTP(recSelRestore, selRestore)
	if recSelRestore.Code != http.StatusOK {
		t.Fatalf("selective full restore failed: %d: %s", recSelRestore.Code, recSelRestore.Body.String())
	}
	gotProf, err := srv.routingProfile()
	if err != nil || gotProf.Mode != "global" || gotProf.RemoteDNS != "tls://1.1.1.1:853" {
		t.Fatalf("selective nodes-only restore wiped routing profile: %+v (err=%v)", gotProf, err)
	}
	if groups, gErr := srv.store.ListGroups(); gErr != nil || len(groups) != 1 || groups[0].ID != "grp-lb-merge" {
		t.Fatalf("selective nodes-only restore wiped groups: %+v (err=%v)", groups, gErr)
	}

	// Add custom rule set and delete it cleanly.
	addRS := httptest.NewRequest(http.MethodPost, "/api/rulesets", strings.NewReader(`{
		"id": "custom-test-srs",
		"tag": "custom-test-srs",
		"format": "binary",
		"source_type": "remote",
		"url": "https://example.com/custom.srs",
		"update_interval": "12h",
		"enabled": true
	}`))
	recAdd := httptest.NewRecorder()
	h.ServeHTTP(recAdd, addRS)
	if recAdd.Code != http.StatusOK {
		t.Fatalf("POST /api/rulesets failed: %d: %s", recAdd.Code, recAdd.Body.String())
	}

	delCustom := httptest.NewRequest(http.MethodDelete, "/api/rulesets/custom-test-srs", nil)
	recDel := httptest.NewRecorder()
	h.ServeHTTP(recDel, delCustom)
	if recDel.Code != http.StatusOK {
		t.Fatalf("DELETE /api/rulesets/custom-test-srs failed: %d: %s", recDel.Code, recDel.Body.String())
	}

	// Verify interval parser clamps bounds properly.
	if d := parseRuleSetUpdateInterval("15m"); d != time.Hour {
		t.Fatalf("expected 1h clamp for 15m, got %v", d)
	}
	if d := parseRuleSetUpdateInterval(""); d != 24*time.Hour {
		t.Fatalf("expected 24h default, got %v", d)
	}

	// Verify SHA256SUMS.txt parser extracts digests cleanly.
	sums := parseSHA256Sums([]byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  dist/prismray-v1.0.2-android-arm64.apk\n"))
	if sums["prismray-v1.0.2-android-arm64.apk"] != "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" {
		t.Fatalf("SHA256SUMS parse failed: %+v", sums)
	}

	// Verify DNS diagnostic endpoint validates domain and returns structured payload.
	badDNS := httptest.NewRequest(http.MethodPost, "/api/diagnostics/dns", strings.NewReader(`{"domain":"bad host/path"}`))
	badDNSRec := httptest.NewRecorder()
	h.ServeHTTP(badDNSRec, badDNS)
	if badDNSRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid DNS domain, got %d", badDNSRec.Code)
	}

	// DNS wire query encoding/decoding sanity test.
	q, err := buildDNSAQuery("example.com")
	if err != nil || len(q) < 12 {
		t.Fatalf("buildDNSAQuery failed: %v", err)
	}
	// Construct a minimal synthetic DNS response with 1 answer A=93.184.216.34.
	var resp bytes.Buffer
	resp.Write(q[:2])              // ID
	resp.Write([]byte{0x81, 0x80}) // QR=1, RD=1, RA=1, RCODE=0
	resp.Write([]byte{0x00, 0x01}) // QDCOUNT=1
	resp.Write([]byte{0x00, 0x01}) // ANCOUNT=1
	resp.Write([]byte{0x00, 0x00, 0x00, 0x00})
	resp.Write(q[12:])             // Question
	resp.Write([]byte{0xC0, 0x0C}) // Name pointer to offset 12
	resp.Write([]byte{0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04})
	resp.Write([]byte{93, 184, 216, 34})
	ips, err := parseDNSAResponse(resp.Bytes())
	if err != nil || len(ips) != 1 || ips[0] != "93.184.216.34" {
		t.Fatalf("parseDNSAResponse failed: ips=%v err=%v", ips, err)
	}
	_ = storage.TrafficBucket{}
	_ = ruleset.DefaultRoutingProfile()
}
