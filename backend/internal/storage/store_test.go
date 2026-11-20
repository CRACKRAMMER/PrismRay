// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
)

func TestPersistenceAndIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prismray.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	node := &config.Node{ID: "a", Name: "original", UserAlias: "HK-Main", Favorite: true, EnginePref: "auto"}
	if err := s.Add(node); err != nil {
		t.Fatal(err)
	}
	node.Name = "external"
	s.Get("a").Name = "external"
	s.List()[0].Name = "external"
	if s.Get("a").Name != "original" {
		t.Fatal("shared mutable node")
	}
	listener := &config.ListenConfig{ID: "l", Name: "Mixed", Protocol: "mixed", Address: "127.0.0.1", Port: 10808, NodeIDs: []string{"a"}}
	if err := s.AddListener(listener); err != nil {
		t.Fatal(err)
	}
	listener.NodeIDs[0] = "external"
	if err := s.Delete("a"); err == nil {
		t.Fatal("deleted referenced node")
	}

	s2, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	got := s2.Get("a")
	if got == nil || got.Name != "original" || got.UserAlias != "HK-Main" || !got.Favorite {
		t.Fatalf("lost saved node: %+v", got)
	}
	if runtime.GOOS != "windows" {
		st, err := os.Stat(s.Path())
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != 0600 {
			t.Fatal(st.Mode())
		}
	}
}

func TestFailedSaveRollsBack(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "prismray.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if err := s.Add(&config.Node{ID: "a", Name: "original"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, event string
		op          func() error
	}{
		{"insert", "INSERT", func() error { return s.Add(&config.Node{ID: "b"}) }},
		{"update", "UPDATE", func() error { return s.Update(&config.Node{ID: "a", Name: "changed"}) }},
		{"delete", "DELETE", func() error { return s.Delete("a") }},
	} {
		if _, err := s.db.Exec("CREATE TRIGGER fail_" + tc.name + " BEFORE " + tc.event + " ON nodes BEGIN SELECT RAISE(ABORT,'forced'); END"); err != nil {
			t.Fatal(err)
		}
		if err := tc.op(); err == nil {
			t.Fatal("expected write failure")
		}
		if len(s.List()) != 1 || s.Get("a").Name != "original" {
			t.Fatal("failed write changed memory")
		}
		if _, err := s.db.Exec("DROP TRIGGER fail_" + tc.name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoadBalanceGroupPriorityRuleAutoFailoverAndReorder(t *testing.T) {
	if got := CanonicalGroupStrategy("load-balance"); got != "loadbalance" {
		t.Fatalf("expected CanonicalGroupStrategy(load-balance)=loadbalance, got %q", got)
	}
	if got := CanonicalGroupStrategy("hash"); got != "loadbalance" {
		t.Fatalf("expected CanonicalGroupStrategy(hash)=loadbalance, got %q", got)
	}

	// Verify idempotent migration from a legacy groups table lacking priority_rule / auto_failover.
	legacyPath := filepath.Join(t.TempDir(), "legacy.db")
	initStore, err := NewStore(legacyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initStore.db.Exec(`ALTER TABLE groups DROP COLUMN priority_rule`); err != nil {
		t.Fatal(err)
	}
	if _, err := initStore.db.Exec(`ALTER TABLE groups DROP COLUMN auto_failover`); err != nil {
		t.Fatal(err)
	}
	_ = initStore.Close()

	s, err := NewStore(legacyPath)
	if err != nil {
		t.Fatalf("NewStore on legacy schema failed: %v", err)
	}
	// Calling ensureGroupsColumns a second time must be a safe no-op.
	if err := s.ensureGroupsColumns(); err != nil {
		t.Fatalf("repeat ensureGroupsColumns failed: %v", err)
	}
	for _, nid := range []string{"n1", "n2"} {
		if err := s.Add(&config.Node{ID: nid, Name: nid}); err != nil {
			t.Fatalf("Add(%s) failed: %v", nid, err)
		}
	}

	trueVal, falseVal := true, false
	gNil := Group{ID: "g-nil", Name: "LB", Strategy: "loadbalance", NodeIDs: []string{"n1", "n2"}, PriorityRule: "", AutoFailover: nil, SortOrder: 0}
	gTrue := Group{ID: "g-true", Name: "Auto", Strategy: "urltest", NodeIDs: []string{"n1", "n2"}, PriorityRule: "speed_first", AutoFailover: &trueVal, SortOrder: 1}
	gFalse := Group{ID: "g-false", Name: "Pin", Strategy: "selector", NodeIDs: []string{"n1", "n2"}, SelectedNodeID: "n1", PriorityRule: "hybrid_score", AutoFailover: &falseVal, SortOrder: 2}
	for _, g := range []Group{gNil, gTrue, gFalse} {
		if err := s.SaveGroup(g); err != nil {
			t.Fatalf("SaveGroup(%s) failed: %v", g.ID, err)
		}
	}

	if err := s.ReorderGroups([]string{"g-false", "g-nil", "g-true"}); err != nil {
		t.Fatalf("ReorderGroups failed: %v", err)
	}
	_ = s.Close()

	s2, err := NewStore(legacyPath)
	if err != nil {
		t.Fatalf("reopen store failed: %v", err)
	}
	defer s2.Close()

	list, err := s2.ListGroups()
	if err != nil {
		t.Fatalf("ListGroups failed: %v", err)
	}
	if len(list) != 3 || list[0].ID != "g-false" || list[1].ID != "g-nil" || list[2].ID != "g-true" {
		t.Fatalf("unexpected persisted group order: %+v", list)
	}
	if list[0].AutoFailover == nil || *list[0].AutoFailover != false || list[0].PriorityRule != "hybrid_score" {
		t.Fatalf("g-false roundtrip mismatch: %+v", list[0])
	}
	if list[1].Strategy != "loadbalance" || list[1].AutoFailover != nil || list[1].PriorityRule != "" {
		t.Fatalf("g-nil roundtrip mismatch: %+v", list[1])
	}
	if list[2].AutoFailover == nil || *list[2].AutoFailover != true || list[2].PriorityRule != "speed_first" {
		t.Fatalf("g-true roundtrip mismatch: %+v", list[2])
	}
}

func TestCorruptStoreIsNotSilentlyDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prismray.db")
	for _, body := range []string{"broken sqlite file", "SQLite format 3\x00corrupt"} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewStore(path); err == nil {
			t.Fatal("corrupt store accepted")
		}
	}
}

func TestLatencyUpdatePreservesConcurrentEdit(t *testing.T) {
	s, err := NewStore(filepath.Join(t.TempDir(), "prismray.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Add(&config.Node{ID: "a", Name: "before"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Update(&config.Node{ID: "a", Name: "edited"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateLatency("a", 42); err != nil {
		t.Fatal(err)
	}
	n := s.Get("a")
	if n.Name != "edited" || n.Latency != 42 {
		t.Fatalf("lost edit: %+v", n)
	}
	path := s.Path()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateLatency("a", 99); err == nil {
		t.Fatal("expected write failure")
	}
	s, err = NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Get("a").Latency != 42 {
		t.Fatal("failed write changed latency")
	}
}

func TestV10GroupsSubscriptionsRuleSetsAndSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prismray.db")
	s, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	if err = s.Unlock(key); err != nil {
		t.Fatal(err)
	}

	if err = s.Add(&config.Node{ID: "sub1-n1", SubID: "sub1", Name: "JP-01", Protocol: config.ProtocolVLESS, Address: "jp.example.com", Port: 443, UUID: "uuid-1"}); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveGroup(Group{ID: "g", Name: "Fast", Strategy: "urltest", ToleranceMS: 80, Interval: "3m", NodeIDs: []string{"sub1-n1"}}); err != nil {
		t.Fatal(err)
	}
	if err = s.SelectGroupNode("g", "sub1-n1"); err != nil {
		t.Fatal(err)
	}
	if err = s.SaveSubscription(SubscriptionRecord{
		ID:            "sub1",
		Name:          "Airport",
		URL:           "https://secret.example.com/sub?token=abc",
		UploadBytes:   100,
		DownloadBytes: 200,
		TotalBytes:    1000,
		ImportedCount: 1,
		SkippedCount:  2,
		Warnings:      []string{"skipped 2 unknown entries"},
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret.example.com") {
		t.Fatal("subscription URL stored in plaintext")
	}

	subs, err := s.ListSubscriptions()
	if err != nil || len(subs) != 1 || subs[0].URL != "https://secret.example.com/sub?token=abc" {
		t.Fatalf("subscription mismatch: %+v %v", subs, err)
	}

	if err = s.SaveRuleSet(RuleSetRecord{ID: "rs1", Tag: "geosite-cn", Format: "binary", SourceType: "remote", URL: "https://example.com/geosite-cn.srs", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ruleSets, err := s.ListRuleSets()
	if err != nil || len(ruleSets) != 1 || ruleSets[0].Tag != "geosite-cn" {
		t.Fatalf("rule sets mismatch: %+v %v", ruleSets, err)
	}

	if err = s.SaveRoutingProfile(RoutingProfileRecord{ID: "default", Document: json.RawMessage(`{"mode":"rule","block_ads":true}`)}); err != nil {
		t.Fatal(err)
	}
	rp, found, err := s.GetRoutingProfile("default")
	if err != nil || !found || !strings.Contains(string(rp.Document), "block_ads") {
		t.Fatalf("routing profile mismatch: %+v found=%v err=%v", rp, found, err)
	}

	groups, err := s.ListGroups()
	if err != nil || len(groups) != 1 || groups[0].SelectedNodeID != "sub1-n1" || groups[0].ToleranceMS != 80 {
		t.Fatalf("groups not persisted: %#v %v", groups, err)
	}
}
