// SPDX-License-Identifier: MPL-2.0

package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	_ "modernc.org/sqlite"
)

const (
	defaultPath   = "prismray.db"
	schemaVersion = 100
)

// Store is the application's v1.0.0 SQLite-backed encrypted configuration store.
type Store struct {
	mu     sync.RWMutex
	db     *sql.DB
	dbPath string
	key    []byte
}

type sealedDocument struct {
	Encrypted bool   `json:"encrypted"`
	Nonce     string `json:"nonce"`
	Data      string `json:"data"`
}

// Group defines a proxy selection, latency test, failover, or domain-hash loadbalance group.
type Group struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Strategy       string   `json:"strategy"` // selector | urltest | failover | loadbalance
	SelectedNodeID string   `json:"selected_node_id,omitempty"`
	Filter         string   `json:"filter,omitempty"`
	ToleranceMS    int      `json:"tolerance_ms,omitempty"`
	Interval       string   `json:"interval,omitempty"`
	PriorityRule   string   `json:"priority_rule,omitempty"` // "" (inherit global) | latency_first | speed_first | hybrid_score
	AutoFailover   *bool    `json:"auto_failover,omitempty"`
	DetourID       string   `json:"detour_id,omitempty"`
	SortOrder      int      `json:"sort_order"`
	NodeIDs        []string `json:"node_ids"`
}

// SubscriptionRecord stores encrypted subscription source URLs, quota telemetry,
// and the structured import/skip diagnostic report.
type SubscriptionRecord struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	URL             string   `json:"url"`
	UploadBytes     int64    `json:"upload_bytes"`
	DownloadBytes   int64    `json:"download_bytes"`
	TotalBytes      int64    `json:"total_bytes"`
	ExpireUnix      int64    `json:"expire_unix"`
	AutoUpdateHours int      `json:"auto_update_hours"`
	ImportedCount   int      `json:"imported_count"`
	SkippedCount    int      `json:"skipped_count"`
	Warnings        []string `json:"warnings"`
	LastUpdatedAt   string   `json:"last_updated_at"`
}

// RuleSetRecord stores metadata for local/remote .srs rule sets.
type RuleSetRecord struct {
	ID             string `json:"id"`
	Tag            string `json:"tag"`
	Format         string `json:"format"`      // binary | source
	SourceType     string `json:"source_type"` // remote | local | inline
	URL            string `json:"url,omitempty"`
	LocalPath      string `json:"local_path,omitempty"`
	UpdateInterval string `json:"update_interval,omitempty"`
	Enabled        bool   `json:"enabled"`
	LastSyncedAt   string `json:"last_synced_at,omitempty"`
	SizeBytes      int64  `json:"size_bytes,omitempty"`
}

// RoutingProfileRecord stores named routing profiles and JSON policy documents.
type RoutingProfileRecord struct {
	ID        string          `json:"id"`
	Document  json.RawMessage `json:"document"`
	UpdatedAt string          `json:"updated_at,omitempty"`
}

// NewStore opens or creates the v1.0.0 SQLite database at path.
func NewStore(path string) (*Store, error) {
	if path == "" {
		path = defaultPath
	}
	dbPath := path
	if strings.ToLower(filepath.Ext(path)) != ".db" {
		dbPath = filepath.Join(filepath.Dir(path), defaultPath)
	}
	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, dbPath: dbPath}
	if err = s.initialize(); err != nil {
		db.Close()
		return nil, err
	}
	if err = os.Chmod(dbPath, 0600); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) initialize() error {
	_, err := s.db.Exec(fmt.Sprintf(`
		PRAGMA foreign_keys=ON;
		PRAGMA journal_mode=WAL;
		PRAGMA secure_delete=ON;
		PRAGMA busy_timeout=5000;
		CREATE TABLE IF NOT EXISTS schema_migrations(
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		INSERT OR IGNORE INTO schema_migrations(version) VALUES(%d);
		CREATE TABLE IF NOT EXISTS nodes(
			id TEXT PRIMARY KEY,
			sub_id TEXT NOT NULL DEFAULT '',
			name TEXT NOT NULL DEFAULT '',
			user_alias TEXT NOT NULL DEFAULT '',
			favorite INTEGER NOT NULL DEFAULT 0,
			protocol TEXT NOT NULL DEFAULT '',
			engine_pref TEXT NOT NULL DEFAULT 'auto',
			address TEXT NOT NULL DEFAULT '',
			port INTEGER NOT NULL DEFAULT 0,
			insecure_tls INTEGER NOT NULL DEFAULT 0,
			latency_ms INTEGER NOT NULL DEFAULT 0,
			sealed_credentials BLOB NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE INDEX IF NOT EXISTS nodes_sub_idx ON nodes(sub_id);
		CREATE TABLE IF NOT EXISTS subscriptions(
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			url_sealed BLOB NOT NULL,
			upload_bytes INTEGER NOT NULL DEFAULT 0,
			download_bytes INTEGER NOT NULL DEFAULT 0,
			total_bytes INTEGER NOT NULL DEFAULT 0,
			expire_unix INTEGER NOT NULL DEFAULT 0,
			auto_update_hours INTEGER NOT NULL DEFAULT 0,
			imported_count INTEGER NOT NULL DEFAULT 0,
			skipped_count INTEGER NOT NULL DEFAULT 0,
			warnings_json TEXT NOT NULL DEFAULT '[]',
			last_updated_at TEXT NOT NULL DEFAULT ''
		);
		CREATE TABLE IF NOT EXISTS inbounds(
			id TEXT PRIMARY KEY,
			document BLOB NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS settings(
			key TEXT PRIMARY KEY,
			document BLOB NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS groups(
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL UNIQUE,
			strategy TEXT NOT NULL DEFAULT 'selector',
			selected_node_id TEXT NOT NULL DEFAULT '',
			filter TEXT NOT NULL DEFAULT '',
			tolerance_ms INTEGER NOT NULL DEFAULT 50,
			interval TEXT NOT NULL DEFAULT '5m',
			priority_rule TEXT NOT NULL DEFAULT '',
			auto_failover INTEGER NOT NULL DEFAULT -1,
			detour_id TEXT NOT NULL DEFAULT '',
			sort_order INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS group_members(
			group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
			node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
			sort_order INTEGER NOT NULL DEFAULT 0,
			PRIMARY KEY(group_id, node_id)
		);
		CREATE INDEX IF NOT EXISTS group_members_node_idx ON group_members(node_id);
		CREATE TABLE IF NOT EXISTS routing_profiles(
			id TEXT PRIMARY KEY,
			document TEXT NOT NULL,
			updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE IF NOT EXISTS rule_sets(
			id TEXT PRIMARY KEY,
			tag TEXT NOT NULL UNIQUE,
			format TEXT NOT NULL DEFAULT 'binary',
			source_type TEXT NOT NULL DEFAULT 'remote',
			url TEXT NOT NULL DEFAULT '',
			local_path TEXT NOT NULL DEFAULT '',
			update_interval TEXT NOT NULL DEFAULT '24h',
			enabled INTEGER NOT NULL DEFAULT 1,
			last_synced_at TEXT NOT NULL DEFAULT '',
			size_bytes INTEGER NOT NULL DEFAULT 0
		);
	`, schemaVersion))
	if err != nil {
		return err
	}
	return s.ensureGroupsColumns()
}

func (s *Store) ensureGroupsColumns() error {
	rows, err := s.db.Query(`PRAGMA table_info(groups)`)
	if err != nil {
		return err
	}
	cols := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt any
		if err = rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		cols[name] = true
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if !cols["priority_rule"] {
		if _, err = s.db.Exec(`ALTER TABLE groups ADD COLUMN priority_rule TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	if !cols["auto_failover"] {
		if _, err = s.db.Exec(`ALTER TABLE groups ADD COLUMN auto_failover INTEGER NOT NULL DEFAULT -1`); err != nil {
			return err
		}
	}
	if !cols["detour_id"] {
		if _, err = s.db.Exec(`ALTER TABLE groups ADD COLUMN detour_id TEXT NOT NULL DEFAULT ''`); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string { return s.dbPath }

func seal(key, plaintext []byte, purpose string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	sealed := aead.Seal(nil, nonce, plaintext, []byte(purpose))
	return json.Marshal(sealedDocument{
		Encrypted: true,
		Nonce:     base64.RawStdEncoding.EncodeToString(nonce),
		Data:      base64.RawStdEncoding.EncodeToString(sealed),
	})
}

func openDocument(key, body []byte, purpose string) ([]byte, bool, error) {
	var doc sealedDocument
	if json.Unmarshal(body, &doc) != nil || !doc.Encrypted {
		return body, false, nil
	}
	if len(key) != 32 {
		return nil, true, fmt.Errorf("configuration is locked")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(doc.Nonce)
	if err != nil {
		return nil, true, err
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(doc.Data)
	if err != nil {
		return nil, true, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, true, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, true, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(purpose))
	return plaintext, true, err
}

func (s *Store) encodeNode(n *config.Node) ([]byte, error) {
	body, err := json.Marshal(n)
	if err != nil || len(s.key) == 0 {
		return body, err
	}
	return seal(s.key, body, "node:"+n.ID)
}

func (s *Store) decodeNode(id string, body []byte) (*config.Node, error) {
	body, _, err := openDocument(s.key, body, "node:"+id)
	if err != nil {
		return nil, err
	}
	var n config.Node
	if err = json.Unmarshal(body, &n); err != nil {
		return nil, err
	}
	return &n, nil
}

func (s *Store) encodeInbound(l *config.ListenConfig) ([]byte, error) {
	body, err := json.Marshal(l)
	if err != nil || len(s.key) == 0 {
		return body, err
	}
	return seal(s.key, body, "inbound:"+l.ID)
}

func (s *Store) decodeInbound(id string, body []byte) (*config.ListenConfig, error) {
	body, _, err := openDocument(s.key, body, "inbound:"+id)
	if err != nil {
		return nil, err
	}
	var l config.ListenConfig
	if err = json.Unmarshal(body, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) encodeSubURL(id, rawURL string) ([]byte, error) {
	if len(s.key) == 0 {
		return []byte(rawURL), nil
	}
	return seal(s.key, []byte(rawURL), "sub:"+id)
}

func (s *Store) decodeSubURL(id string, body []byte) (string, error) {
	plain, _, err := openDocument(s.key, body, "sub:"+id)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func enginePrefOrDefault(pref string) string {
	switch pref {
	case "sing-box", "xray":
		return pref
	default:
		return "auto"
	}
}

// SalvageResult summarizes records recovered or cleared when resetting a mismatched device key.
type SalvageResult struct {
	RecoveredNodes  int
	DeletedNodes    int
	DeletedInbounds int
	ResetSubURLs    int
	BackupPath      string
}

// Unlock supplies the in-memory data key, verifies existing encrypted records,
// and seals any pre-initialization plaintext records in one transaction.
func (s *Store) Unlock(key []byte) error {
	if len(key) != 32 {
		return fmt.Errorf("invalid data key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.key = append(s.key[:0], key...)
	success := false
	defer func() {
		if !success {
			for i := range s.key {
				s.key[i] = 0
			}
			s.key = nil
		}
	}()

	rows, err := s.db.Query(`
		SELECT 'node', id, sealed_credentials FROM nodes
		UNION ALL
		SELECT 'inbound', id, document FROM inbounds
		UNION ALL
		SELECT 'sub', id, url_sealed FROM subscriptions
	`)
	if err != nil {
		return err
	}
	type item struct {
		kind string
		id   string
		body []byte
	}
	var plain []item
	for rows.Next() {
		var v item
		if err = rows.Scan(&v.kind, &v.id, &v.body); err != nil {
			rows.Close()
			return err
		}
		_, encrypted, err := openDocument(s.key, v.body, v.kind+":"+v.id)
		if err != nil {
			rows.Close()
			return fmt.Errorf("unlock %s %s: %w", v.kind, v.id, err)
		}
		if !encrypted {
			plain = append(plain, v)
		}
	}
	if err = rows.Close(); err != nil {
		return err
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if len(plain) > 0 {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, v := range plain {
			body, err := seal(s.key, v.body, v.kind+":"+v.id)
			if err != nil {
				return err
			}
			var stmt string
			switch v.kind {
			case "node":
				stmt = `UPDATE nodes SET sealed_credentials=? WHERE id=?`
			case "inbound":
				stmt = `UPDATE inbounds SET document=? WHERE id=?`
			case "sub":
				stmt = `UPDATE subscriptions SET url_sealed=? WHERE id=?`
			default:
				return fmt.Errorf("unexpected sealed item kind %q", v.kind)
			}
			if _, err = tx.Exec(stmt, body, v.id); err != nil {
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if _, err = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			return err
		}
	}
	success = true
	return nil
}

// SalvageWithSingBoxConfig repairs sealed database records that can no longer be opened
// with key by matching node IDs against the last generated sing-box.json runtime config
// and preserving unencrypted metadata, groups, settings, and subscription quotas.
func (s *Store) SalvageWithSingBoxConfig(key []byte, singBoxConfigPath string) (*SalvageResult, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid data key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	res := &SalvageResult{}
	if _, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return nil, err
	}
	if s.dbPath != "" {
		if rawDB, err := os.ReadFile(s.dbPath); err == nil {
			bakPath := fmt.Sprintf("%s.bak.%d", s.dbPath, time.Now().Unix())
			if wErr := os.WriteFile(bakPath, rawDB, 0o600); wErr == nil {
				res.BackupPath = bakPath
			}
		}
	}

	recoveredByID := map[string]*config.Node{}
	if strings.TrimSpace(singBoxConfigPath) != "" {
		if rawCfg, err := os.ReadFile(singBoxConfigPath); err == nil {
			if parsed, pErr := config.ParseSubscriptionResilient(string(rawCfg)); pErr == nil && parsed != nil {
				for _, n := range parsed.Nodes {
					if n == nil || n.Name == "" {
						continue
					}
					recoveredByID[n.Name] = n
					if trimmed := strings.TrimPrefix(n.Name, "node-"); trimmed != "" && trimmed != n.Name {
						recoveredByID[trimmed] = n
					}
				}
			}
		}
	}

	type nodeRow struct {
		id          string
		subID       string
		name        string
		userAlias   string
		favorite    int
		enginePref  string
		insecureTLS int
		latencyMS   int
		body        []byte
	}
	var nodeRows []nodeRow
	nRows, err := s.db.Query(`SELECT id, sub_id, name, user_alias, favorite, engine_pref, insecure_tls, latency_ms, sealed_credentials FROM nodes`)
	if err != nil {
		return nil, err
	}
	for nRows.Next() {
		var r nodeRow
		if err = nRows.Scan(&r.id, &r.subID, &r.name, &r.userAlias, &r.favorite, &r.enginePref, &r.insecureTLS, &r.latencyMS, &r.body); err != nil {
			nRows.Close()
			return nil, err
		}
		nodeRows = append(nodeRows, r)
	}
	if err = nRows.Close(); err != nil {
		return nil, err
	}
	if err = nRows.Err(); err != nil {
		return nil, err
	}

	type sealedRow struct {
		id   string
		body []byte
	}
	var inboundRows []sealedRow
	inRows, err := s.db.Query(`SELECT id, document FROM inbounds`)
	if err != nil {
		return nil, err
	}
	for inRows.Next() {
		var r sealedRow
		if err = inRows.Scan(&r.id, &r.body); err != nil {
			inRows.Close()
			return nil, err
		}
		inboundRows = append(inboundRows, r)
	}
	if err = inRows.Close(); err != nil {
		return nil, err
	}
	if err = inRows.Err(); err != nil {
		return nil, err
	}

	var subRows []sealedRow
	sbRows, err := s.db.Query(`SELECT id, url_sealed FROM subscriptions`)
	if err != nil {
		return nil, err
	}
	for sbRows.Next() {
		var r sealedRow
		if err = sbRows.Scan(&r.id, &r.body); err != nil {
			sbRows.Close()
			return nil, err
		}
		subRows = append(subRows, r)
	}
	if err = sbRows.Close(); err != nil {
		return nil, err
	}
	if err = sbRows.Err(); err != nil {
		return nil, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	for _, r := range nodeRows {
		if _, _, err := openDocument(key, r.body, "node:"+r.id); err == nil {
			continue
		}
		if src := recoveredByID[r.id]; src != nil {
			rebuilt := *src
			rebuilt.ID = r.id
			rebuilt.SubID = r.subID
			if r.name != "" {
				rebuilt.Name = r.name
			}
			rebuilt.UserAlias = r.userAlias
			rebuilt.Favorite = r.favorite != 0
			if r.enginePref != "" {
				rebuilt.EnginePref = r.enginePref
			}
			if r.latencyMS != 0 {
				rebuilt.Latency = r.latencyMS
			}
			if r.insecureTLS != 0 {
				rebuilt.AllowInsecure = true
			}
			rawJSON, err := json.Marshal(&rebuilt)
			if err != nil {
				return nil, err
			}
			sealed, err := seal(key, rawJSON, "node:"+r.id)
			if err != nil {
				return nil, err
			}
			if _, err = tx.Exec(`UPDATE nodes SET sealed_credentials=? WHERE id=?`, sealed, r.id); err != nil {
				return nil, err
			}
			res.RecoveredNodes++
		} else {
			if _, err = tx.Exec(`DELETE FROM nodes WHERE id=?`, r.id); err != nil {
				return nil, err
			}
			res.DeletedNodes++
		}
	}

	for _, r := range inboundRows {
		if _, _, err := openDocument(key, r.body, "inbound:"+r.id); err == nil {
			continue
		}
		if _, err = tx.Exec(`DELETE FROM inbounds WHERE id=?`, r.id); err != nil {
			return nil, err
		}
		res.DeletedInbounds++
	}

	for _, r := range subRows {
		if _, _, err := openDocument(key, r.body, "sub:"+r.id); err == nil {
			continue
		}
		emptyURL, err := seal(key, []byte(""), "sub:"+r.id)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec(`UPDATE subscriptions SET url_sealed=? WHERE id=?`, emptyURL, r.id); err != nil {
			return nil, err
		}
		res.ResetSubURLs++
	}

	if err = tx.Commit(); err != nil {
		return nil, err
	}
	if _, err = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return nil, err
	}
	return res, nil
}

// Lock wipes the in-memory encryption key so sealed records cannot be decoded.
func (s *Store) Lock() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.key {
		s.key[i] = 0
	}
	s.key = nil
}

// Unlocked reports whether an encryption key is currently loaded.
func (s *Store) Unlocked() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.key) == 32
}

func (s *Store) scanNodes(rows *sql.Rows) ([]*config.Node, error) {
	defer rows.Close()
	out := []*config.Node{}
	for rows.Next() {
		var id, subID, userAlias, enginePref string
		var favorite, latency int
		var body []byte
		if err := rows.Scan(&id, &subID, &userAlias, &favorite, &enginePref, &latency, &body); err != nil {
			return nil, err
		}
		n, err := s.decodeNode(id, body)
		if err != nil {
			return nil, err
		}
		if n.SubID == "" && subID != "" {
			n.SubID = subID
		}
		if n.UserAlias == "" && userAlias != "" {
			n.UserAlias = userAlias
		}
		if !n.Favorite && favorite != 0 {
			n.Favorite = true
		}
		if n.EnginePref == "" && enginePref != "" {
			n.EnginePref = enginePref
		}
		if n.Latency == 0 && latency != 0 {
			n.Latency = latency
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

const nodeSelectColumns = `id, sub_id, user_alias, favorite, engine_pref, latency_ms, sealed_credentials`

// List returns all stored nodes ordered by favorite flag and insertion order.
func (s *Store) List() []*config.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT ` + nodeSelectColumns + ` FROM nodes ORDER BY favorite DESC, rowid ASC`)
	if err != nil {
		return nil
	}
	out, err := s.scanNodes(rows)
	if err != nil {
		return nil
	}
	return out
}

// ListBySubscription returns nodes belonging to the specified subscription ID.
func (s *Store) ListBySubscription(subID string) []*config.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT `+nodeSelectColumns+` FROM nodes WHERE sub_id=? ORDER BY rowid ASC`, subID)
	if err != nil {
		return nil
	}
	out, err := s.scanNodes(rows)
	if err != nil {
		return nil
	}
	return out
}

// Get returns a single decoded node or nil if missing/locked.
func (s *Store) Get(id string) *config.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var subID, userAlias, enginePref string
	var favorite, latency int
	var body []byte
	err := s.db.QueryRow(`SELECT `+nodeSelectColumns+` FROM nodes WHERE id=?`, id).Scan(
		&id, &subID, &userAlias, &favorite, &enginePref, &latency, &body,
	)
	if err != nil {
		return nil
	}
	n, err := s.decodeNode(id, body)
	if err != nil {
		return nil
	}
	return n
}

func (s *Store) upsertNodeTx(tx *sql.Tx, insertOnly bool, n *config.Node) error {
	body, err := s.encodeNode(n)
	if err != nil {
		return err
	}
	if insertOnly {
		_, err = tx.Exec(`
			INSERT INTO nodes(
				id, sub_id, name, user_alias, favorite, protocol, engine_pref,
				address, port, insecure_tls, latency_ms, sealed_credentials
			) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		`, n.ID, n.SubID, n.Name, n.UserAlias, boolInt(n.Favorite), string(n.Protocol),
			enginePrefOrDefault(n.EnginePref), n.Address, n.Port, boolInt(n.AllowInsecure), n.Latency, body)
		return err
	}
	_, err = tx.Exec(`
		INSERT INTO nodes(
			id, sub_id, name, user_alias, favorite, protocol, engine_pref,
			address, port, insecure_tls, latency_ms, sealed_credentials, updated_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			sub_id=excluded.sub_id,
			name=excluded.name,
			user_alias=excluded.user_alias,
			favorite=excluded.favorite,
			protocol=excluded.protocol,
			engine_pref=excluded.engine_pref,
			address=excluded.address,
			port=excluded.port,
			insecure_tls=excluded.insecure_tls,
			latency_ms=excluded.latency_ms,
			sealed_credentials=excluded.sealed_credentials,
			updated_at=CURRENT_TIMESTAMP
	`, n.ID, n.SubID, n.Name, n.UserAlias, boolInt(n.Favorite), string(n.Protocol),
		enginePrefOrDefault(n.EnginePref), n.Address, n.Port, boolInt(n.AllowInsecure), n.Latency, body)
	return err
}

// Add inserts one node.
func (s *Store) Add(node *config.Node) error { return s.AddMultiple([]*config.Node{node}) }

// AddMultiple inserts multiple nodes atomically.
func (s *Store) AddMultiple(nodes []*config.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, n := range nodes {
		if n == nil || n.ID == "" {
			return fmt.Errorf("invalid node")
		}
		if err = s.upsertNodeTx(tx, true, n); err != nil {
			return fmt.Errorf("add node: %w", err)
		}
	}
	return tx.Commit()
}

// Update replaces an existing node record.
func (s *Store) Update(node *config.Node) error {
	if node == nil || node.ID == "" {
		return fmt.Errorf("invalid node")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := s.encodeNode(node)
	if err != nil {
		return err
	}
	result, err := s.db.Exec(`
		UPDATE nodes SET
			sub_id=?, name=?, user_alias=?, favorite=?, protocol=?, engine_pref=?,
			address=?, port=?, insecure_tls=?, latency_ms=?, sealed_credentials=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?
	`, node.SubID, node.Name, node.UserAlias, boolInt(node.Favorite), string(node.Protocol),
		enginePrefOrDefault(node.EnginePref), node.Address, node.Port, boolInt(node.AllowInsecure),
		node.Latency, body, node.ID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// Delete removes a node if no inbound listener currently references it.
func (s *Store) Delete(id string) error {
	for _, inbound := range s.ListListeners() {
		for _, nodeID := range inbound.NodeIDs {
			if nodeID == id {
				return fmt.Errorf("node is referenced by inbound %q", inbound.Name)
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`DELETE FROM nodes WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// UpdateLatency updates only a node's latency while holding the write lock so
// concurrent metadata edits are never lost.
func (s *Store) UpdateLatency(id string, latency int) error {
	return s.UpdateNodeProbeMetrics(id, &latency, nil, nil, nil)
}

// UpdateNodeProbeMetrics atomically updates probe latency, TCP ping, and bandwidth metrics.
func (s *Store) UpdateNodeProbeMetrics(id string, latencyMS, pingMS *int, downMbps, upMbps *float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var currentLatency int
	var body []byte
	err := s.db.QueryRow(`SELECT latency_ms, sealed_credentials FROM nodes WHERE id=?`, id).Scan(&currentLatency, &body)
	if errors.Is(err, sql.ErrNoRows) {
		return os.ErrNotExist
	}
	if err != nil {
		return err
	}
	n, err := s.decodeNode(id, body)
	if err != nil {
		return err
	}
	if latencyMS != nil {
		n.Latency = *latencyMS
		currentLatency = *latencyMS
	}
	if pingMS != nil {
		n.PingMS = *pingMS
	}
	if downMbps != nil {
		n.DownSpeedMbps = *downMbps
	}
	if upMbps != nil {
		n.UpSpeedMbps = *upMbps
	}
	updatedBody, err := s.encodeNode(n)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE nodes SET latency_ms=?, sealed_credentials=? WHERE id=?`, currentLatency, updatedBody, id)
	return err
}

// SyncSubscriptionNodes synchronizes all nodes owned by a subscription while
// preserving local user overrides (alias, favorite, engine preference) and any
// nodes currently pinned by inbound listeners.
func (s *Store) SyncSubscriptionNodes(subID string, nodes []*config.Node) error {
	return s.syncNodes(subID, subID+"-", nodes)
}

// ReplaceSubscription provides prefix-based replacement for compatibility with
// legacy subscription callers and delegates to syncNodes.
func (s *Store) ReplaceSubscription(prefix string, nodes []*config.Node) error {
	subID := strings.TrimSuffix(prefix, "-")
	return s.syncNodes(subID, prefix, nodes)
}

func (s *Store) syncNodes(subID, idPrefix string, nodes []*config.Node) error {
	for _, n := range nodes {
		if n == nil || n.ID == "" {
			return fmt.Errorf("invalid node")
		}
		if err := n.Validate(); err != nil {
			return err
		}
	}
	referenced := map[string]bool{}
	for _, inbound := range s.ListListeners() {
		for _, id := range inbound.NodeIDs {
			referenced[id] = true
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	incoming := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		incoming[n.ID] = true
		if n.SubID == "" && subID != "" {
			n.SubID = subID
		}
	}

	rows, err := tx.Query(`SELECT id, sealed_credentials FROM nodes WHERE sub_id=? OR id LIKE ?`, subID, idPrefix+"%")
	if err != nil {
		return err
	}
	existing := map[string]*config.Node{}
	for rows.Next() {
		var id string
		var body []byte
		if err = rows.Scan(&id, &body); err != nil {
			rows.Close()
			return err
		}
		if prev, err := s.decodeNode(id, body); err == nil {
			existing[id] = prev
		} else {
			existing[id] = &config.Node{ID: id}
		}
	}
	rows.Close()

	for id := range existing {
		if incoming[id] || referenced[id] {
			continue
		}
		if _, err = tx.Exec(`DELETE FROM nodes WHERE id=?`, id); err != nil {
			return err
		}
	}
	for _, n := range nodes {
		if prev, ok := existing[n.ID]; ok {
			if n.UserAlias == "" {
				n.UserAlias = prev.UserAlias
			}
			if !n.Favorite {
				n.Favorite = prev.Favorite
			}
			if n.EnginePref == "" {
				n.EnginePref = prev.EnginePref
			}
			if n.Group == "" {
				n.Group = prev.Group
			}
			if len(n.Tags) == 0 && len(prev.Tags) > 0 {
				n.Tags = prev.Tags
			}
			if n.Latency == 0 {
				n.Latency = prev.Latency
			}
			if n.PingMS == 0 {
				n.PingMS = prev.PingMS
			}
			if n.DownSpeedMbps == 0 {
				n.DownSpeedMbps = prev.DownSpeedMbps
			}
			if n.UpSpeedMbps == 0 {
				n.UpSpeedMbps = prev.UpSpeedMbps
			}
		}
		if err = s.upsertNodeTx(tx, false, n); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) scanInbounds(rows *sql.Rows) ([]*config.ListenConfig, error) {
	defer rows.Close()
	out := []*config.ListenConfig{}
	for rows.Next() {
		var id string
		var body []byte
		if err := rows.Scan(&id, &body); err != nil {
			return nil, err
		}
		l, err := s.decodeInbound(id, body)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// ListListeners returns all configured inbound listeners.
func (s *Store) ListListeners() []*config.ListenConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id, document FROM inbounds ORDER BY rowid ASC`)
	if err != nil {
		return nil
	}
	out, err := s.scanInbounds(rows)
	if err != nil {
		return nil
	}
	return out
}

// GetListener returns an inbound listener by ID or nil.
func (s *Store) GetListener(id string) *config.ListenConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var body []byte
	if err := s.db.QueryRow(`SELECT document FROM inbounds WHERE id=?`, id).Scan(&body); err != nil {
		return nil
	}
	l, err := s.decodeInbound(id, body)
	if err != nil {
		return nil
	}
	return l
}

// AddListener inserts a new inbound listener.
func (s *Store) AddListener(l *config.ListenConfig) error {
	if l == nil || l.ID == "" {
		return fmt.Errorf("invalid listener")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := s.encodeInbound(l)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO inbounds(id, document) VALUES(?,?)`, l.ID, body)
	return err
}

// UpdateListener updates an existing inbound listener.
func (s *Store) UpdateListener(l *config.ListenConfig) error {
	if l == nil || l.ID == "" {
		return fmt.Errorf("invalid listener")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	body, err := s.encodeInbound(l)
	if err != nil {
		return err
	}
	result, err := s.db.Exec(`UPDATE inbounds SET document=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, body, l.ID)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// DeleteListener removes an inbound listener by ID.
func (s *Store) DeleteListener(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`DELETE FROM inbounds WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

func validateRestore(nodes []*config.Node, listeners []*config.ListenConfig) error {
	ids := map[string]bool{}
	for _, n := range nodes {
		if n == nil || n.ID == "" || ids[n.ID] {
			return fmt.Errorf("invalid or duplicate node")
		}
		if err := n.Validate(); err != nil {
			return err
		}
		ids[n.ID] = true
	}
	lids := map[string]bool{}
	for _, l := range listeners {
		if l == nil || l.ID == "" || lids[l.ID] || l.Port < 1 || l.Port > 65535 || l.Address == "" ||
			(l.Protocol != "http" && l.Protocol != "socks" && l.Protocol != "mixed") {
			return fmt.Errorf("invalid listener")
		}
		lids[l.ID] = true
		for _, id := range l.NodeIDs {
			if !ids[id] {
				return fmt.Errorf("missing listener node")
			}
		}
	}
	return nil
}

// Restore atomically replaces all nodes and inbound listeners.
func (s *Store) Restore(nodes []*config.Node, listeners []*config.ListenConfig) error {
	if err := validateRestore(nodes, listeners); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM inbounds`); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM nodes`); err != nil {
		return err
	}
	for _, n := range nodes {
		if err = s.upsertNodeTx(tx, true, n); err != nil {
			return err
		}
	}
	for _, l := range listeners {
		body, err := s.encodeInbound(l)
		if err != nil {
			return err
		}
		if _, err = tx.Exec(`INSERT INTO inbounds(id, document) VALUES(?,?)`, l.ID, body); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// GetSetting decodes a plaintext JSON configuration setting by key.
func (s *Store) GetSetting(key string, target any) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var body []byte
	err := s.db.QueryRow(`SELECT document FROM settings WHERE key=?`, key).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(body, target)
}

// PutSetting persists a plaintext JSON configuration setting.
func (s *Store) PutSetting(key string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.db.Exec(`INSERT INTO settings(key,document) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET document=excluded.document, updated_at=CURRENT_TIMESTAMP`, key, body)
	return err
}

// PutSecret encrypts and stores a secret byte slice under the given setting key.
func (s *Store) PutSecret(key string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.key) != 32 {
		return fmt.Errorf("configuration is locked")
	}
	body, err := seal(s.key, value, "setting:"+key)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO settings(key,document) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET document=excluded.document, updated_at=CURRENT_TIMESTAMP`, key, body)
	return err
}

// GetSecret decrypts and returns a secret byte slice stored under the given key.
func (s *Store) GetSecret(key string) ([]byte, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var body []byte
	err := s.db.QueryRow(`SELECT document FROM settings WHERE key=?`, key).Scan(&body)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	plain, _, err := openDocument(s.key, body, "setting:"+key)
	return plain, true, err
}

// DeleteSetting removes a setting or secret by key.
func (s *Store) DeleteSetting(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`DELETE FROM settings WHERE key=?`, key)
	return err
}

// CanonicalGroupStrategy maps UI/v0.1 group strategy names to sing-box semantics.
func CanonicalGroupStrategy(strategy string) string {
	switch strings.ToLower(strings.TrimSpace(strategy)) {
	case "manual":
		return "selector"
	case "latency":
		return "urltest"
	case "loadbalance", "load-balance", "hash":
		return "loadbalance"
	default:
		return strings.ToLower(strings.TrimSpace(strategy))
	}
}

func encodeGroupAutoFailover(v *bool) int {
	if v == nil {
		return -1
	}
	if *v {
		return 1
	}
	return 0
}

func decodeGroupAutoFailover(raw int) *bool {
	if raw < 0 {
		return nil
	}
	val := raw > 0
	return &val
}

func normalizeGroupPriorityRule(raw string) string {
	switch strings.TrimSpace(raw) {
	case "latency_first", "speed_first", "hybrid_score":
		return strings.TrimSpace(raw)
	default:
		return ""
	}
}

func validateGroup(g Group) error {
	if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.Name) == "" {
		return fmt.Errorf("group ID and name are required")
	}
	switch CanonicalGroupStrategy(g.Strategy) {
	case "selector", "urltest", "failover", "loadbalance":
		return nil
	default:
		return fmt.Errorf("group strategy must be selector, urltest, failover, or loadbalance")
	}
}

// ListGroups returns all proxy groups along with their ordered member node IDs.
func (s *Store) ListGroups() ([]Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`SELECT id, name, strategy, selected_node_id, filter, tolerance_ms, interval, priority_rule, auto_failover, detour_id, sort_order FROM groups ORDER BY sort_order, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		var autoFailoverRaw int
		if err = rows.Scan(&g.ID, &g.Name, &g.Strategy, &g.SelectedNodeID, &g.Filter, &g.ToleranceMS, &g.Interval, &g.PriorityRule, &autoFailoverRaw, &g.DetourID, &g.SortOrder); err != nil {
			return nil, err
		}
		g.AutoFailover = decodeGroupAutoFailover(autoFailoverRaw)
		out = append(out, g)
	}
	if err = rows.Close(); err != nil {
		return nil, err
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		g := &out[i]
		memberRows, err := s.db.Query(`SELECT node_id FROM group_members WHERE group_id=? ORDER BY sort_order, node_id`, g.ID)
		if err != nil {
			return nil, err
		}
		for memberRows.Next() {
			var id string
			if err = memberRows.Scan(&id); err != nil {
				memberRows.Close()
				return nil, err
			}
			g.NodeIDs = append(g.NodeIDs, id)
		}
		memberRows.Close()
	}
	return out, nil
}

// SaveGroup creates or updates a proxy group and replaces its member list.
func (s *Store) SaveGroup(g Group) error {
	if err := validateGroup(g); err != nil {
		return err
	}
	g.PriorityRule = normalizeGroupPriorityRule(g.PriorityRule)
	if g.ToleranceMS <= 0 {
		g.ToleranceMS = 50
	}
	if strings.TrimSpace(g.Interval) == "" {
		g.Interval = "5m"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`
		INSERT INTO groups(id, name, strategy, selected_node_id, filter, tolerance_ms, interval, priority_rule, auto_failover, detour_id, sort_order)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			strategy=excluded.strategy,
			selected_node_id=excluded.selected_node_id,
			filter=excluded.filter,
			tolerance_ms=excluded.tolerance_ms,
			interval=excluded.interval,
			priority_rule=excluded.priority_rule,
			auto_failover=excluded.auto_failover,
			detour_id=excluded.detour_id,
			sort_order=excluded.sort_order
	`, g.ID, strings.TrimSpace(g.Name), g.Strategy, g.SelectedNodeID, g.Filter, g.ToleranceMS, g.Interval, g.PriorityRule, encodeGroupAutoFailover(g.AutoFailover), strings.TrimSpace(g.DetourID), g.SortOrder); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM group_members WHERE group_id=?`, g.ID); err != nil {
		return err
	}
	for i, id := range g.NodeIDs {
		if _, err = tx.Exec(`INSERT INTO group_members(group_id, node_id, sort_order) VALUES(?,?,?)`, g.ID, id, i); err != nil {
			return fmt.Errorf("group member %q: %w", id, err)
		}
	}
	return tx.Commit()
}

// ReorderGroups updates group sort_order atomically using the provided ordered IDs.
func (s *Store) ReorderGroups(orderedIDs []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.Query(`SELECT id FROM groups ORDER BY sort_order, name`)
	if err != nil {
		return err
	}
	var existingOrder []string
	existingSet := map[string]bool{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		existingSet[id] = true
		existingOrder = append(existingOrder, id)
	}
	if err = rows.Close(); err != nil {
		return err
	}

	finalOrder := make([]string, 0, len(existingOrder))
	seen := map[string]bool{}
	for _, raw := range orderedIDs {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if !existingSet[id] {
			return fmt.Errorf("unknown group id %q", id)
		}
		if !seen[id] {
			seen[id] = true
			finalOrder = append(finalOrder, id)
		}
	}
	for _, id := range existingOrder {
		if !seen[id] {
			seen[id] = true
			finalOrder = append(finalOrder, id)
		}
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for idx, id := range finalOrder {
		if _, err = tx.Exec(`UPDATE groups SET sort_order=? WHERE id=?`, idx+1, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SelectGroupNode persists the currently selected node inside a selector group.
func (s *Store) SelectGroupNode(groupID, nodeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`UPDATE groups SET selected_node_id=? WHERE id=?`, nodeID, groupID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// DeleteGroup removes a proxy group.
func (s *Store) DeleteGroup(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.db.Exec(`DELETE FROM groups WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// ReplaceGroups atomically replaces all proxy groups.
func (s *Store) ReplaceGroups(groups []Group) error {
	seen := map[string]bool{}
	for _, group := range groups {
		if err := validateGroup(group); err != nil || seen[group.ID] {
			return fmt.Errorf("invalid or duplicate group")
		}
		seen[group.ID] = true
		for _, id := range group.NodeIDs {
			if s.Get(id) == nil {
				return fmt.Errorf("group references missing node %q", id)
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM groups`); err != nil {
		return err
	}
	for _, group := range groups {
		tol := group.ToleranceMS
		if tol <= 0 {
			tol = 50
		}
		interval := strings.TrimSpace(group.Interval)
		if interval == "" {
			interval = "5m"
		}
		if _, err = tx.Exec(`
			INSERT INTO groups(id, name, strategy, selected_node_id, filter, tolerance_ms, interval, priority_rule, auto_failover, detour_id, sort_order)
			VALUES(?,?,?,?,?,?,?,?,?,?,?)
		`, group.ID, strings.TrimSpace(group.Name), group.Strategy, group.SelectedNodeID, group.Filter, tol, interval, normalizeGroupPriorityRule(group.PriorityRule), encodeGroupAutoFailover(group.AutoFailover), strings.TrimSpace(group.DetourID), group.SortOrder); err != nil {
			return err
		}
		for i, id := range group.NodeIDs {
			if _, err = tx.Exec(`INSERT INTO group_members(group_id, node_id, sort_order) VALUES(?,?,?)`, group.ID, id, i); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// ListSubscriptions returns all saved subscription profiles with decrypted URLs.
func (s *Store) ListSubscriptions() ([]SubscriptionRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT id, name, url_sealed, upload_bytes, download_bytes, total_bytes, expire_unix,
		       auto_update_hours, imported_count, skipped_count, warnings_json, last_updated_at
		FROM subscriptions ORDER BY rowid ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SubscriptionRecord{}
	for rows.Next() {
		var rec SubscriptionRecord
		var urlSealed []byte
		var warningsJSON string
		if err = rows.Scan(
			&rec.ID, &rec.Name, &urlSealed, &rec.UploadBytes, &rec.DownloadBytes, &rec.TotalBytes, &rec.ExpireUnix,
			&rec.AutoUpdateHours, &rec.ImportedCount, &rec.SkippedCount, &warningsJSON, &rec.LastUpdatedAt,
		); err != nil {
			return nil, err
		}
		rec.URL, err = s.decodeSubURL(rec.ID, urlSealed)
		if err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(warningsJSON), &rec.Warnings)
		if rec.Warnings == nil {
			rec.Warnings = []string{}
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// GetSubscription returns one decoded subscription profile by ID.
func (s *Store) GetSubscription(id string) (*SubscriptionRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var rec SubscriptionRecord
	var urlSealed []byte
	var warningsJSON string
	err := s.db.QueryRow(`
		SELECT id, name, url_sealed, upload_bytes, download_bytes, total_bytes, expire_unix,
		       auto_update_hours, imported_count, skipped_count, warnings_json, last_updated_at
		FROM subscriptions WHERE id=?
	`, id).Scan(
		&rec.ID, &rec.Name, &urlSealed, &rec.UploadBytes, &rec.DownloadBytes, &rec.TotalBytes, &rec.ExpireUnix,
		&rec.AutoUpdateHours, &rec.ImportedCount, &rec.SkippedCount, &warningsJSON, &rec.LastUpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rec.URL, err = s.decodeSubURL(rec.ID, urlSealed)
	if err != nil {
		return nil, false, err
	}
	_ = json.Unmarshal([]byte(warningsJSON), &rec.Warnings)
	if rec.Warnings == nil {
		rec.Warnings = []string{}
	}
	return &rec, true, nil
}

// SaveSubscription creates or updates a subscription profile with encrypted URL storage.
func (s *Store) SaveSubscription(rec SubscriptionRecord) error {
	if strings.TrimSpace(rec.ID) == "" || strings.TrimSpace(rec.Name) == "" {
		return fmt.Errorf("subscription id and name are required")
	}
	if rec.Warnings == nil {
		rec.Warnings = []string{}
	}
	warningsBody, err := json.Marshal(rec.Warnings)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	urlSealed, err := s.encodeSubURL(rec.ID, rec.URL)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
		INSERT INTO subscriptions(
			id, name, url_sealed, upload_bytes, download_bytes, total_bytes, expire_unix,
			auto_update_hours, imported_count, skipped_count, warnings_json, last_updated_at
		) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name,
			url_sealed=excluded.url_sealed,
			upload_bytes=excluded.upload_bytes,
			download_bytes=excluded.download_bytes,
			total_bytes=excluded.total_bytes,
			expire_unix=excluded.expire_unix,
			auto_update_hours=excluded.auto_update_hours,
			imported_count=excluded.imported_count,
			skipped_count=excluded.skipped_count,
			warnings_json=excluded.warnings_json,
			last_updated_at=excluded.last_updated_at
	`, rec.ID, rec.Name, urlSealed, rec.UploadBytes, rec.DownloadBytes, rec.TotalBytes, rec.ExpireUnix,
		rec.AutoUpdateHours, rec.ImportedCount, rec.SkippedCount, string(warningsBody), rec.LastUpdatedAt)
	return err
}

// DeleteSubscription removes a subscription record by ID.
func (s *Store) DeleteSubscription(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM subscriptions WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// ListRuleSets returns all configured .srs / inline rule-set entries.
func (s *Store) ListRuleSets() ([]RuleSetRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows, err := s.db.Query(`
		SELECT id, tag, format, source_type, url, local_path, update_interval, enabled, last_synced_at, size_bytes
		FROM rule_sets ORDER BY rowid ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleSetRecord{}
	for rows.Next() {
		var r RuleSetRecord
		var enabled int
		if err = rows.Scan(&r.ID, &r.Tag, &r.Format, &r.SourceType, &r.URL, &r.LocalPath, &r.UpdateInterval, &enabled, &r.LastSyncedAt, &r.SizeBytes); err != nil {
			return nil, err
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// SaveRuleSet inserts or updates a rule-set definition.
func (s *Store) SaveRuleSet(r RuleSetRecord) error {
	if strings.TrimSpace(r.ID) == "" || strings.TrimSpace(r.Tag) == "" {
		return fmt.Errorf("rule set id and tag are required")
	}
	if r.Format == "" {
		r.Format = "binary"
	}
	if r.SourceType == "" {
		r.SourceType = "remote"
	}
	if r.UpdateInterval == "" {
		r.UpdateInterval = "24h"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO rule_sets(id, tag, format, source_type, url, local_path, update_interval, enabled, last_synced_at, size_bytes)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			tag=excluded.tag,
			format=excluded.format,
			source_type=excluded.source_type,
			url=excluded.url,
			local_path=excluded.local_path,
			update_interval=excluded.update_interval,
			enabled=excluded.enabled,
			last_synced_at=excluded.last_synced_at,
			size_bytes=excluded.size_bytes
	`, r.ID, r.Tag, r.Format, r.SourceType, r.URL, r.LocalPath, r.UpdateInterval, boolInt(r.Enabled), r.LastSyncedAt, r.SizeBytes)
	return err
}

// DeleteRuleSet removes a rule-set record.
func (s *Store) DeleteRuleSet(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(`DELETE FROM rule_sets WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return os.ErrNotExist
	}
	return nil
}

// SaveRoutingProfile inserts or updates a named routing profile.
func (s *Store) SaveRoutingProfile(p RoutingProfileRecord) error {
	if strings.TrimSpace(p.ID) == "" || len(p.Document) == 0 {
		return fmt.Errorf("routing profile id and document are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(`
		INSERT INTO routing_profiles(id, document, updated_at) VALUES(?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET document=excluded.document, updated_at=CURRENT_TIMESTAMP
	`, p.ID, string(p.Document))
	return err
}

// GetRoutingProfile retrieves a routing profile by ID.
func (s *Store) GetRoutingProfile(id string) (*RoutingProfileRecord, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var doc string
	var updatedAt string
	err := s.db.QueryRow(`SELECT document, updated_at FROM routing_profiles WHERE id=?`, id).Scan(&doc, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return &RoutingProfileRecord{ID: id, Document: json.RawMessage(doc), UpdatedAt: updatedAt}, true, nil
}
