// SPDX-License-Identifier: MPL-2.0

package api

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/appconfig"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/singbox/ruleset"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
	xc "github.com/CRACKRAMMER/PrismRay/backend/internal/xray/config"
)

const (
	encryptedBackupFormat     = "prismray-encrypted-backup"
	encryptedBackupVersion    = 5
	encryptedBackupKDF        = "argon2id"
	encryptedBackupKDFTime    = uint32(3)
	encryptedBackupKDFMemory  = uint32(64 * 1024)
	encryptedBackupKDFThreads = uint8(2)
)

// BackupNamedProfile preserves multi-profile routing definitions inside full backups.
type BackupNamedProfile struct {
	Meta    RoutingProfileMeta     `json:"meta"`
	Profile ruleset.RoutingProfile `json:"profile"`
}

// EncryptedBackupEnvelope wraps a v4 FullBackup JSON document using Argon2id + AES-256-GCM.
type EncryptedBackupEnvelope struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	KDFTime    uint32 `json:"kdf_time,omitempty"`
	KDFMemory  uint32 `json:"kdf_memory,omitempty"`
	KDFThreads uint8  `json:"kdf_threads,omitempty"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// FullBackup represents an exportable configuration snapshot (v4 plaintext or v5 encrypted payload).
type FullBackup struct {
	Version         int                    `json:"version"`
	Nodes           []*config.Node         `json:"nodes"`
	Listeners       []*config.ListenConfig `json:"listeners"`
	Groups          []storage.Group        `json:"groups,omitempty"`
	Subscriptions   []Subscription         `json:"subscriptions,omitempty"`
	RoutingProfile  ruleset.RoutingProfile `json:"routing_profile,omitempty"`
	RoutingProfiles []BackupNamedProfile   `json:"routing_profiles,omitempty"`
	ActiveProfileID string                 `json:"active_profile_id,omitempty"`
	RuleSets        []ruleset.RuleSetSpec  `json:"rule_sets,omitempty"`
	Preferences     *xc.Preferences        `json:"preferences,omitempty"`
	Health          *HealthSettings        `json:"health,omitempty"`
}

func encryptBackupPayload(plaintext []byte, passphrase string) (*EncryptedBackupEnvelope, error) {
	if utf8.RuneCountInString(passphrase) < 8 {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "加密口令至少需要 8 位字符"}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	backupArgonSem <- struct{}{}
	key := argon2.IDKey([]byte(passphrase), salt, encryptedBackupKDFTime, encryptedBackupKDFMemory, encryptedBackupKDFThreads, 32)
	<-backupArgonSem
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(encryptedBackupFormat + ":v5")
	ciphertext := aead.Seal(nil, nonce, plaintext, aad)
	return &EncryptedBackupEnvelope{
		Format:     encryptedBackupFormat,
		Version:    encryptedBackupVersion,
		KDF:        encryptedBackupKDF,
		KDFTime:    encryptedBackupKDFTime,
		KDFMemory:  encryptedBackupKDFMemory,
		KDFThreads: encryptedBackupKDFThreads,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

func decryptBackupEnvelope(env EncryptedBackupEnvelope, passphrase string) ([]byte, error) {
	if env.Format != encryptedBackupFormat || env.Version != encryptedBackupVersion {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "unsupported encrypted backup format"}
	}
	if strings.ToLower(strings.TrimSpace(env.KDF)) != encryptedBackupKDF {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "unsupported backup KDF"}
	}
	if strings.TrimSpace(passphrase) == "" {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "encrypted backup requires passphrase"}
	}
	kdfTime := env.KDFTime
	if kdfTime == 0 {
		kdfTime = encryptedBackupKDFTime
	}
	kdfMem := env.KDFMemory
	if kdfMem == 0 {
		kdfMem = encryptedBackupKDFMemory
	}
	kdfThreads := env.KDFThreads
	if kdfThreads == 0 {
		kdfThreads = encryptedBackupKDFThreads
	}
	// Bound KDF parameters strictly to avoid CPU/memory DoS from untrusted files.
	if kdfTime < 1 || kdfTime > 10 || kdfMem < 8*1024 || kdfMem > 256*1024 || kdfThreads < 1 || kdfThreads > 8 {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "encrypted backup KDF parameters out of safe bounds"}
	}
	salt, err := base64.StdEncoding.DecodeString(env.Salt)
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "invalid encrypted backup salt"}
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "invalid encrypted backup nonce"}
	}
	ciphertext, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertext) < 16 {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "invalid encrypted backup ciphertext"}
	}

	backupArgonSem <- struct{}{}
	key := argon2.IDKey([]byte(passphrase), salt, kdfTime, kdfMem, kdfThreads, 32)
	<-backupArgonSem
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(encryptedBackupFormat+":v5"))
	if err != nil {
		return nil, &httpError{Code: http.StatusBadRequest, Msg: "口令错误或加密备份文件已损坏"}
	}
	return plaintext, nil
}

// unwrapBackupPayload transparently decrypts v5 encrypted backup envelopes (either raw with
// X-Backup-Passphrase header or wrapped in {"passphrase":"...","envelope":{...}}) while leaving
// legacy plaintext v3/v4 backups untouched.
func unwrapBackupPayload(raw []byte, headerPassphrase string) ([]byte, bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, false, &httpError{Code: http.StatusBadRequest, Msg: "empty backup payload"}
	}
	var wrapper struct {
		Passphrase string                   `json:"passphrase"`
		Envelope   *EncryptedBackupEnvelope `json:"envelope"`
		Format     string                   `json:"format"`
		Version    int                      `json:"version"`
		KDF        string                   `json:"kdf"`
		KDFTime    uint32                   `json:"kdf_time"`
		KDFMemory  uint32                   `json:"kdf_memory"`
		KDFThreads uint8                    `json:"kdf_threads"`
		Salt       string                   `json:"salt"`
		Nonce      string                   `json:"nonce"`
		Ciphertext string                   `json:"ciphertext"`
	}
	if err := json.Unmarshal(trimmed, &wrapper); err == nil {
		if wrapper.Envelope != nil && wrapper.Envelope.Format == encryptedBackupFormat {
			pass := wrapper.Passphrase
			if pass == "" {
				pass = headerPassphrase
			}
			plain, decErr := decryptBackupEnvelope(*wrapper.Envelope, pass)
			return plain, true, decErr
		}
		if wrapper.Format == encryptedBackupFormat && wrapper.Version == encryptedBackupVersion {
			env := EncryptedBackupEnvelope{
				Format:     wrapper.Format,
				Version:    wrapper.Version,
				KDF:        wrapper.KDF,
				KDFTime:    wrapper.KDFTime,
				KDFMemory:  wrapper.KDFMemory,
				KDFThreads: wrapper.KDFThreads,
				Salt:       wrapper.Salt,
				Nonce:      wrapper.Nonce,
				Ciphertext: wrapper.Ciphertext,
			}
			plain, decErr := decryptBackupEnvelope(env, headerPassphrase)
			return plain, true, decErr
		}
	}
	return trimmed, false, nil
}

func validateFullBackup(b FullBackup) error {
	if b.Version != 3 && b.Version != 4 {
		return &httpError{Code: http.StatusBadRequest, Msg: "unsupported backup version (expected 3 or 4)"}
	}
	if b.Preferences != nil {
		if err := b.Preferences.Validate(); err != nil {
			return err
		}
	}
	if b.Health != nil && b.Health.URL != "" {
		if _, err := validateHTTPSProbeURL(b.Health.URL); err != nil {
			return err
		}
		if b.Health.IntervalSeconds != 0 && b.Health.IntervalSeconds < 30 {
			return &httpError{Code: http.StatusBadRequest, Msg: "health interval must be >= 30s"}
		}
	}
	return nil
}

func (s *Server) buildFullBackup(include []string) (FullBackup, error) {
	inc := map[string]bool{}
	for _, part := range include {
		if key := strings.ToLower(strings.TrimSpace(part)); key != "" {
			inc[key] = true
		}
	}
	includeAll := len(inc) == 0
	want := func(keys ...string) bool {
		if includeAll {
			return true
		}
		for _, k := range keys {
			if inc[k] {
				return true
			}
		}
		return false
	}

	payload := FullBackup{Version: 4}
	if want("nodes") {
		payload.Nodes = s.store.List()
		if payload.Nodes == nil {
			payload.Nodes = []*config.Node{}
		}
	}
	if want("listeners") {
		payload.Listeners = s.store.ListListeners()
		if payload.Listeners == nil {
			payload.Listeners = []*config.ListenConfig{}
		}
	}
	if want("groups") {
		groups, err := s.store.ListGroups()
		if err != nil {
			return FullBackup{}, err
		}
		payload.Groups = groups
	}
	if want("subscriptions", "subs") {
		subs, err := s.subscriptions()
		if err != nil {
			return FullBackup{}, err
		}
		payload.Subscriptions = subs
	}
	if want("routing", "routing_profile", "dns") {
		routing, err := s.routingProfile()
		if err != nil {
			return FullBackup{}, err
		}
		ruleSets, err := s.effectiveRuleSets()
		if err != nil {
			return FullBackup{}, err
		}
		payload.RoutingProfile = routing
		payload.RuleSets = ruleSets
		if metas, mErr := s.listProfileMetas(); mErr == nil && len(metas) > 0 {
			named := make([]BackupNamedProfile, 0, len(metas))
			for _, m := range metas {
				doc, _ := s.routingProfileByID(m.ID)
				named = append(named, BackupNamedProfile{Meta: m, Profile: doc})
			}
			payload.RoutingProfiles = named
			payload.ActiveProfileID = s.activeRoutingProfileID()
		}
	}
	if want("settings", "preferences", "health") {
		prefs, _ := s.preferences()
		health, _ := s.healthSettings()
		payload.Preferences = &prefs
		payload.Health = &health
	}
	return payload, nil
}

func (s *Server) handleBackupExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Passphrase     string   `json:"passphrase"`
		Include        []string `json:"include,omitempty"`
		AllowPlaintext bool     `json:"allow_plaintext,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	payload, err := s.buildFullBackup(req.Include)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(req.Passphrase) == "" {
		if !req.AllowPlaintext {
			http.Error(w, "请提供至少 8 位加密口令，或显式确认明文导出", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="prismray-backup-v4.json"`)
		_ = json.NewEncoder(w).Encode(payload)
		return
	}
	plainJSON, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	env, err := encryptBackupPayload(plainJSON, req.Passphrase)
	if err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="prismray-backup-v5.enc.json"`)
	_ = json.NewEncoder(w).Encode(env)
}

var backupArgonSem = make(chan struct{}, 2)

func (s *Server) captureBackupRollback() func() {
	prevNodes := s.store.List()
	prevListeners := s.store.ListListeners()
	prevGroups, _ := s.store.ListGroups()
	prevSubs, _ := s.subscriptions()
	prevRuleSets, _ := s.store.ListRuleSets()
	prevRouting, _ := s.routingProfile()
	prevProfileMetas, _ := s.listProfileMetas()
	prevActiveProfileID := s.activeRoutingProfileID()
	prevProfileDocs := make(map[string]ruleset.RoutingProfile, len(prevProfileMetas))
	for _, m := range prevProfileMetas {
		if doc, pErr := s.routingProfileByID(m.ID); pErr == nil {
			prevProfileDocs[m.ID] = doc
		}
	}
	var prevPrefs json.RawMessage
	hasPrevPrefs, _ := s.store.GetSetting("app.preferences", &prevPrefs)
	var prevHealth json.RawMessage
	hasPrevHealth, _ := s.store.GetSetting("health.settings", &prevHealth)

	return func() {
		_ = s.store.Restore(prevNodes, prevListeners)
		_ = s.store.ReplaceGroups(prevGroups)
		if curSubs, err := s.subscriptions(); err == nil {
			for _, sub := range curSubs {
				_ = s.store.DeleteSubscription(sub.ID)
			}
		}
		for _, sub := range prevSubs {
			_ = s.store.SaveSubscription(sub)
		}
		if curRS, err := s.store.ListRuleSets(); err == nil {
			for _, rs := range curRS {
				_ = s.store.DeleteRuleSet(rs.ID)
			}
		}
		for _, rs := range prevRuleSets {
			_ = s.store.SaveRuleSet(rs)
		}
		if curMetas, err := s.listProfileMetas(); err == nil {
			for _, m := range curMetas {
				if _, ok := prevProfileDocs[m.ID]; !ok {
					_ = s.store.DeleteRoutingProfile(m.ID)
				}
			}
		}
		for id, doc := range prevProfileDocs {
			_ = s.saveRoutingProfileByID(id, doc)
		}
		if len(prevProfileMetas) > 0 {
			_ = s.saveProfileMetas(prevProfileMetas)
		}
		s.setActiveRoutingProfileID(prevActiveProfileID)
		_ = s.store.PutSetting(activeProfileSettingKey, prevActiveProfileID)
		_ = s.saveRoutingProfile(prevRouting)
		if hasPrevPrefs {
			_ = s.store.PutSetting("app.preferences", prevPrefs)
		} else {
			_ = s.store.DeleteSetting("app.preferences")
		}
		if hasPrevHealth {
			_ = s.store.PutSetting("health.settings", prevHealth)
		} else {
			_ = s.store.DeleteSetting("health.settings")
		}
	}
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		includeRaw := strings.TrimSpace(r.URL.Query().Get("include"))
		var include []string
		if includeRaw != "" {
			include = strings.Split(includeRaw, ",")
		}
		payload, err := s.buildFullBackup(include)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="prismray-backup-v4.json"`)
		_ = json.NewEncoder(w).Encode(payload)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("mode")), "merge") {
		s.handleMergeBackup(w, r)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plainRaw, wasEncrypted, err := unwrapBackupPayload(raw, r.Header.Get("X-Backup-Passphrase"))
	if err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()
	if s.ensureOrchestrator().Status().Running {
		http.Error(w, "请先断开连接再恢复备份", http.StatusConflict)
		return
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(plainRaw, &top); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	hasSection := func(key string) bool {
		rawVal, ok := top[key]
		if !ok {
			return false
		}
		trimmed := bytes.TrimSpace(rawVal)
		return len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null"))
	}

	var b FullBackup
	if err := json.Unmarshal(plainRaw, &b); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := validateFullBackup(b); err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}

	isZeroRoutingProfile := func(rp ruleset.RoutingProfile) bool {
		return strings.TrimSpace(rp.Mode) == "" &&
			!rp.BypassLAN && !rp.BypassCN && !rp.BlockAds && !rp.FakeIP &&
			rp.HijackDNS == nil && rp.KillSwitch == nil &&
			strings.TrimSpace(rp.LocalDNS) == "" && strings.TrimSpace(rp.RemoteDNS) == "" &&
			strings.TrimSpace(rp.LogLevel) == "" &&
			len(rp.CustomRules) == 0 && len(rp.FakeIPFilter) == 0 &&
			strings.TrimSpace(rp.PerAppMode) == "" && len(rp.PerAppPackages) == 0 &&
			!rp.AllowLANBroadcast
	}

	// Capture complete rollback snapshot before applying mutations.
	prevNodes := s.store.List()
	prevListeners := s.store.ListListeners()
	prevGroups, prevGroupsErr := s.store.ListGroups()
	prevSubs, _ := s.subscriptions()
	rollback := s.captureBackupRollback()

	hasNodes := hasSection("nodes")
	hasListeners := hasSection("listeners")
	if hasNodes || hasListeners {
		restoreNodes := prevNodes
		if hasNodes {
			restoreNodes = b.Nodes
		}
		restoreListeners := prevListeners
		if hasListeners {
			restoreListeners = b.Listeners
		}
		if err := s.store.Restore(restoreNodes, restoreListeners); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if hasNodes && !hasSection("groups") && prevGroupsErr == nil && len(prevGroups) > 0 {
			validNodeIDs := make(map[string]bool, len(restoreNodes))
			for _, n := range restoreNodes {
				if n != nil && n.ID != "" {
					validNodeIDs[n.ID] = true
				}
			}
			validGroupIDs := make(map[string]bool, len(prevGroups))
			for _, g := range prevGroups {
				if g.ID != "" {
					validGroupIDs[g.ID] = true
				}
			}
			preservedGroups := make([]storage.Group, 0, len(prevGroups))
			for _, g := range prevGroups {
				filteredMembers := make([]string, 0, len(g.NodeIDs))
				for _, mid := range g.NodeIDs {
					if validNodeIDs[mid] {
						filteredMembers = append(filteredMembers, mid)
					}
				}
				g.NodeIDs = filteredMembers
				if g.SelectedNodeID != "" && !validNodeIDs[g.SelectedNodeID] {
					g.SelectedNodeID = ""
					g.ManualPin = false
				}
				if g.DetourID != "" && !validNodeIDs[g.DetourID] && !validGroupIDs[g.DetourID] {
					g.DetourID = ""
				}
				preservedGroups = append(preservedGroups, g)
			}
			if err := s.store.ReplaceGroups(preservedGroups); err != nil {
				rollback()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	if hasSection("groups") {
		if err := s.store.ReplaceGroups(b.Groups); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	if hasSection("subscriptions") {
		incomingSubIDs := make(map[string]bool, len(b.Subscriptions))
		for _, sub := range b.Subscriptions {
			incomingSubIDs[sub.ID] = true
		}
		for _, oldSub := range prevSubs {
			if !incomingSubIDs[oldSub.ID] {
				if err := s.store.DeleteSubscription(oldSub.ID); err != nil {
					rollback()
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
		for _, sub := range b.Subscriptions {
			if err := s.store.SaveSubscription(sub); err != nil {
				rollback()
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
	}
	if b.Version >= 4 {
		if hasSection("routing_profiles") && len(b.RoutingProfiles) > 0 {
			metas := make([]RoutingProfileMeta, 0, len(b.RoutingProfiles))
			metaIDs := make(map[string]bool, len(b.RoutingProfiles))
			for _, np := range b.RoutingProfiles {
				pid := strings.TrimSpace(np.Meta.ID)
				if pid == "" || strings.TrimSpace(np.Meta.Name) == "" {
					continue
				}
				if err := s.saveRoutingProfileByID(pid, np.Profile); err != nil {
					rollback()
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				metas = append(metas, np.Meta)
				metaIDs[pid] = true
			}
			if len(metas) > 0 {
				if err := s.saveProfileMetas(metas); err != nil {
					rollback()
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				act := strings.TrimSpace(b.ActiveProfileID)
				if act == "" || !metaIDs[act] {
					act = metas[0].ID
				}
				s.setActiveRoutingProfileID(act)
				if err := s.store.PutSetting(activeProfileSettingKey, act); err != nil {
					rollback()
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
		if hasSection("routing_profile") && !isZeroRoutingProfile(b.RoutingProfile) {
			if err := s.saveRoutingProfile(b.RoutingProfile); err != nil {
				rollback()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
		if hasSection("rule_sets") {
			for _, rs := range b.RuleSets {
				if strings.TrimSpace(rs.ID) == "" || strings.TrimSpace(rs.Tag) == "" {
					continue
				}
				cleanPath, pErr := sanitizeRuleSetPath(s.ruleSetDir(), rs.Tag, rs.LocalPath)
				if pErr != nil {
					cleanPath, pErr = sanitizeRuleSetPath(s.ruleSetDir(), rs.Tag, "")
					if pErr != nil {
						continue
					}
				}
				cleanURL := rs.URL
				if rs.SourceType == "remote" {
					if validatedURL, uErr := validateRuleSetURL(rs.URL); uErr == nil {
						cleanURL = validatedURL
					} else {
						continue
					}
				}
				if err := s.store.SaveRuleSet(storage.RuleSetRecord{
					ID:             strings.TrimSpace(rs.ID),
					Tag:            strings.TrimSpace(rs.Tag),
					Format:         rs.Format,
					SourceType:     rs.SourceType,
					URL:            cleanURL,
					LocalPath:      cleanPath,
					UpdateInterval: rs.UpdateInterval,
					Enabled:        rs.Enabled,
					LastSyncedAt:   rs.LastSyncedAt,
					SizeBytes:      rs.SizeBytes,
				}); err != nil {
					rollback()
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}
	}
	if b.Preferences != nil {
		if err := s.store.PutSetting("app.preferences", *b.Preferences); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if b.Version == 3 {
			if err := s.saveRoutingProfile(syncRoutingFromPreferences(ruleset.DefaultRoutingProfile(), *b.Preferences)); err != nil {
				rollback()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	if b.Health != nil {
		if err := s.store.PutSetting("health.settings", *b.Health); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":          b.Version,
		"encrypted":        wasEncrypted,
		"nodes":            len(b.Nodes),
		"listeners":        len(b.Listeners),
		"groups":           len(b.Groups),
		"subscriptions":    len(b.Subscriptions),
		"restart_required": false,
	})
}

func decodeMergePayload(raw []byte) (FullBackup, []byte, error) {
	var b FullBackup
	if err := json.Unmarshal(raw, &b); err != nil {
		return FullBackup{}, nil, err
	}
	if b.Version == 0 {
		b.Version = 4
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return FullBackup{}, nil, err
	}

	if rpRaw, ok := top["routing_profile"]; ok {
		trimmed := bytes.TrimSpace(rpRaw)
		if len(trimmed) > 0 && !bytes.Equal(trimmed, []byte("null")) {
			return b, trimmed, nil
		}
	}

	// Support standalone RoutingProfile JSON files imported directly into the merge endpoint.
	for _, key := range []string{"custom_rules", "local_dns", "remote_dns"} {
		if _, ok := top[key]; ok {
			var standalone ruleset.RoutingProfile
			if err := json.Unmarshal(raw, &standalone); err != nil {
				return FullBackup{}, nil, err
			}
			b.RoutingProfile = standalone
			return b, raw, nil
		}
	}
	return b, nil, nil
}

func (s *Server) validateMergeBundle(b *FullBackup) error {
	if err := validateFullBackup(*b); err != nil {
		return err
	}

	knownNodes := map[string]bool{}
	for _, existing := range s.store.List() {
		if existing != nil && existing.ID != "" {
			knownNodes[existing.ID] = true
		}
	}
	for _, n := range b.Nodes {
		if n == nil {
			return &httpError{Code: http.StatusBadRequest, Msg: "invalid null node in merge bundle"}
		}
		if strings.TrimSpace(n.ID) == "" {
			n.ID = newRandomID("node-")
		}
		if err := n.Validate(); err != nil {
			return &httpError{Code: http.StatusBadRequest, Msg: err.Error()}
		}
		knownNodes[n.ID] = true
	}

	for _, l := range b.Listeners {
		if l == nil {
			return &httpError{Code: http.StatusBadRequest, Msg: "invalid null listener in merge bundle"}
		}
		if strings.TrimSpace(l.ID) == "" {
			l.ID = newRandomID("lis-")
		}
		if l.Port < 1 || l.Port > 65535 || l.Address == "" ||
			(l.Protocol != "http" && l.Protocol != "socks" && l.Protocol != "mixed") {
			return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("invalid listener %q", l.ID)}
		}
		for _, nid := range l.NodeIDs {
			if !knownNodes[nid] {
				return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("listener %q references missing node %q", l.ID, nid)}
			}
		}
	}

	for _, g := range b.Groups {
		if strings.TrimSpace(g.ID) == "" || strings.TrimSpace(g.Name) == "" {
			return &httpError{Code: http.StatusBadRequest, Msg: "group ID and name are required"}
		}
		switch storage.CanonicalGroupStrategy(g.Strategy) {
		case "selector", "urltest", "failover", "loadbalance":
		default:
			return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("invalid group strategy %q", g.Strategy)}
		}
		for _, nid := range g.NodeIDs {
			if !knownNodes[nid] {
				return &httpError{Code: http.StatusBadRequest, Msg: fmt.Sprintf("group %q references missing node %q", g.ID, nid)}
			}
		}
	}
	return nil
}

func mergeRoutingProfile(existing ruleset.RoutingProfile, routingRaw []byte) (ruleset.RoutingProfile, error) {
	prevRules := existing.CustomRules
	merged := existing
	if existing.HijackDNS != nil {
		v := *existing.HijackDNS
		merged.HijackDNS = &v
	}
	if existing.KillSwitch != nil {
		v := *existing.KillSwitch
		merged.KillSwitch = &v
	}
	if len(existing.FakeIPFilter) > 0 {
		merged.FakeIPFilter = append([]string(nil), existing.FakeIPFilter...)
	}
	merged.CustomRules = nil
	if err := json.Unmarshal(routingRaw, &merged); err != nil {
		return ruleset.RoutingProfile{}, err
	}

	seenIDs := map[string]bool{}
	seenSignatures := map[string]bool{}
	for _, r := range merged.CustomRules {
		if id := strings.TrimSpace(r.ID); id != "" {
			seenIDs[id] = true
		}
		if sig, err := json.Marshal(r); err == nil {
			seenSignatures[string(sig)] = true
		}
	}
	for _, old := range prevRules {
		if id := strings.TrimSpace(old.ID); id != "" && seenIDs[id] {
			continue
		}
		if sig, err := json.Marshal(old); err == nil && seenSignatures[string(sig)] {
			continue
		}
		merged.CustomRules = append(merged.CustomRules, old)
	}
	merged.Normalize()
	return merged, nil
}

func (s *Server) handleMergeBackup(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	plainRaw, wasEncrypted, err := unwrapBackupPayload(raw, r.Header.Get("X-Backup-Passphrase"))
	if err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}
	b, routingRaw, err := decodeMergePayload(plainRaw)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if err := s.validateMergeBundle(&b); err != nil {
		respondError(w, err, http.StatusBadRequest)
		return
	}

	rollback := s.captureBackupRollback()

	for _, n := range b.Nodes {
		if s.store.Get(n.ID) != nil {
			if err := s.store.Update(n); err != nil {
				rollback()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if err := s.store.Add(n); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	existingListeners := map[string]bool{}
	for _, l := range s.store.ListListeners() {
		if l != nil && l.ID != "" {
			existingListeners[l.ID] = true
		}
	}
	for _, l := range b.Listeners {
		if existingListeners[l.ID] {
			if err := s.store.UpdateListener(l); err != nil {
				rollback()
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if err := s.store.AddListener(l); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	for _, g := range b.Groups {
		if err := s.store.SaveGroup(g); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, sub := range b.Subscriptions {
		if err := s.store.SaveSubscription(sub); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	for _, rs := range b.RuleSets {
		rsID := strings.TrimSpace(rs.ID)
		rsTag := strings.TrimSpace(rs.Tag)
		if rsID == "" || rsTag == "" ||
			strings.ContainsAny(rsID, "/\\") || strings.Contains(rsID, "..") ||
			strings.ContainsAny(rsTag, "/\\") || strings.Contains(rsTag, "..") {
			continue
		}
		sourceType := strings.TrimSpace(rs.SourceType)
		if sourceType == "" {
			sourceType = "remote"
		}
		cleanURL := ""
		cleanPath := ""
		switch sourceType {
		case "remote":
			u, uErr := validateRuleSetURL(rs.URL)
			if uErr != nil {
				rollback()
				http.Error(w, "invalid ruleset URL in merge backup: "+uErr.Error(), http.StatusBadRequest)
				return
			}
			cleanURL = u
			p, pErr := sanitizeRuleSetPath(s.ruleSetDir(), rsTag, rs.LocalPath)
			if pErr != nil {
				rollback()
				http.Error(w, "invalid ruleset local_path in merge backup: "+pErr.Error(), http.StatusBadRequest)
				return
			}
			cleanPath = p
		case "local":
			p, pErr := sanitizeRuleSetPath(s.ruleSetDir(), rsTag, rs.LocalPath)
			if pErr != nil {
				rollback()
				http.Error(w, "invalid ruleset local_path in merge backup: "+pErr.Error(), http.StatusBadRequest)
				return
			}
			cleanPath = p
		case "inline":
			cleanPath = ""
		default:
			rollback()
			http.Error(w, "invalid ruleset source_type in merge backup", http.StatusBadRequest)
			return
		}
		format := strings.TrimSpace(rs.Format)
		if format != "binary" && format != "source" {
			format = "binary"
		}
		_ = s.store.SaveRuleSet(storage.RuleSetRecord{
			ID:             rsID,
			Tag:            rsTag,
			Format:         format,
			SourceType:     sourceType,
			URL:            cleanURL,
			LocalPath:      cleanPath,
			UpdateInterval: rs.UpdateInterval,
			Enabled:        rs.Enabled,
			LastSyncedAt:   rs.LastSyncedAt,
			SizeBytes:      rs.SizeBytes,
		})
	}

	customCount := 0
	if len(routingRaw) > 0 {
		cur, _ := s.routingProfile()
		merged, err := mergeRoutingProfile(cur, routingRaw)
		if err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := s.saveRoutingProfile(merged); err != nil {
			rollback()
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		customCount = len(merged.CustomRules)
	} else {
		cur, _ := s.routingProfile()
		customCount = len(cur.CustomRules)
	}

	if b.Preferences != nil {
		_ = s.store.PutSetting("app.preferences", *b.Preferences)
	}
	if b.Health != nil {
		_ = s.store.PutSetting("health.settings", *b.Health)
	}

	if s.ensureOrchestrator().Status().Running {
		rs := s.runtimeState()
		if _, err := s.reconcileRuntime(r.Context(), rs.activeNodeID, rs.activeGroupID, rs.tunEnabled); err != nil {
			rollback()
			respondError(w, err, http.StatusBadGateway)
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"mode":             "merge",
		"version":          b.Version,
		"encrypted":        wasEncrypted,
		"nodes":            len(b.Nodes),
		"groups":           len(b.Groups),
		"custom_rules":     customCount,
		"restart_required": false,
	})
}

// RecoverBackup cleans or completes interrupted SQLite backup marker files before opening the database.
func RecoverBackup(cfg *appconfig.Config) error {
	if cfg == nil {
		return nil
	}
	dir := cfg.DataDir()
	if dir == "" {
		return nil
	}
	backupMarker := filepath.Join(dir, "prismray.db.bak")
	if _, err := os.Stat(backupMarker); err == nil {
		_ = os.Remove(backupMarker)
	}
	return nil
}
