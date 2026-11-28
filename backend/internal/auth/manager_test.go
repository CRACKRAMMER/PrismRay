// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/config"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

func TestInitializeLoginAndEncryptedNodeStorage(t *testing.T) {
	store, err := storage.NewStore(filepath.Join(t.TempDir(), "prismray.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.Add(&config.Node{ID: "n1", Protocol: config.ProtocolTrojan, Address: "example.com", Port: 443, Password: "top-secret"}); err != nil {
		t.Fatal(err)
	}
	m, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	if err = m.Initialize("correct horse battery", m.BootstrapToken(), false); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "top-secret") {
		t.Fatal("node secret persisted in plaintext")
	}
	m.Lock()
	if store.Get("n1") != nil {
		t.Fatal("read encrypted node while locked")
	}
	if _, err = m.Login("wrong password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	token, err := m.Login("correct horse battery")
	if err != nil || !m.Valid(token) || store.Get("n1").Password != "top-secret" {
		t.Fatalf("login did not unlock data: %v", err)
	}
}

func TestInitializationRequiresTokenAndStrongEnoughPassword(t *testing.T) {
	store, err := storage.NewStore(filepath.Join(t.TempDir(), "prismray.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	m, _ := New(store)
	if err = m.Initialize("short", m.BootstrapToken(), false); err == nil {
		t.Fatal("short password accepted")
	}
	if err = m.Initialize("long enough", "wrong", false); err == nil {
		t.Fatal("wrong bootstrap token accepted")
	}
}

func TestDesktopAutoUnlockAndOptionalPasswordLockToggle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "prismray.db")
	keySlot := filepath.Join(dir, ".device.key")

	kr := keyring.New(keyring.Options{FallbackPath: keySlot, DisableOSKeyring: true})
	store, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewWithOptions(store, Options{Mode: ModeDesktop, Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	init, unlocked := m.Status()
	if !init || !unlocked || m.PasswordLocked() {
		t.Fatalf("expected desktop auto-unlock, got init=%v unlocked=%v lock=%v", init, unlocked, m.PasswordLocked())
	}
	if err = store.Add(&config.Node{ID: "n1", Protocol: config.ProtocolTrojan, Address: "example.com", Port: 443, Password: "auto-secret"}); err != nil {
		t.Fatal(err)
	}
	_ = store.Close()

	// Reload on restart without password: still auto-unlocked and decrypts existing node.
	store2, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	kr2 := keyring.New(keyring.Options{FallbackPath: keySlot, DisableOSKeyring: true})
	m2, err := NewWithOptions(store2, Options{Mode: ModeDesktop, Keyring: kr2})
	if err != nil {
		t.Fatal(err)
	}
	if n := store2.Get("n1"); n == nil || n.Password != "auto-secret" {
		t.Fatalf("failed to decrypt node on auto-unlock restart: %+v", n)
	}

	// Enable optional Startup Password Lock -> deletes device key slot, preserves nodes.
	if err = m2.EnablePasswordLock("custom-lock-password"); err != nil {
		t.Fatalf("EnablePasswordLock failed: %v", err)
	}
	if !m2.PasswordLocked() {
		t.Fatal("expected password lock enabled")
	}
	if _, found, _ := kr2.Load(); found {
		t.Fatal("device key slot should be removed when password lock is enabled")
	}
	_ = store2.Close()

	// Next restart requires password login.
	store3, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store3.Close()
	m3, err := NewWithOptions(store3, Options{Mode: ModeAndroid, Keyring: kr2})
	if err != nil {
		t.Fatal(err)
	}
	init, unlocked = m3.Status()
	if !init || unlocked || !m3.PasswordLocked() {
		t.Fatalf("expected locked restart, got init=%v unlocked=%v lock=%v", init, unlocked, m3.PasswordLocked())
	}
	if store3.Get("n1") != nil {
		t.Fatal("secret node readable while locked")
	}
	if _, err = m3.Login("custom-lock-password"); err != nil {
		t.Fatalf("login failed after enabling password lock: %v", err)
	}
	if n := store3.Get("n1"); n == nil || n.Password != "auto-secret" {
		t.Fatalf("node data lost across password lock toggle: %+v", n)
	}

	// Disable password lock -> restores passwordless key slot.
	if err = m3.DisablePasswordLock("custom-lock-password"); err != nil {
		t.Fatalf("DisablePasswordLock failed: %v", err)
	}
	if m3.PasswordLocked() {
		t.Fatal("expected password lock disabled")
	}
	if _, found, _ := kr2.Load(); !found {
		t.Fatal("expected device key restored")
	}
}

func TestPasswordlessKeyResetSalvagesNodesFromSingBoxConfig(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "prismray.db")
	keySlot := filepath.Join(dir, ".device.key")
	sbPath := filepath.Join(dir, "sing-box.json")

	// 1. Seed initial store with old device key + VLESS Reality node + subscription + group
	krOld := keyring.New(keyring.Options{FallbackPath: keySlot, DisableOSKeyring: true})
	store1, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = NewWithOptions(store1, Options{Mode: ModeDesktop, Keyring: krOld}); err != nil {
		t.Fatal(err)
	}
	node := &config.Node{
		ID:          "us-gcp-vless",
		SubID:       "sub-1",
		Name:        "US GCP Original",
		UserAlias:   "Custom Alias US",
		Favorite:    true,
		Protocol:    config.ProtocolVLESS,
		Address:     "198.51.100.10",
		Port:        443,
		UUID:        "11111111-1111-4111-8111-111111111111",
		Flow:        "xtls-rprx-vision",
		Security:    "reality",
		Sni:         "www.example.com",
		Fingerprint: "chrome",
		PublicKey:   "pub-key-123",
		ShortID:     "abcd1234",
		Latency:     42,
	}
	if err = store1.Add(node); err != nil {
		t.Fatal(err)
	}
	if err = store1.SaveSubscription(storage.SubscriptionRecord{
		ID:            "sub-1",
		Name:          "Provider A",
		URL:           "https://sub.example.com/feed",
		TotalBytes:    1024,
		ImportedCount: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err = store1.SaveGroup(storage.Group{
		ID:       "grp-1",
		Name:     "US Group",
		Strategy: "selector",
		NodeIDs:  []string{"us-gcp-vless"},
	}); err != nil {
		t.Fatal(err)
	}
	_ = store1.Close()

	// Write runtime sing-box.json matching what compiled runtime generates
	sbCfg := `{
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {
      "type": "vless",
      "tag": "node-us-gcp-vless",
      "server": "198.51.100.10",
      "server_port": 443,
      "uuid": "11111111-1111-4111-8111-111111111111",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "www.example.com",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": "pub-key-123", "short_id": "abcd1234"}
      }
    }
  ]
}`
	if err = os.WriteFile(sbPath, []byte(sbCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	// 2. Simulate keyring wipe/replacement (e.g. external key pollution)
	if err = krOld.Delete(); err != nil {
		t.Fatal(err)
	}
	krNew := keyring.New(keyring.Options{FallbackPath: keySlot, DisableOSKeyring: true})
	store2, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer store2.Close()

	m2, err := NewWithOptions(store2, Options{
		Mode:                     ModeDesktop,
		Keyring:                  krNew,
		RuntimeSingBoxConfigPath: sbPath,
	})
	if err != nil {
		t.Fatalf("expected passwordless mismatch self-healing to succeed, got: %v", err)
	}
	if _, unlocked := m2.Status(); !unlocked {
		t.Fatal("expected salvaged store to be unlocked")
	}

	got := store2.Get("us-gcp-vless")
	if got == nil {
		t.Fatal("salvaged node missing from store")
	}
	if got.UUID != node.UUID || got.PublicKey != node.PublicKey || got.ShortID != node.ShortID || got.Flow != node.Flow {
		t.Fatalf("salvaged credentials mismatch: %+v", got)
	}
	if got.Name != node.Name || got.UserAlias != node.UserAlias || !got.Favorite || got.SubID != "sub-1" || got.Latency != 42 {
		t.Fatalf("salvaged metadata mismatch: %+v", got)
	}
	groups, err := store2.ListGroups()
	if err != nil || len(groups) != 1 || len(groups[0].NodeIDs) != 1 || groups[0].NodeIDs[0] != "us-gcp-vless" {
		t.Fatalf("expected group membership preserved, got %+v (%v)", groups, err)
	}
	subs, err := store2.ListSubscriptions()
	if err != nil || len(subs) != 1 || subs[0].Name != "Provider A" || subs[0].TotalBytes != 1024 || subs[0].URL != "" {
		t.Fatalf("expected subscription quota preserved and sealed URL reset, got %+v (%v)", subs, err)
	}
	matches, _ := filepath.Glob(dbPath + ".bak.*")
	if len(matches) != 1 {
		t.Fatalf("expected backup database snapshot created, got %v", matches)
	}
}

func TestDesktopBiometricUnlockLifecycle(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "prismray.db")
	keySlot := filepath.Join(dir, ".device.key")

	st, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	kr := keyring.New(keyring.Options{FallbackPath: keySlot, DisableOSKeyring: true})
	m, err := NewWithOptions(st, Options{Mode: ModeDesktop, Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	// Biometric unlock requires password lock first.
	if err := m.SetBiometricUnlock(true, "StrongPass123!"); err == nil {
		t.Fatal("expected biometric enable without password lock to fail")
	}
	if err := m.EnablePasswordLock("StrongPass123!"); err != nil {
		t.Fatalf("EnablePasswordLock failed: %v", err)
	}
	// Wrong password cannot enable biometric unlock.
	if err := m.SetBiometricUnlock(true, "WrongPass999!"); err == nil {
		t.Fatal("expected biometric enable with wrong password to fail")
	}
	if err := m.SetBiometricUnlock(true, "StrongPass123!"); err != nil {
		t.Fatalf("SetBiometricUnlock(true) failed: %v", err)
	}
	if !m.BiometricEnabled() {
		t.Fatal("expected BiometricEnabled() == true")
	}

	// Simulate app restart (locked state) and unlock via biometric slot.
	m.Lock()
	if _, unlocked := m.Status(); unlocked {
		t.Fatal("expected locked state after Lock()")
	}
	tok, err := m.UnlockWithBiometric()
	if err != nil || tok == "" {
		t.Fatalf("UnlockWithBiometric failed: %v", err)
	}
	if _, unlocked := m.Status(); !unlocked {
		t.Fatal("expected unlocked state after UnlockWithBiometric()")
	}

	// Disabling password lock cleans up biometric state and slot.
	if err := m.DisablePasswordLock("StrongPass123!"); err != nil {
		t.Fatalf("DisablePasswordLock failed: %v", err)
	}
	if m.BiometricEnabled() {
		t.Fatal("expected BiometricEnabled() == false after disabling password lock")
	}
	if _, found, _ := kr.Derive("biometric").Load(); found {
		t.Fatal("expected biometric keyring slot deleted after disabling password lock")
	}
}

func TestAndroidHardwareBiometricKEKLifecycleAndPasswordChange(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "prismray.db")
	keySlot := filepath.Join(dir, ".device.key")
	legacyPlain := keySlot + ".biometric"

	// Simulate an existing legacy plaintext .device.key.biometric left over from older versions.
	if err := os.WriteFile(legacyPlain, []byte("legacy-plaintext-key"), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := storage.NewStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	kr := keyring.New(keyring.Options{FallbackPath: keySlot, DisableOSKeyring: true})
	m, err := NewWithOptions(st, Options{Mode: ModeAndroid, Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(legacyPlain); !os.IsNotExist(statErr) {
		t.Fatal("expected Android startup to delete legacy plaintext .device.key.biometric")
	}

	if err := m.EnablePasswordLock("InitialPass123!"); err != nil {
		t.Fatalf("EnablePasswordLock failed: %v", err)
	}
	kek, err := m.SetBiometricUnlockHardware(true, "InitialPass123!")
	if err != nil || kek == "" {
		t.Fatalf("SetBiometricUnlockHardware failed: %v", err)
	}
	if _, statErr := os.Stat(legacyPlain); !os.IsNotExist(statErr) {
		t.Fatal("hardware biometric enrollment must not create plaintext .device.key.biometric")
	}

	// Changing password must preserve hardware biometric wrapping.
	if err := m.ChangePassword("InitialPass123!", "RotatedPass456!"); err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}
	m.Lock()
	if _, err := m.UnlockWithBiometricKEK("invalid-base64"); err == nil {
		t.Fatal("expected invalid KEK to fail")
	}
	tok, err := m.UnlockWithBiometricKEK(kek)
	if err != nil || tok == "" {
		t.Fatalf("expected hardware KEK unlock to succeed after ChangePassword, got err=%v", err)
	}
	// Legacy keyring-based UnlockWithBiometric must always be rejected on Android.
	m.Lock()
	if _, err := m.UnlockWithBiometric(); err == nil {
		t.Fatal("expected UnlockWithBiometric without hardware KEK to fail on Android")
	}
}

func TestAuthHardeningDoubleEnableAndTryLockAndLockout(t *testing.T) {
	dir := t.TempDir()
	st, err := storage.NewStore(filepath.Join(dir, "prismray.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	kr := keyring.New(keyring.Options{FallbackPath: filepath.Join(dir, ".device.key"), DisableOSKeyring: true})
	m, err := NewWithOptions(st, Options{Mode: ModeDesktop, Keyring: kr})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.EnablePasswordLock("StrongPass123!"); err != nil {
		t.Fatalf("EnablePasswordLock failed: %v", err)
	}
	if err := m.EnablePasswordLock("OverwritePass999!"); err == nil {
		t.Fatal("expected second EnablePasswordLock call while already locked to fail")
	}

	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_ = m.TryLock()
			} else {
				_, _ = m.Login("WrongPassword!")
			}
		}(i)
	}
	wg.Wait()

	// Drain up to 5 failures to trigger brute-force lockout and verify subsequent attempt is rejected.
	for i := 0; i < 5; i++ {
		_, _ = m.Login("WrongPassword!")
	}
	if _, err := m.Login("StrongPass123!"); err == nil || !strings.Contains(err.Error(), "too many attempts") {
		t.Fatalf("expected lockout after 5 bad passwords, got %v", err)
	}
}
