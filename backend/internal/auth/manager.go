// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/keyring"
	"github.com/CRACKRAMMER/PrismRay/backend/internal/storage"
)

const recordKey = "security.account"

const (
	ModeWeb     = "web"
	ModeDesktop = "desktop"
	ModeAndroid = "android"
)

type record struct {
	Salt             string `json:"salt"`
	Verifier         string `json:"verifier"`
	KeyNonce         string `json:"key_nonce"`
	WrappedKey       string `json:"wrapped_key"`
	BiometricEnabled bool   `json:"biometric_enabled,omitempty"`
}

type session struct{ expires time.Time }

// Options configures adaptive authentication behavior per platform mode.
type Options struct {
	Mode                     string
	Keyring                  *keyring.Store
	BootstrapOverride        string
	RuntimeSingBoxConfigPath string
}

// Manager handles Argon2id initialization/login for Web mode as well as
// hardware/OS keyring auto-unlock and optional startup password locking for
// Desktop and Android modes.
type Manager struct {
	mu             sync.Mutex
	mode           string
	store          *storage.Store
	keyring        *keyring.Store
	record         record
	dataKey        []byte
	ready          bool
	unlocked       bool
	passwordLocked bool
	bootstrap      string
	sessions       map[string]session
	failures       int
	retryAt        time.Time
}

// New constructs an authentication manager in strict Web mode.
func New(store *storage.Store, bootstrapOverride ...string) (*Manager, error) {
	override := ""
	if len(bootstrapOverride) > 0 {
		override = bootstrapOverride[0]
	}
	return NewWithOptions(store, Options{
		Mode:              ModeWeb,
		BootstrapOverride: override,
	})
}

// NewWithOptions constructs an adaptive authentication manager for Web, Desktop, or Android.
func NewWithOptions(store *storage.Store, opts Options) (*Manager, error) {
	mode := normalizeMode(opts.Mode)
	m := &Manager{
		mode:     mode,
		store:    store,
		keyring:  opts.Keyring,
		sessions: map[string]session{},
	}
	found, err := store.GetSetting(recordKey, &m.record)
	if err != nil {
		return nil, err
	}
	if found {
		m.ready = true
		m.passwordLocked = true
		return m, nil
	}

	if mode == ModeDesktop || mode == ModeAndroid {
		if m.keyring == nil {
			return nil, fmt.Errorf("%s mode requires a keyring store", mode)
		}
		dataKey, err := m.keyring.LoadOrCreate()
		if err != nil {
			return nil, fmt.Errorf("load device key: %w", err)
		}
		if err := m.store.Unlock(dataKey); err != nil {
			recovered := false
			if fbKey, fbFound, fbErr := m.keyring.LoadFallbackFile(); fbErr == nil && fbFound {
				if m.store.Unlock(fbKey) == nil {
					zeroBytes(dataKey)
					dataKey = fbKey
					_ = m.keyring.Save(fbKey)
					recovered = true
					slog.Warn("recovered desktop device key from fallback slot")
				} else {
					zeroBytes(fbKey)
				}
			}
			if !recovered {
				salvaged, salvageErr := m.store.SalvageWithSingBoxConfig(dataKey, opts.RuntimeSingBoxConfigPath)
				if salvageErr != nil {
					zeroBytes(dataKey)
					return nil, fmt.Errorf("unlock store with device key: %w (salvage failed: %v)", err, salvageErr)
				}
				if unlockErr := m.store.Unlock(dataKey); unlockErr != nil {
					zeroBytes(dataKey)
					return nil, fmt.Errorf("unlock store with device key after salvage: %w", unlockErr)
				}
				slog.Warn(
					"recovered from device key mismatch by salvaging database",
					"recovered_nodes", salvaged.RecoveredNodes,
					"deleted_nodes", salvaged.DeletedNodes,
					"deleted_inbounds", salvaged.DeletedInbounds,
					"reset_sub_urls", salvaged.ResetSubURLs,
					"backup", salvaged.BackupPath,
				)
			}
		}
		m.dataKey = append([]byte(nil), dataKey...)
		m.ready = true
		m.unlocked = true
		m.passwordLocked = false
		return m, nil
	}

	if opts.BootstrapOverride != "" {
		m.bootstrap = opts.BootstrapOverride
	} else {
		token, err := randomString(24)
		if err != nil {
			return nil, err
		}
		m.bootstrap = token
	}
	return m, nil
}

func normalizeMode(mode string) string {
	switch mode {
	case ModeDesktop, ModeAndroid:
		return mode
	default:
		return ModeWeb
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (m *Manager) Mode() string { return m.mode }

func (m *Manager) BootstrapToken() string { return m.bootstrap }

func (m *Manager) PasswordLocked() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.passwordLocked
}

func (m *Manager) BiometricEnabled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.passwordLocked && m.record.BiometricEnabled
}

func (m *Manager) biometricKeyring() *keyring.Store {
	if m.keyring == nil {
		return nil
	}
	return m.keyring.Derive("biometric")
}

func (m *Manager) Status() (initialized, unlocked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready, m.unlocked
}

func derive(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
}

func verifier(key []byte) []byte {
	v := sha256.Sum256(append(append([]byte(nil), key...), []byte("prismray-password-verifier-v1")...))
	return v[:]
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func randomString(n int) (string, error) {
	b, err := randomBytes(n)
	return base64.RawURLEncoding.EncodeToString(b), err
}

func wrap(master, data []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce, err = randomBytes(aead.NonceSize())
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, data, []byte(recordKey)), nil
}

func unwrap(master, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, []byte(recordKey))
}

func (m *Manager) buildRecordLocked(password string, dataKey []byte) (record, error) {
	if len(password) < 8 {
		return record{}, fmt.Errorf("管理密码至少需要 8 个字符")
	}
	salt, err := randomBytes(16)
	if err != nil {
		return record{}, err
	}
	master := derive(password, salt)
	nonce, wrapped, err := wrap(master, dataKey)
	if err != nil {
		return record{}, err
	}
	return record{
		Salt:       base64.RawStdEncoding.EncodeToString(salt),
		Verifier:   base64.RawStdEncoding.EncodeToString(verifier(master)),
		KeyNonce:   base64.RawStdEncoding.EncodeToString(nonce),
		WrappedKey: base64.RawStdEncoding.EncodeToString(wrapped),
	}, nil
}

func (m *Manager) verifyAndUnwrapLocked(password string) ([]byte, error) {
	if time.Now().Before(m.retryAt) {
		return nil, fmt.Errorf("too many attempts; try again later")
	}
	salt, err := base64.RawStdEncoding.DecodeString(m.record.Salt)
	if err != nil {
		return nil, err
	}
	master := derive(password, salt)
	expected, err := base64.RawStdEncoding.DecodeString(m.record.Verifier)
	if err != nil || subtle.ConstantTimeCompare(verifier(master), expected) != 1 {
		m.failures++
		if m.failures >= 5 {
			m.retryAt = time.Now().Add(30 * time.Second)
			m.failures = 0
		}
		return nil, fmt.Errorf("invalid password")
	}
	nonce, err := base64.RawStdEncoding.DecodeString(m.record.KeyNonce)
	if err != nil {
		return nil, err
	}
	wrapped, err := base64.RawStdEncoding.DecodeString(m.record.WrappedKey)
	if err != nil {
		return nil, err
	}
	dataKey, err := unwrap(master, nonce, wrapped)
	if err != nil {
		return nil, fmt.Errorf("unlock configuration: %w", err)
	}
	return dataKey, nil
}

// Initialize sets the initial administrator password in Web mode.
func (m *Manager) Initialize(password, bootstrap string, trusted bool) error {
	if len(password) < 8 {
		return fmt.Errorf("管理密码至少需要 8 个字符")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ready && m.passwordLocked {
		return fmt.Errorf("already initialized")
	}
	if !m.ready && !trusted && subtle.ConstantTimeCompare([]byte(bootstrap), []byte(m.bootstrap)) != 1 {
		return fmt.Errorf("invalid initialization token")
	}
	var dataKey []byte
	if len(m.dataKey) == 32 {
		dataKey = append([]byte(nil), m.dataKey...)
	} else {
		var err error
		dataKey, err = randomBytes(32)
		if err != nil {
			return err
		}
	}
	rec, err := m.buildRecordLocked(password, dataKey)
	if err != nil {
		return err
	}
	if err = m.store.PutSetting(recordKey, rec); err != nil {
		return err
	}
	if err = m.store.Unlock(dataKey); err != nil {
		return err
	}
	if m.keyring != nil {
		_ = m.keyring.Delete()
	}
	zeroBytes(m.dataKey)
	m.dataKey = dataKey
	m.record = rec
	m.ready, m.unlocked, m.passwordLocked, m.bootstrap = true, true, true, ""
	return nil
}

// Login verifies the password, unlocks SQLite, and issues a session token.
func (m *Manager) Login(password string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ready {
		return "", fmt.Errorf("not initialized")
	}
	if !m.passwordLocked && m.unlocked {
		token, err := randomString(32)
		if err != nil {
			return "", err
		}
		m.sessions[token] = session{expires: time.Now().Add(12 * time.Hour)}
		return token, nil
	}
	dataKey, err := m.verifyAndUnwrapLocked(password)
	if err != nil {
		return "", err
	}
	if err = m.store.Unlock(dataKey); err != nil {
		return "", err
	}
	token, err := randomString(32)
	if err != nil {
		return "", err
	}
	zeroBytes(m.dataKey)
	m.dataKey = dataKey
	m.sessions[token] = session{expires: time.Now().Add(12 * time.Hour)}
	m.failures, m.retryAt, m.unlocked = 0, time.Time{}, true
	return token, nil
}

// EnablePasswordLock protects the currently unlocked database with a startup password
// and removes the plaintext/keyring auto-unlock device key.
func (m *Manager) EnablePasswordLock(password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.unlocked || len(m.dataKey) != 32 {
		return fmt.Errorf("configuration is locked")
	}
	rec, err := m.buildRecordLocked(password, m.dataKey)
	if err != nil {
		return err
	}
	if err = m.store.PutSetting(recordKey, rec); err != nil {
		return err
	}
	if m.keyring != nil {
		if err = m.keyring.Delete(); err != nil {
			return err
		}
	}
	m.record = rec
	m.ready = true
	m.passwordLocked = true
	return nil
}

// DisablePasswordLock verifies the current password and restores keyring-based
// passwordless auto-unlock on Desktop or Android.
func (m *Manager) DisablePasswordLock(password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == ModeWeb || m.keyring == nil {
		return fmt.Errorf("passwordless mode is not available in %s mode", m.mode)
	}
	if !m.passwordLocked {
		return nil
	}
	dataKey, err := m.verifyAndUnwrapLocked(password)
	if err != nil {
		return err
	}
	if err = m.store.Unlock(dataKey); err != nil {
		zeroBytes(dataKey)
		return err
	}
	if err = m.keyring.Save(dataKey); err != nil {
		zeroBytes(dataKey)
		return err
	}
	if err = m.store.DeleteSetting(recordKey); err != nil {
		return err
	}
	if bioKR := m.biometricKeyring(); bioKR != nil {
		_ = bioKR.Delete()
	}
	zeroBytes(m.dataKey)
	m.dataKey = dataKey
	m.record = record{}
	m.passwordLocked = false
	m.unlocked = true
	m.ready = true
	m.failures, m.retryAt = 0, time.Time{}
	return nil
}

// SetBiometricUnlock enables or disables OS-biometric-gated keyring unlock while
// password lock is active in Desktop or Android mode.
func (m *Manager) SetBiometricUnlock(enabled bool, currentPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == ModeWeb || m.keyring == nil {
		return fmt.Errorf("biometric unlock is only available in desktop or android mode")
	}
	if !m.passwordLocked {
		return fmt.Errorf("请先开启启动密码锁再启用生物信息解锁")
	}
	bioKR := m.biometricKeyring()
	if !enabled {
		if bioKR != nil {
			_ = bioKR.Delete()
		}
		rec := m.record
		rec.BiometricEnabled = false
		if err := m.store.PutSetting(recordKey, rec); err != nil {
			return err
		}
		m.record = rec
		return nil
	}
	dataKey, err := m.verifyAndUnwrapLocked(currentPassword)
	if err != nil {
		return err
	}
	defer zeroBytes(dataKey)
	if err := bioKR.Save(dataKey); err != nil {
		return fmt.Errorf("save biometric keyring slot: %w", err)
	}
	rec := m.record
	rec.BiometricEnabled = true
	if err := m.store.PutSetting(recordKey, rec); err != nil {
		_ = bioKR.Delete()
		return err
	}
	m.record = rec
	return nil
}

// UnlockWithBiometric unlocks SQLite using the isolated biometric keyring slot
// after the native OS biometric prompt succeeds.
func (m *Manager) UnlockWithBiometric() (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.mode == ModeWeb || m.keyring == nil {
		return "", fmt.Errorf("biometric unlock is unavailable in %s mode", m.mode)
	}
	if !m.ready || !m.passwordLocked || !m.record.BiometricEnabled {
		return "", fmt.Errorf("biometric unlock is not enabled")
	}
	bioKR := m.biometricKeyring()
	dataKey, found, err := bioKR.Load()
	if err != nil {
		return "", fmt.Errorf("load biometric key: %w", err)
	}
	if !found || len(dataKey) != 32 {
		return "", fmt.Errorf("未找到系统生物解锁凭据，请使用主密码登录并在设置中重新开启")
	}
	if err := m.store.Unlock(dataKey); err != nil {
		zeroBytes(dataKey)
		return "", fmt.Errorf("biometric key failed to unlock database: %w", err)
	}
	token, err := randomString(32)
	if err != nil {
		zeroBytes(dataKey)
		return "", err
	}
	zeroBytes(m.dataKey)
	m.dataKey = dataKey
	m.sessions[token] = session{expires: time.Now().Add(12 * time.Hour)}
	m.failures, m.retryAt, m.unlocked = 0, time.Time{}, true
	return token, nil
}

// ChangePassword updates the password-wrapped master key after verifying currentPassword.
func (m *Manager) ChangePassword(currentPassword, newPassword string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.passwordLocked {
		return fmt.Errorf("password lock is not enabled")
	}
	dataKey, err := m.verifyAndUnwrapLocked(currentPassword)
	if err != nil {
		return err
	}
	rec, err := m.buildRecordLocked(newPassword, dataKey)
	if err != nil {
		zeroBytes(dataKey)
		return err
	}
	rec.BiometricEnabled = m.record.BiometricEnabled
	if err = m.store.PutSetting(recordKey, rec); err != nil {
		zeroBytes(dataKey)
		return err
	}
	zeroBytes(m.dataKey)
	m.dataKey = dataKey
	m.record = rec
	return nil
}

func (m *Manager) Valid(token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[token]
	if !ok || time.Now().After(s.expires) {
		delete(m.sessions, token)
		return false
	}
	return true
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

func (m *Manager) Lock() {
	m.mu.Lock()
	m.sessions = map[string]session{}
	zeroBytes(m.dataKey)
	m.dataKey = nil
	m.unlocked = false
	m.mu.Unlock()
	m.store.Lock()
}
