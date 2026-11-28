// SPDX-License-Identifier: MPL-2.0

package keyring

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const keySize = 32

var ErrNotFound = errors.New("keyring entry not found")

// Store manages the 32-byte device master key used for passwordless auto-unlock
// on Desktop and Android. When an OS keyring is available and enabled, it is
// preferred; otherwise it safely falls back to a 0600 key slot file inside the
// application's private data directory.
type Store struct {
	service      string
	account      string
	fallbackPath string
	disableOS    bool
}

// Options configures a keyring Store.
type Options struct {
	Service          string
	Account          string
	FallbackPath     string
	DisableOSKeyring bool
}

// New constructs a keyring Store.
func New(opts Options) *Store {
	service := strings.TrimSpace(opts.Service)
	if service == "" {
		service = "io.prismray.devicekey"
	}
	account := strings.TrimSpace(opts.Account)
	if account == "" {
		account = "default"
	}
	disableOS := opts.DisableOSKeyring || strings.EqualFold(strings.TrimSpace(os.Getenv("PRISMRAY_KEYRING")), "file")
	return &Store{
		service:      service,
		account:      account,
		fallbackPath: opts.FallbackPath,
		disableOS:    disableOS,
	}
}

// Derive returns a sibling Store isolated under "<account>-<suffix>" (and "<fallback>.<suffix>")
// so auxiliary slots such as biometric unlock never overwrite the primary device key.
func (s *Store) Derive(suffix string) *Store {
	if s == nil {
		return nil
	}
	clean := strings.TrimSpace(suffix)
	if clean == "" {
		clean = "aux"
	}
	fb := ""
	if s.fallbackPath != "" {
		fb = s.fallbackPath + "." + clean
	}
	return &Store{
		service:      s.service,
		account:      s.account + "-" + clean,
		fallbackPath: fb,
		disableOS:    s.disableOS,
	}
}

// Load returns the stored 32-byte key and true if present, or nil, false, nil if not found.
func (s *Store) Load() ([]byte, bool, error) {
	if !s.disableOS && osKeyringAvailable() {
		key, err := s.loadOS()
		if err == nil {
			return key, true, nil
		}
		if !errors.Is(err, ErrNotFound) {
			// Fall back to the local 0600 slot if D-Bus / OS keychain is temporarily unreachable.
		}
	}
	if s.fallbackPath == "" {
		return nil, false, nil
	}
	return s.loadFile()
}

// LoadFallbackFile reads only the local 0600 fallback key slot, bypassing the OS keyring.
func (s *Store) LoadFallbackFile() ([]byte, bool, error) {
	if s.fallbackPath == "" {
		return nil, false, nil
	}
	return s.loadFile()
}

// Save stores a 32-byte key in the OS keyring when available, or writes the 0600 fallback file.
func (s *Store) Save(key []byte) error {
	if len(key) != keySize {
		return fmt.Errorf("invalid key length %d: expected %d", len(key), keySize)
	}
	if !s.disableOS && osKeyringAvailable() {
		if err := s.saveOS(key); err == nil {
			// Ensure stale plaintext fallback slot does not remain alongside OS keyring storage.
			if s.fallbackPath != "" {
				_ = os.Remove(s.fallbackPath)
			}
			return nil
		}
	}
	if s.fallbackPath == "" {
		return fmt.Errorf("no keyring backend available and fallback path is empty")
	}
	return s.saveFile(key)
}

// LoadOrCreate loads an existing 32-byte key or generates and stores a new one.
func (s *Store) LoadOrCreate() ([]byte, error) {
	key, found, err := s.Load()
	if err != nil {
		return nil, err
	}
	if found {
		return key, nil
	}
	key = make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := s.Save(key); err != nil {
		return nil, err
	}
	return key, nil
}

// Delete removes any stored device key from both OS keyring and the local fallback slot.
func (s *Store) Delete() error {
	var firstErr error
	if !s.disableOS && osKeyringAvailable() {
		if err := s.deleteOS(); err != nil && !errors.Is(err, ErrNotFound) {
			firstErr = err
		}
	}
	if s.fallbackPath != "" {
		if err := os.Remove(s.fallbackPath); err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func decodeKeyString(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, ErrNotFound
	}
	key, err := base64.RawStdEncoding.DecodeString(trimmed)
	if err != nil {
		key, err = base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("decode key: %w", err)
		}
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key size %d", len(key))
	}
	return key, nil
}

func (s *Store) loadFile() ([]byte, bool, error) {
	data, err := os.ReadFile(s.fallbackPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, err
	}
	key, err := unprotectFileKey(string(data))
	if err != nil {
		return nil, false, err
	}
	if runtime.GOOS == "windows" && !strings.HasPrefix(strings.TrimSpace(string(data)), "dpapi:") {
		// Seamlessly re-seal legacy plaintext Windows .device.key using DPAPI.
		_ = s.saveFile(key)
	}
	return key, true, nil
}

func (s *Store) saveFile(key []byte) error {
	dir := filepath.Dir(s.fallbackPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	encoded, err := protectFileKey(key)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".device-key-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(encoded); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.fallbackPath); err != nil {
		return err
	}
	cleanup = false
	if runtime.GOOS != "windows" {
		_ = os.Chmod(s.fallbackPath, 0600)
	}
	return nil
}

func osKeyringAvailable() bool {
	switch runtime.GOOS {
	case "linux":
		if os.Getenv("DBUS_SESSION_BUS_ADDRESS") == "" {
			return false
		}
		_, err := exec.LookPath("secret-tool")
		return err == nil
	case "darwin":
		_, err := exec.LookPath("security")
		return err == nil
	default:
		return false
	}
}

func (s *Store) loadOS() ([]byte, error) {
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("secret-tool", "lookup", "service", s.service, "account", s.account)
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 && len(bytes.TrimSpace(out)) == 0 {
				return nil, ErrNotFound
			}
			return nil, err
		}
		return decodeKeyString(string(out))
	case "darwin":
		cmd := exec.Command("security", "find-generic-password", "-s", s.service, "-a", s.account, "-w")
		out, err := cmd.Output()
		if err != nil {
			return nil, ErrNotFound
		}
		return decodeKeyString(string(out))
	default:
		return nil, ErrNotFound
	}
}

func (s *Store) saveOS(key []byte) error {
	encoded := base64.RawStdEncoding.EncodeToString(key)
	switch runtime.GOOS {
	case "linux":
		cmd := exec.Command("secret-tool", "store", "--label", "PrismRay Device Key", "service", s.service, "account", s.account)
		cmd.Stdin = strings.NewReader(encoded)
		return cmd.Run()
	case "darwin":
		// Use `security -i` over stdin so the base64 master key never appears in process argv.
		cmd := exec.Command("security", "-i")
		line := fmt.Sprintf("add-generic-password -U -s %q -a %q -w %q\n", s.service, s.account, encoded)
		cmd.Stdin = strings.NewReader(line)
		return cmd.Run()
	default:
		return errors.New("unsupported OS keyring")
	}
}

func (s *Store) deleteOS() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("secret-tool", "clear", "service", s.service, "account", s.account).Run()
	case "darwin":
		return exec.Command("security", "delete-generic-password", "-s", s.service, "-a", s.account).Run()
	default:
		return ErrNotFound
	}
}
