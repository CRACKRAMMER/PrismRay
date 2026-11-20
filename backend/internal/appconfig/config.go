// SPDX-License-Identifier: MPL-2.0

package appconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/CRACKRAMMER/PrismRay/backend/internal/fileutil"
)

// Config holds all backend server configuration.
type Config struct {
	Server     ServerConfig  `json:"server"`
	SingBox    SingBoxConfig `json:"sing_box"`
	Xray       XrayConfig    `json:"xray"`
	Storage    StorageConfig `json:"storage"`
	runtimeDir string
}

// SingBoxConfig configures the primary sing-box 1.14+ data-plane engine.
type SingBoxConfig struct {
	BinaryPath     string `json:"binary_path"`
	ConfigPath     string `json:"config_path"`
	MixedPort      int    `json:"mixed_port"`
	ClashAPIPort   int    `json:"clash_api_port"`
	ClashAPISecret string `json:"clash_api_secret,omitempty"`
	RuleSetDir     string `json:"rule_set_dir"`
	AutoUpdate     bool   `json:"auto_update"`
}

// ServerConfig configures the control-plane API server.
type ServerConfig struct {
	AllowedOrigins []string `json:"allowed_origins"`
	Host           string   `json:"host"` // Listen address, e.g. "127.0.0.1" or "0.0.0.0"
	Port           int      `json:"port"` // Listen port, e.g. 2178
}

// XrayConfig configures the on-demand Xray v26+ coprocessor.
type XrayConfig struct {
	BinaryPath string `json:"binary_path"` // Path to xray binary (empty = auto-detect)
	ConfigPath string `json:"config_path"` // Path for generated Xray sidecar config file
	SocksPort  int    `json:"socks_port"`  // Base SOCKS5 port / legacy listener port
	StatsPort  int    `json:"stats_port"`  // Xray API / stats port
	AutoUpdate bool   `json:"auto_update"`
}

// StorageConfig configures persistent SQLite storage and application data directory.
type StorageConfig struct {
	DatabasePath string `json:"database_path"`        // Primary v1.0 SQLite database path
	NodesFile    string `json:"nodes_file,omitempty"` // Compatibility alias kept synced during v1.0 refactor
}

// Default returns a Config with v1.0.0 defaults.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:           "127.0.0.1",
			AllowedOrigins: []string{"http://localhost:1420", "http://127.0.0.1:1420", "tauri://localhost", "http://tauri.localhost", "https://tauri.localhost"},
			Port:           2178,
		},
		SingBox: SingBoxConfig{
			ConfigPath:   "sing-box.json",
			MixedPort:    10808,
			ClashAPIPort: 9090,
			RuleSetDir:   "rulesets",
			AutoUpdate:   true,
		},
		Xray: XrayConfig{
			ConfigPath: "xray-sidecar.json",
			SocksPort:  10808,
			StatsPort:  10085,
			AutoUpdate: true,
		},
		Storage: StorageConfig{
			DatabasePath: "prismray.db",
			NodesFile:    "prismray.db",
		},
	}
}

// MergeStored keeps bootstrap settings that are needed before SQLite can be
// opened, while applying the remaining runtime settings stored in SQLite.
func MergeStored(bootstrap, stored *Config) *Config {
	merged := *stored
	merged.Server = bootstrap.Server
	merged.Storage = bootstrap.Storage
	merged.runtimeDir = bootstrap.runtimeDir
	applyDefaults(&merged)
	return &merged
}

// Load reads configuration from a JSON file, creating it with defaults if missing.
func Load(path string) (*Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := cfg.Save(path); err != nil {
				return nil, err
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config %s: %w", path, err)
	}

	applyDefaults(cfg)
	return cfg, nil
}

func applyDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "127.0.0.1"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 2178
	}
	if cfg.SingBox.ConfigPath == "" {
		cfg.SingBox.ConfigPath = "sing-box.json"
	}
	if cfg.SingBox.MixedPort == 0 {
		if cfg.Xray.SocksPort != 0 {
			cfg.SingBox.MixedPort = cfg.Xray.SocksPort
		} else {
			cfg.SingBox.MixedPort = 10808
		}
	}
	if cfg.SingBox.ClashAPIPort == 0 {
		cfg.SingBox.ClashAPIPort = 9090
	}
	if cfg.SingBox.RuleSetDir == "" {
		cfg.SingBox.RuleSetDir = "rulesets"
	}
	if cfg.Xray.ConfigPath == "" || cfg.Xray.ConfigPath == "xray.json" {
		cfg.Xray.ConfigPath = "xray-sidecar.json"
	}
	if cfg.Xray.SocksPort == 0 {
		cfg.Xray.SocksPort = cfg.SingBox.MixedPort
	}
	if cfg.Xray.StatsPort == 0 {
		cfg.Xray.StatsPort = 10085
	}
	if cfg.Storage.DatabasePath == "" {
		if cfg.Storage.NodesFile != "" {
			cfg.Storage.DatabasePath = cfg.Storage.NodesFile
		} else {
			cfg.Storage.DatabasePath = "prismray.db"
		}
	}
	if cfg.Storage.NodesFile == "" {
		cfg.Storage.NodesFile = cfg.Storage.DatabasePath
	}
}

// Save writes the current config to a JSON file.
func (c *Config) Save(path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return fileutil.WritePrivate(path, data)
}

// SetRuntimeDir overrides the directory used for runtime state, downloaded cores, and rule-sets.
func (c *Config) SetRuntimeDir(dir string) {
	if c == nil {
		return
	}
	c.runtimeDir = strings.TrimSpace(dir)
}

// RuntimeDir returns the directory for runtime state, downloaded cores, and rule-sets,
// falling back to DataDir() when not explicitly configured.
func (c *Config) RuntimeDir() string {
	if c == nil {
		return "."
	}
	if c.runtimeDir != "" {
		return c.runtimeDir
	}
	return c.DataDir()
}

// DataDir returns the directory containing the SQLite database.
func (c *Config) DataDir() string {
	path := c.Storage.DatabasePath
	if path == "" {
		path = c.Storage.NodesFile
	}
	if path == "" {
		return "."
	}
	return filepath.Dir(path)
}

// ListenAddr returns the address string for http.ListenAndServe.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// HTTPPort returns the default HTTP proxy port (MixedPort + 1 when split).
func (c *Config) HTTPPort() int {
	if c.Xray.SocksPort != 0 {
		return c.Xray.SocksPort + 1
	}
	return c.SingBox.MixedPort + 1
}
