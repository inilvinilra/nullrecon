package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type Config struct {
	Version      string `json:"version"`
	DataDir      string `json:"dataDir"`
	DatabasePath string `json:"databasePath"`
	VaultDir     string `json:"vaultDir"`
	EvidenceDir  string `json:"evidenceDir"`
	Mode         string `json:"mode"`
	Telemetry    bool   `json:"telemetry"`
}

const ConfigVersion = "nr.config/v1"

func Default() (Config, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return Config{}, err
	}
	return ForDataDir(filepath.Join(base, "nullrecon")), nil
}

func ForDataDir(dir string) Config {
	return Config{
		Version:      ConfigVersion,
		DataDir:      dir,
		DatabasePath: filepath.Join(dir, "nullrecon.db"),
		VaultDir:     filepath.Join(dir, "vault"),
		EvidenceDir:  filepath.Join(dir, "evidence"),
		Mode:         "standalone",
		Telemetry:    false,
	}
}

func (c Config) Path() string {
	return filepath.Join(c.DataDir, "config.json")
}

func (c Config) Save() error {
	if c.Version != ConfigVersion {
		return errors.New("config: unsupported version")
	}
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.Path(), data, 0o600)
}

func Load(dataDir string) (Config, error) {
	cfg := ForDataDir(dataDir)
	data, err := os.ReadFile(cfg.Path())
	if errors.Is(err, os.ErrNotExist) {
		return Config{}, errors.New("config: not initialized; run nullrecon init")
	}
	if err != nil {
		return Config{}, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Version != ConfigVersion {
		return Config{}, errors.New("config: unsupported version " + cfg.Version)
	}
	return cfg, nil
}
