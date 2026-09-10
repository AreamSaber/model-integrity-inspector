package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

func TestHistoricalKeyConfigurationIsExplicitAndRelative(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mii.yaml")
	text := "integrity:\n  security:\n    master_key_version: v2\n    master_key_file: keys/current.key\n    previous_master_keys:\n      - version: v1\n        file: keys/old.key\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path, noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	refs := cfg.masterKeyReferences()
	if len(refs) != 2 || refs[0].Version != "v2" || refs[0].File != filepath.Join(dir, "keys/current.key") || refs[1].Version != "v1" || refs[1].File != filepath.Join(dir, "keys/old.key") {
		t.Fatal("historical file references not resolved against configuration")
	}
	refs[1].File = "mutated"
	if cfg.PreviousMasterKeys[0].File == "mutated" {
		t.Fatal("references borrowed mutable config slice")
	}
	if _, err := LoadConfig(path, func(key string) string {
		if key == "MII_MASTER_KEY_VERSION" {
			return "v1"
		}
		return ""
	}); !errors.Is(err, ErrConfig) {
		t.Fatal("environment silently duplicated a historical version")
	}
	overridden, err := LoadConfig(path, func(key string) string {
		switch key {
		case "MII_MASTER_KEY_VERSION":
			return "v3"
		case "MII_MASTER_KEY_FILE":
			return "keys/active-three.key"
		}
		return ""
	})
	if err != nil || overridden.MasterKeyVersion != "v3" || overridden.MasterKeyFile != filepath.Join(dir, "keys/active-three.key") || len(overridden.PreviousMasterKeys) != 1 || overridden.PreviousMasterKeys[0] != cfg.PreviousMasterKeys[0] {
		t.Fatal("active override changed or dropped explicit history")
	}
	for _, bad := range []string{
		strings.Replace(text, "version: v1", "version: v2", 1),
		strings.Replace(text, "version: v1", "version: bad/version", 1),
		strings.Replace(text, "file: keys/old.key", "file: ''", 1),
		strings.Replace(text, "file: keys/old.key", "master: INLINE-SECRET-CANARY", 1),
		strings.Replace(text, "file: keys/old.key", "file: keys/old.key\n        typo: true", 1),
		text + "      - version: v1\n        file: another.key\n",
	} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path, noEnvironment); !errors.Is(err, ErrConfig) {
			t.Fatal("ambiguous or inline-secret historical config accepted")
		}
	}
}

func TestHistoricalKeyConfigurationBoundsAndRedaction(t *testing.T) {
	cfg, err := LoadConfig("", noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < secret.MaxMasterKeyFiles-1; i++ {
		cfg.PreviousMasterKeys = append(cfg.PreviousMasterKeys, secret.KeyFileReference{Version: fmt.Sprintf("old.%d", i), File: filepath.Join(t.TempDir(), "private-path-canary.key")})
	}
	if cfg.Validate() != nil {
		t.Fatal("63 historical references plus active rejected")
	}
	for _, value := range []any{cfg, &cfg} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, value), "canary") {
				t.Fatal("config formatting exposed historical paths")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("config JSON exposed historical paths")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("config YAML exposed historical paths")
		}
		var logs bytes.Buffer
		slog.New(slog.NewJSONHandler(&logs, nil)).Info("config", "value", value)
		if strings.Contains(logs.String(), "canary") {
			t.Fatal("config slog exposed historical paths")
		}
	}
	cfg.PreviousMasterKeys = append(cfg.PreviousMasterKeys, secret.KeyFileReference{Version: "excess", File: "private-path-canary.key"})
	if !errors.Is(cfg.Validate(), ErrConfig) {
		t.Fatal("unbounded historical file list accepted")
	}
}

func TestHistoricalKeyConfigRejectsBeforeApplicationFilesAreCreated(t *testing.T) {
	cfg := testConfig(t)
	cfg.MasterKeyVersion = "v2"
	cfg.PreviousMasterKeys = []secret.KeyFileReference{{Version: "v1", File: filepath.Join(t.TempDir(), "missing-key-path-canary.key")}}
	app, err := prepare(t.Context(), cfg)
	if app != nil || err == nil || strings.Contains(err.Error(), "canary") {
		t.Fatal("missing history did not stop startup")
	}
	for _, path := range []string{cfg.DatabasePath, cfg.ReportPath} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("startup touched database/report path before all keys loaded")
		}
	}
}
