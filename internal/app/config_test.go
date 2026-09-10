package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func noEnvironment(string) string { return "" }

func TestDefaultConfigurationIsLocalAndRedacted(t *testing.T) {
	cfg, err := LoadConfig("", noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Addr != "127.0.0.1:8080" || cfg.DatabaseDriver != "sqlite" || cfg.Role != "all" {
		t.Fatal("unsafe defaults")
	}
	cfg.DatabaseDSN = "synthetic-sensitive-dsn"
	cfg.SetupToken = "synthetic-sensitive-bootstrap-token"
	if _, err := json.Marshal(cfg); err == nil {
		t.Fatal("operator config serialized")
	}
	if strings.Contains(fmt.Sprintf("%#v", cfg), "synthetic-sensitive") {
		t.Fatal("operator config leaked into logs")
	}
}

func TestStrictConfigurationAndRelativePaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mii.yaml")
	text := "integrity:\n  database:\n    path: nested/local.db\n  security:\n    master_key_file: nested/master.key\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path, noEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DatabasePath != filepath.Join(dir, "nested/local.db") || cfg.MasterKeyFile != filepath.Join(dir, "nested/master.key") {
		t.Fatal("paths not relative to config")
	}
	for _, bad := range []string{"integrity:\n  typo: true\n", "integrity:\n  enabled: false\n", "integrity:\n  queue:\n    provider: redis\n", "integrity:\n  security:\n    master_key_source: kms\n", "integrity:\n  role: worker\n", "integrity: {}\n---\nintegrity: {}\n", "integrity:\n  database:\n    dsn: postgres://secret\n", strings.Repeat(" ", 65<<10)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path, noEnvironment); err == nil {
			t.Fatal("invalid config accepted")
		}
	}
}

func TestConfigurationEnvironmentValidation(t *testing.T) {
	for _, env := range []map[string]string{
		{"MII_ADDR": "0.0.0.0:8080"},
		{"MII_PUBLIC_ORIGIN": "http://public.test"},
		{"MII_ALLOW_INSECURE_LOOPBACK": "false"},
		{"MII_ALLOW_INSECURE_LOOPBACK": "yes"},
		{"MII_DATABASE_DRIVER": "postgres"},
		{"APP_ROLE": "server"},
		{"MII_SETUP_TOKEN": "short"},
		{"MII_ADDR": "127.0.0.1:0"},
	} {
		if _, err := LoadConfig("", func(key string) string { return env[key] }); err == nil {
			t.Fatal("unsafe environment accepted")
		}
	}
	env := map[string]string{"MII_ADDR": "0.0.0.0:8080", "MII_PUBLIC_ORIGIN": "https://control.test", "MII_ALLOW_INSECURE_LOOPBACK": "false", "MII_DATABASE_DRIVER": "postgres", "MII_DATABASE_DSN": "postgres://synthetic-config-only", "APP_ROLE": "server"}
	cfg, err := LoadConfig("", func(key string) string { return env[key] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Role != "server" || cfg.DatabaseDSN != env["MII_DATABASE_DSN"] {
		t.Fatal("explicit overrides missing")
	}
}

func TestReportDirectoryIsExplicitAbsoluteAndNotVolumeRoot(t *testing.T) {
	expected := filepath.Join(t.TempDir(), "private-reports")
	cfg, err := LoadConfig("", func(key string) string {
		if key == "MII_REPORT_PATH" {
			return expected
		}
		return ""
	})
	if err != nil || cfg.ReportPath != expected {
		t.Fatal("report path override missing")
	}
	for _, path := range []string{"", "relative-reports", filepath.VolumeName(expected) + string(filepath.Separator), expected + "\x00"} {
		invalid := cfg
		invalid.ReportPath = path
		if invalid.Validate() == nil {
			t.Fatal("unsafe report path accepted")
		}
	}
}
