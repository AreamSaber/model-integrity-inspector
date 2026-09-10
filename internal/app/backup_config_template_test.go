package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

func backupConfigurationFixture(t testing.TB) Config {
	t.Helper()
	c, err := LoadConfig("", noEnvironment)
	if err != nil {
		t.Fatal("load synthetic configuration")
	}
	c.Addr = "127.0.0.99:8123"
	c.PublicOrigin = "https://source-private-canary.invalid"
	c.DatabaseDSN = "postgres://source-dsn-canary:secret@source.invalid/db"
	c.SetupToken = strings.Repeat("source-setup-canary", 3)
	c.DatabasePath = filepath.Join(t.TempDir(), "source-db-canary.db")
	c.ReportPath = filepath.Join(t.TempDir(), "source-report-canary")
	c.MasterKeyFile = filepath.Join(t.TempDir(), "source-active-canary.key")
	c.MasterKeyVersion = "v3"
	c.PreviousMasterKeys = []secret.KeyFileReference{
		{Version: "v2", File: "source-previous-two-canary.key"},
		{Version: "v1", File: "source-previous-one-canary.key"},
	}
	c.Build.Version, c.Build.Commit = "source-build-canary", "source-commit-canary"
	return c
}

func backupConfigurationDigest(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func TestBackupConfigurationRealLoaderRoundTripAndRelocation(t *testing.T) {
	for _, mode := range []struct{ driver, role string }{{"sqlite", "all"}, {"postgres", "all"}, {"postgres", "server"}, {"postgres", "worker"}} {
		t.Run(mode.driver+"_"+mode.role, func(t *testing.T) {
			c := backupConfigurationFixture(t)
			c.DatabaseDriver, c.Role = mode.driver, appruntime.Role(mode.role)
			original := slices.Clone(c.PreviousMasterKeys)
			a, err := newBackupConfigurationTemplate(t.Context(), c)
			if err != nil || a == nil {
				t.Fatal("create actual safe template", err)
			}
			raw := a.Bytes()
			if len(raw) > backupConfigurationMaxBytes || a.SHA256() != backupConfigurationDigest(raw) {
				t.Fatal("template size/hash mismatch")
			}
			for _, forbidden := range []string{"canary", "127.0.0.99", c.DatabasePath, c.MasterKeyFile, c.ReportPath} {
				if bytes.Contains(raw, []byte(forbidden)) {
					t.Fatal("source operator information entered archive template")
				}
			}
			if !slices.Equal(c.PreviousMasterKeys, original) {
				t.Fatal("template sorted/mutated caller's source references")
			}
			verified, err := verifyBackupConfigurationTemplate(t.Context(), raw, a.SHA256())
			if err != nil || !bytes.Equal(verified.Bytes(), raw) {
				t.Fatal("canonical template verification failed", err)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "restore-template.yaml")
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal("write synthetic template")
			}
			var lookups []string
			loaded, err := LoadConfig(path, func(key string) string {
				lookups = append(lookups, key)
				if key == "MII_DATABASE_DSN" && mode.driver == "postgres" {
					return "postgres://new-synthetic-environment.invalid/new-database"
				}
				return ""
			})
			if err != nil {
				t.Fatal("real LoadConfig rejected generated template", err)
			}
			if string(loaded.Role) != mode.role || loaded.DatabaseDriver != mode.driver || loaded.MasterKeyVersion != "v3" || loaded.SetupToken != "" || loaded.Addr != "127.0.0.1:8080" || loaded.PublicOrigin != "https://restore.invalid" || loaded.AllowInsecureLoopback {
				t.Fatal("loader changed approved relocation semantics")
			}
			if loaded.DatabasePath != filepath.Join(dir, "data/mii.db") || loaded.ReportPath != filepath.Join(dir, "reports") || loaded.MasterKeyFile != filepath.Join(dir, "keys/master.key") || len(loaded.PreviousMasterKeys) != 2 {
				t.Fatal("relocation reused original directory or lost keys")
			}
			for i, ref := range loaded.PreviousMasterKeys {
				if ref.Version != fmt.Sprintf("v%d", i+1) || ref.File != filepath.Join(dir, fmt.Sprintf("keys/previous-%04d.key", i+1)) {
					t.Fatal("historical label-to-placeholder mapping changed")
				}
			}
			for _, key := range lookups {
				if strings.Contains(key, "canary") {
					t.Fatal("source-defined environment key restored")
				}
			}
			if mode.driver == "postgres" {
				if _, err := LoadConfig(path, noEnvironment); !errors.Is(err, ErrConfig) {
					t.Fatal("PostgreSQL template fabricated missing operator credentials")
				}
			}
			for _, path := range []string{loaded.DatabasePath, loaded.MasterKeyFile, loaded.ReportPath} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("template/load opened or created runtime data")
				}
			}
			if mode.driver == "sqlite" {
				if len(raw) != 689 || a.SHA256() != "6fefae6c170bf5f1220d603ce76411a8151caed2f97d3177d8383874068086ec" {
					t.Fatal("v1 canonical protocol changed without explicit migration")
				}
			}
		})
	}
}

func TestBackupConfigurationOwnedAndExplicitSerialization(t *testing.T) {
	c := backupConfigurationFixture(t)
	a, err := newBackupConfigurationTemplate(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	raw := a.Bytes()
	b, err := verifyBackupConfigurationTemplate(t.Context(), raw, a.SHA256())
	if err != nil {
		t.Fatal(err)
	}
	raw[0] ^= 1
	c.PreviousMasterKeys[0].Version = "mutated"
	if !bytes.Equal(a.Bytes(), b.Bytes()) || a.SHA256() != b.SHA256() {
		t.Fatal("caller buffer/config mutated owned artifact")
	}
	for _, value := range []any{a, *a} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if got := fmt.Sprintf(format, value); got != "[private backup configuration template]" {
				t.Fatal("implicit formatting exposed template")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("implicit JSON accepted")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("implicit YAML accepted")
		}
		var output bytes.Buffer
		slog.New(slog.NewJSONHandler(&output, nil)).Info("synthetic", "template", value)
		if strings.Contains(output.String(), "restore.invalid") || strings.Contains(output.String(), a.SHA256()) {
			t.Fatal("log exposed template metadata")
		}
	}
}

func TestBackupConfigurationRejectsEvenRehashedUnsafeOrAmbiguousTemplates(t *testing.T) {
	a, err := newBackupConfigurationTemplate(t.Context(), backupConfigurationFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(a.Bytes())
	bad := []string{"", "integrity: {}\n", strings.Repeat("x", backupConfigurationMaxBytes+1),
		raw + "---\nintegrity: {}\n", raw + "# extra\n", strings.ReplaceAll(raw, "\n", "\r\n"),
		strings.Replace(raw, "restore.invalid", "source-private-canary.invalid", 1),
		strings.Replace(raw, "127.0.0.1:8080", "0.0.0.0:8080", 1),
		strings.Replace(raw, "allow_insecure_loopback: false", "allow_insecure_loopback: true", 1),
		strings.Replace(raw, "enabled: true", "enabled: false", 1),
		strings.Replace(raw, "enabled: true", "enabled: true\n    enabled: true", 1),
		strings.Replace(raw, "enabled: true", "enabled: &flag true", 1),
		strings.Replace(raw, "enabled: true", "enabled: !!bool true", 1),
		strings.Replace(raw, "enabled: true", "Enabled: true", 1),
		strings.Replace(raw, "enabled: true", "enabled: null", 1),
		strings.Replace(raw, "    enabled: true\n", "", 1),
		strings.Replace(raw, "role: all", "role: worker", 1),
		strings.Replace(raw, "provider: database", "provider: redis", 1),
		strings.Replace(raw, "provider: sqlite", "provider: unknown", 1),
		strings.Replace(raw, "./data/mii.db", "../../source-private-canary.db", 1),
		strings.Replace(raw, "./reports", "source-private-canary", 1),
		strings.Replace(raw, "MII_DATABASE_DSN", "SOURCE_PRIVATE_CANARY_DSN", 1),
		strings.Replace(raw, "MII_SETUP_TOKEN", "SOURCE_PRIVATE_CANARY_SETUP", 1),
		strings.Replace(raw, "./keys/master.key", "source-private-canary.key", 1),
		strings.Replace(raw, "./keys/previous-0001.key", "./keys/previous-0002.key", 1),
		strings.Replace(raw, "version: v1", "version: v3", 1),
		strings.Replace(raw, "version: v1", "version: bad/version", 1),
		strings.Replace(raw, "version: v1", "version: v2", 1),
		strings.Replace(raw, "integrity:", "integrity:\n    unimplemented_worker_setting: 100", 1),
		strings.Replace(raw, "mii.backup-config-template.v1", "mii.backup-config-template.v2", 1),
		strings.Replace(raw, "enabled: true", "enabled: "+strings.Repeat("[", 40)+"true"+strings.Repeat("]", 40), 1),
	}
	for i, input := range bad {
		if input == raw {
			t.Fatalf("mutation %d did not change fixture", i)
		}
		got, err := verifyBackupConfigurationTemplate(t.Context(), []byte(input), backupConfigurationDigest([]byte(input)))
		if got != nil || !errors.Is(err, ErrConfig) {
			t.Fatalf("mutation %d admitted invalid candidate", i)
		}
	}
	for _, digest := range []string{"", strings.ToUpper(a.SHA256()), strings.Repeat("0", 64)} {
		if got, err := verifyBackupConfigurationTemplate(t.Context(), a.Bytes(), digest); got != nil || !errors.Is(err, ErrConfig) {
			t.Fatal("independent expected hash bypassed")
		}
	}
}

func TestBackupConfigurationKeyBoundsAndInputValidation(t *testing.T) {
	c := backupConfigurationFixture(t)
	c.PreviousMasterKeys = nil
	for i := 0; i < secret.MaxMasterKeyFiles; i++ {
		a, err := newBackupConfigurationTemplate(t.Context(), c)
		if err != nil || a == nil {
			t.Fatal("supported historical key count rejected", i)
		}
		if got, err := verifyBackupConfigurationTemplate(t.Context(), a.Bytes(), a.SHA256()); err != nil || got == nil {
			t.Fatal("supported key list failed strict round trip", i)
		}
		c.PreviousMasterKeys = append(c.PreviousMasterKeys, secret.KeyFileReference{Version: fmt.Sprintf("old-%02d", i), File: "source-private-canary.key"})
	}
	if got, err := newBackupConfigurationTemplate(t.Context(), c); got != nil || !errors.Is(err, ErrConfig) {
		t.Fatal("65 total configured versions accepted")
	}
	if got, err := newBackupConfigurationTemplate(t.Context(), Config{}); got != nil || !errors.Is(err, ErrConfig) {
		t.Fatal("invalid source config accepted")
	}
}

type backupConfigurationCancelContext struct {
	context.Context
	cancel        context.CancelFunc
	checks, after int
}

func (c *backupConfigurationCancelContext) Err() error {
	c.checks++
	if c.checks == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestBackupConfigurationCancellationProducesNoCandidate(t *testing.T) {
	c := backupConfigurationFixture(t)
	a, err := newBackupConfigurationTemplate(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	for _, verify := range []bool{false, true} {
		for after := 1; after <= 3; after++ {
			base, cancel := context.WithCancel(t.Context())
			ctx := &backupConfigurationCancelContext{Context: base, cancel: cancel, after: after}
			var got *backupConfigurationTemplate
			if verify {
				got, err = verifyBackupConfigurationTemplate(ctx, a.Bytes(), a.SHA256())
			} else {
				got, err = newBackupConfigurationTemplate(ctx, c)
			}
			cancel()
			if got != nil || !errors.Is(err, context.Canceled) || ctx.checks < after {
				t.Fatal("cancellation escaped with candidate", verify, after, err)
			}
		}
	}
	var absent context.Context
	if got, err := newBackupConfigurationTemplate(absent, c); got != nil || !errors.Is(err, ErrConfig) {
		t.Fatal("nil export context")
	}
	if got, err := verifyBackupConfigurationTemplate(absent, a.Bytes(), a.SHA256()); got != nil || !errors.Is(err, ErrConfig) {
		t.Fatal("nil verify context")
	}
}

func FuzzBackupConfigurationTemplate(f *testing.F) {
	a, err := newBackupConfigurationTemplate(f.Context(), backupConfigurationFixture(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(a.Bytes())
	f.Add([]byte(backupConfigurationHeader + "integrity: {}\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := verifyBackupConfigurationTemplate(t.Context(), data, backupConfigurationDigest(data))
		if err != nil {
			if got != nil {
				t.Fatal("failed parse returned candidate")
			}
			return
		}
		if !bytes.Equal(got.Bytes(), data) || got.SHA256() != backupConfigurationDigest(data) {
			t.Fatal("noncanonical verification output")
		}
		if again, err := verifyBackupConfigurationTemplate(t.Context(), got.Bytes(), got.SHA256()); err != nil || !bytes.Equal(again.Bytes(), data) {
			t.Fatal("verified template cannot round trip")
		}
	})
}
