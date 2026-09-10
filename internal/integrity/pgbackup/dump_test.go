package pgbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func testConnection() Connection {
	return Connection{Host: "127.0.0.1", Port: 15432, Database: "mii_test", Username: "mii_test_owner", Password: "password-canary='\\:\n", SSLMode: "disable", ChannelBinding: "prefer"}
}

func TestDumpExplicitEnvironmentAndProtectedValues(t *testing.T) {
	for _, key := range []string{"PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGPASSWORD", "PGPASSFILE", "PGHOST", "PGSSLKEY", "PGSSLCERT", "LD_PRELOAD", "OPENSSL_CONF", "SSL_CERT_FILE"} {
		t.Setenv(key, "ambient-credential-canary")
	}
	c := testConnection()
	env := connectionEnvironment(c)
	values := make(map[string]string)
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || strings.Contains(entry, "ambient-credential-canary") {
			t.Fatal("inherited ambient connection/loader setting")
		}
		if _, exists := values[key]; exists {
			t.Fatal("duplicate child environment key")
		}
		values[key] = value
	}
	if values["PGPASSWORD"] != c.Password || values["PGHOST"] != c.Host || values["PGDATABASE"] != c.Database || values["PGSSLCERTMODE"] != "disable" || values["PGSSLCRL"] != os.DevNull || values["PGREQUIREAUTH"] != "scram-sha-256,md5,password" {
		t.Fatal("explicit connection altered")
	}
	for _, key := range []string{"PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGPASSFILE", "PGSSLKEY", "PGSSLCERT", "LD_PRELOAD", "OPENSSL_CONF", "SSL_CERT_FILE", "PATH", "HOME", "APPDATA"} {
		if _, exists := values[key]; exists {
			t.Fatal("unrequested child setting retained")
		}
	}
	for _, entry := range toolEnvironment() {
		if strings.Contains(entry, "canary") || strings.HasPrefix(entry, "PG") {
			t.Fatal("version probe received database configuration")
		}
	}
	r := DumpRequest{Snapshot: "ABC-DEF-1", Schema: "private_schema_canary", MaxBytes: 1024}
	for _, value := range []any{c, &c, r, &r} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			text := fmt.Sprintf(format, value)
			if strings.Contains(text, "canary") || strings.Contains(text, "ABC") {
				t.Fatal("infrastructure formatting exposed fields")
			}
		}
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private configuration serialized to JSON")
		}
		if _, err := yaml.Marshal(value); err == nil {
			t.Fatal("private configuration serialized to YAML")
		}
		var log bytes.Buffer
		slog.New(slog.NewJSONHandler(&log, nil)).Info("test", "value", value)
		if strings.Contains(log.String(), "canary") || strings.Contains(log.String(), "ABC") {
			t.Fatal("infrastructure logging exposed fields")
		}
	}
}

func TestDumpConnectionAndRequestValidation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal("resolve trusted test executable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	c := testConnection()
	r := DumpRequest{Snapshot: "00000001-00000002-1", Schema: "Exact_Case", MaxBytes: 1024}
	if err := validateDump(ctx, executable, c, r, io.Discard); err != nil {
		t.Fatal("valid explicit request refused")
	}
	for name, mutate := range map[string]func(*Connection){
		"missing_password":          func(v *Connection) { v.Password = "" },
		"nul_password":              func(v *Connection) { v.Password = "abc\x00def" },
		"missing_mode":              func(v *Connection) { v.SSLMode = "" },
		"tls_downgrade":             func(v *Connection) { v.SSLMode = "prefer" },
		"missing_ca":                func(v *Connection) { v.SSLMode = "verify-full" },
		"multi_host":                func(v *Connection) { v.Host = "host-a,host-b" },
		"host_uri":                  func(v *Connection) { v.Host = "postgres://other" },
		"host_options":              func(v *Connection) { v.Host = "host options=-c" },
		"database_conninfo":         func(v *Connection) { v.Database = "host=other" },
		"zero_port":                 func(v *Connection) { v.Port = 0 },
		"invalid_auth":              func(v *Connection) { v.ChannelBinding = "unknown" },
		"plaintext_channel_binding": func(v *Connection) { v.ChannelBinding = "require" },
		"plaintext_cert":            func(v *Connection) { v.ClientCertificate = executable },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := c
			mutate(&candidate)
			if validConnection(candidate) {
				t.Fatal("unsafe or ambiguous connection accepted")
			}
		})
	}
	for _, snapshot := range []string{"", "A-B", "A-B-C-D", "A--B", "a-b-1", "A-B-1'", "A-B-1\n", strings.Repeat("A", 125) + "-B-C"} {
		candidate := r
		candidate.Snapshot = snapshot
		if err := validateDump(ctx, executable, c, candidate, io.Discard); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsafe snapshot accepted")
		}
	}
	for _, schema := range []string{"", "public*", "public|secret", "x.y", "x\"", "--help", strings.Repeat("a", 64)} {
		candidate := r
		candidate.Schema = schema
		if err := validateDump(ctx, executable, c, candidate, io.Discard); !errors.Is(err, ErrConfiguration) {
			t.Fatal("pattern/unknown scope accepted")
		}
	}
	whole := r
	whole.WholeDatabase = true
	if err := validateDump(ctx, executable, c, whole, io.Discard); !errors.Is(err, ErrConfiguration) {
		t.Fatal("ambiguous database and schema scopes accepted")
	}
	whole.Schema = ""
	if err := validateDump(ctx, executable, c, whole, io.Discard); err != nil {
		t.Fatal("explicit whole-database scope refused")
	}
	for _, maxBytes := range []int64{0, 5, MaxDumpBytes + 1} {
		candidate := r
		candidate.MaxBytes = maxBytes
		if err := validateDump(ctx, executable, c, candidate, io.Discard); err == nil {
			t.Fatal("invalid byte limit accepted")
		}
	}
	for _, name := range []string{"mii-backup", "other", "mii-backup-" + strings.Repeat("A", 32), "mii-backup-" + strings.Repeat("a", 31), "mii-backup-" + strings.Repeat("0", 32) + "\n"} {
		candidate := r
		candidate.ApplicationName = name
		if err := validateDump(ctx, executable, c, candidate, io.Discard); !errors.Is(err, ErrConfiguration) {
			t.Fatal("arbitrary application marker accepted")
		}
	}
	identified := r
	identified.ApplicationName = "mii-backup-" + strings.Repeat("f", 32)
	if err := validateDump(ctx, executable, c, identified, io.Discard); err != nil {
		t.Fatal("coordinator operation marker refused")
	}
	long, stop := context.WithTimeout(t.Context(), 25*time.Hour)
	defer stop()
	for _, badCtx := range []context.Context{nil, context.Background(), long} {
		if err := validateDump(badCtx, executable, c, r, io.Discard); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unbounded context accepted")
		}
	}
	canceled, stopCanceled := context.WithCancel(ctx)
	stopCanceled()
	if err := validateDump(canceled, executable, c, r, io.Discard); !errors.Is(err, ErrCanceled) {
		t.Fatal("cancellation lost")
	}
	for _, path := range []string{"pg_dump", filepath.Dir(executable), filepath.Join(t.TempDir(), "missing.exe")} {
		if err := validateDump(ctx, path, c, r, io.Discard); !errors.Is(err, ErrConfiguration) {
			t.Fatal("untrusted command location accepted")
		}
	}
	if err := validateDump(ctx, executable, c, r, nil); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil output accepted")
	}
}

func TestDumpExplicitTLSConfiguration(t *testing.T) {
	dir := t.TempDir()
	files := []string{filepath.Join(dir, "ca.pem"), filepath.Join(dir, "client.pem"), filepath.Join(dir, "client.key")}
	for _, path := range files {
		if err := os.WriteFile(path, []byte("synthetic-path-fixture-not-a-real-certificate"), 0600); err != nil {
			t.Fatal("create explicit TLS path fixture")
		}
	}
	c := testConnection()
	c.SSLMode = "verify-full"
	c.RootCertificate = files[0]
	c.ClientCertificate = files[1]
	c.ClientKey = files[2]
	c.ChannelBinding = "require"
	if !validConnection(c) {
		t.Fatal("explicit TLS paths rejected")
	}
	// This only verifies explicit path mapping. The TLS integration tests,
	// not these synthetic files, establish actual certificate acceptance.
	var wanted = map[string]string{"PGSSLMODE": "verify-full", "PGSSLROOTCERT": files[0], "PGSSLCERT": files[1], "PGSSLKEY": files[2], "PGSSLCRL": os.DevNull, "PGCHANNELBINDING": "require", "PGSSLCERTMODE": "allow"}
	for _, entry := range connectionEnvironment(c) {
		key, value, _ := strings.Cut(entry, "=")
		if want, ok := wanted[key]; ok {
			if want != value {
				t.Fatal("explicit TLS setting changed")
			}
			delete(wanted, key)
		}
	}
	if len(wanted) != 0 {
		t.Fatal("TLS parameters silently omitted")
	}
	c.ClientKey = ""
	if validConnection(c) {
		t.Fatal("incomplete client identity accepted")
	}
	c = testConnection()
	c.SSLMode = "verify-full"
	c.RootCertificate = "system"
	if !validConnection(c) {
		t.Fatal("explicit system roots rejected")
	}
	c.SSLMode = "require"
	if validConnection(c) {
		t.Fatal("system roots with weaker verification accepted")
	}
}

type testOutputWriter struct{ mode string }

func (w testOutputWriter) Write(p []byte) (int, error) {
	switch w.mode {
	case "short":
		return len(p) - 1, nil
	case "error":
		return 0, errors.New("private-output-canary")
	case "panic":
		panic("private-output-canary")
	case "invalid_count":
		return len(p) + 1, nil
	}
	return len(p), nil
}

func TestDumpOutputBoundsAndFaults(t *testing.T) {
	for _, mode := range []string{"short", "error", "panic", "invalid_count"} {
		t.Run(mode, func(t *testing.T) {
			w := &dumpOutput{destination: testOutputWriter{mode}, limit: 64, sum: sha256.New()}
			if _, err := w.Write([]byte("PGDMPdata")); !errors.Is(err, ErrOutput) {
				t.Fatal("writer fault escaped closed output error")
			}
			if _, err := w.Write([]byte("again")); !errors.Is(err, ErrOutput) {
				t.Fatal("writer fault was not sticky")
			}
		})
	}
	w := &dumpOutput{destination: io.Discard, limit: 8, sum: sha256.New()}
	if n, err := w.Write([]byte("PGDMPdat")); n != 8 || err != nil {
		t.Fatal("exact byte boundary rejected")
	}
	if n, err := w.Write([]byte("a")); n != 0 || !errors.Is(err, ErrLimit) {
		t.Fatal("overflow emitted bytes")
	}
	if w.count != 8 || !bytes.Equal(w.header, []byte("PGDMP")) {
		t.Fatal("overflow changed receipt or header")
	}
	var reject rejectOutput
	if n, err := reject.Write(nil); n != 0 || err != nil || reject.seen {
		t.Fatal("empty stderr rejected")
	}
	if _, err := reject.Write([]byte("private-stderr-canary")); !errors.Is(err, ErrProcess) || !reject.seen {
		t.Fatal("stderr warning accepted")
	}
	// Stream >24 MiB in fixed 64 KiB writes; no whole-dump buffer is allocated.
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	copy(chunk, "PGDMP")
	large := &dumpOutput{destination: io.Discard, limit: 32 << 20, sum: sha256.New()}
	oracle := sha256.New()
	for range 512 {
		if n, err := large.Write(chunk); err != nil || n != len(chunk) {
			t.Fatal("large bounded stream failed")
		}
		_, _ = oracle.Write(chunk)
	}
	if large.count != 32<<20 || !bytes.Equal(large.header, []byte("PGDMP")) || hex.EncodeToString(large.sum.Sum(nil)) != hex.EncodeToString(oracle.Sum(nil)) {
		t.Fatal("large stream digest/count mismatch")
	}
}

func TestDumpToolVersionGrammar(t *testing.T) {
	for _, s := range []string{"pg_dump (PostgreSQL) 18.6", "pg_dump (PostgreSQL) 18.6 (Debian 18.6-1.pgdg13+1)"} {
		if !versionLine.MatchString(s) {
			t.Fatal("pinned tool identity rejected")
		}
	}
	for _, s := range []string{"pg_dump (PostgreSQL) 18.5", "pg_dump (PostgreSQL) 18.60", "fake pg_dump (PostgreSQL) 18.6", "pg_dump (PostgreSQL) 18.6\ncanary", "pg_dump (PostgreSQL) 18.6;", "pg_restore (PostgreSQL) 18.6"} {
		if versionLine.MatchString(s) {
			t.Fatal("unapproved tool identity accepted")
		}
	}
	if !reflect.DeepEqual(toolEnvironment(), toolEnvironment()) {
		t.Fatal("tool environment changed without an explicit request")
	}
}
