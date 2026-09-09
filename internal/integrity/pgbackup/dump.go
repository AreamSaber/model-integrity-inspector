package pgbackup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ToolVersion        = "18.6"
	MaxDumpBytes int64 = 1 << 40
	maxDuration        = 24 * time.Hour
)

// Connection is supplied by the trusted coordinator, never inferred from the
// parent environment. It must describe the SAME database/TLS policy used by
// the snapshot exporter. This is not a general libpq DSN parser. Unsupported
// settings must be rejected by the future app adapter, not silently dropped.
// Password exists only in this process and the child environment, never argv.
// Same-user/root process inspection is outside this infrastructure boundary.
type Connection struct {
	Host              string
	Port              uint16
	Database          string
	Username          string
	Password          string
	SSLMode           string
	RootCertificate   string
	ClientCertificate string
	ClientKey         string
	RevocationList    string
	ChannelBinding    string
}

func (Connection) String() string               { return "[private PostgreSQL connection]" }
func (c Connection) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, c.String()) }
func (c Connection) LogValue() slog.Value       { return slog.StringValue(c.String()) }
func (Connection) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (Connection) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// DumpRequest selects either the explicitly named schema or the whole dedicated
// database. The coordinator must separately authenticate the complete schema /
// object inventory and keep the exporting transaction alive until Dump returns.
// Schema-only selection does not prove dependencies/large objects are complete.
type DumpRequest struct {
	Snapshot        string
	Schema          string
	ApplicationName string
	WholeDatabase   bool
	MaxBytes        int64
}

func (DumpRequest) String() string               { return "[private PostgreSQL dump request]" }
func (r DumpRequest) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (r DumpRequest) LogValue() slog.Value       { return slog.StringValue(r.String()) }
func (DumpRequest) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (DumpRequest) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// DumpReceipt is returned only after the complete child and stream lifecycle
// succeeds. It is not an authenticated archive/restore receipt. The caller must
// discard all emitted bytes on ANY error and publish only after its source
// snapshot transaction, private output and authority checks also succeed.
type DumpReceipt struct {
	Bytes       int64
	SHA256      string
	ToolVersion string
}

// Dump runs a fixed custom-format, uncompressed, non-parallel pg_dump. The
// destination must be private bounded storage (or a trusted test stream); no
// output path, DSN or credential is passed in the command-line arguments.
// TLS trust/client-key paths are explicit operator configuration, not HTTP input.
func Dump(ctx context.Context, executable string, connection Connection, request DumpRequest, destination io.Writer) (DumpReceipt, error) {
	if err := validateDump(ctx, executable, connection, request, destination); err != nil {
		return DumpReceipt{}, err
	}
	environment := connectionEnvironment(connection)
	if request.ApplicationName != "" {
		for i, entry := range environment {
			if entry == "PGAPPNAME=mii-backup" {
				environment[i] = "PGAPPNAME=" + request.ApplicationName
			}
		}
	}
	if err := verifyTool(ctx, executable); err != nil {
		return DumpReceipt{}, err
	}
	deadline, _ := ctx.Deadline()
	remainingMillis := max(int64(1), time.Until(deadline).Milliseconds())
	args := []string{"--format=custom", "--compress=none", "--encoding=UTF8", "--no-password", "--strict-names",
		"--snapshot=" + request.Snapshot, "--lock-wait-timeout=" + strconv.FormatInt(remainingMillis, 10)}
	if !request.WholeDatabase {
		// psql patterns require explicit double quotes for exact case-sensitive
		// matching. validIdentifier excludes pattern metacharacters and quotes.
		args = append(args, "--schema=\""+request.Schema+"\"")
	}
	output := &dumpOutput{destination: destination, limit: request.MaxBytes, sum: sha256.New()}
	stderr := &rejectOutput{}
	err := executeNative(ctx, nativeProcessSpec{path: executable, args: args, env: environment, dir: filepath.Dir(executable), stdout: output, stderr: stderr})
	if ctx.Err() != nil {
		return DumpReceipt{}, ErrCanceled
	}
	if output.failure != nil {
		return DumpReceipt{}, output.failure
	}
	if stderr.seen {
		return DumpReceipt{}, ErrProcess
	}
	if err != nil {
		return DumpReceipt{}, err
	}
	if len(output.header) != 5 || !bytes.Equal(output.header, []byte("PGDMP")) || output.count <= 5 {
		return DumpReceipt{}, ErrOutput
	}
	return DumpReceipt{Bytes: output.count, SHA256: hex.EncodeToString(output.sum.Sum(nil)), ToolVersion: ToolVersion}, nil
}

func validateDump(ctx context.Context, path string, c Connection, r DumpRequest, out io.Writer) error {
	if ctx == nil || out == nil || !validAbsoluteFile(path) || !validConnection(c) || !validSnapshot(r.Snapshot) || !validDumpApplicationName(r.ApplicationName) ||
		r.MaxBytes <= 5 || r.MaxBytes > MaxDumpBytes || (r.WholeDatabase && r.Schema != "") || (!r.WholeDatabase && !validIdentifier(r.Schema)) {
		return ErrConfiguration
	}
	if ctx.Err() != nil {
		return ErrCanceled
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > maxDuration {
		return ErrConfiguration
	}
	return nil
}

// Only the trusted repository coordinator supplies a per-operation nonce.
// It is not an authorization token or a user-controlled connection setting.
func validDumpApplicationName(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != len("mii-backup-")+32 || !strings.HasPrefix(value, "mii-backup-") {
		return false
	}
	for _, char := range value[len("mii-backup-"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validText(value string, limit int) bool {
	return value != "" && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}

func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 63 {
		return false
	}
	for i, char := range []byte(value) {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char == '_' || (i > 0 && char >= '0' && char <= '9') {
			continue
		}
		return false
	}
	return true
}

func validAbsoluteFile(path string) bool {
	if !validText(path, 4096) || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\r\n") {
		return false
	}
	info, err := os.Lstat(path) // #nosec G703 -- Explicit operator-selected absolute tool/TLS file, not an HTTP path; regular-file/no-final-symlink check, no path write.
	return err == nil && info.Mode().IsRegular()
}

func validConnection(c Connection) bool {
	if !validText(c.Host, 253) || c.Port == 0 || !validIdentifier(c.Database) || !validIdentifier(c.Username) || !validText(c.Password, 8192) {
		return false
	}
	if net.ParseIP(c.Host) == nil {
		for _, part := range strings.Split(c.Host, ".") {
			if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
				return false
			}
			for _, b := range []byte(part) {
				if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' {
					return false
				}
			}
		}
	}
	if c.ChannelBinding != "disable" && c.ChannelBinding != "prefer" && c.ChannelBinding != "require" {
		return false
	}
	if c.SSLMode == "disable" {
		return c.RootCertificate == "" && c.ClientCertificate == "" && c.ClientKey == "" && c.RevocationList == "" && c.ChannelBinding != "require"
	}
	if c.SSLMode != "verify-full" && c.SSLMode != "verify-ca" && c.SSLMode != "require" {
		return false
	}
	// Never implicitly consult ~/.postgresql/root.crt. With system roots libpq
	// itself requires verify-full, so refuse weaker combinations before launch.
	if c.RootCertificate == "system" {
		if c.SSLMode != "verify-full" {
			return false
		}
	} else if !validAbsoluteFile(c.RootCertificate) {
		return false
	}
	if (c.ClientCertificate == "") != (c.ClientKey == "") {
		return false
	}
	if c.ClientCertificate != "" && (!validAbsoluteFile(c.ClientCertificate) || !validAbsoluteFile(c.ClientKey)) {
		return false
	}
	return validateCRL(c)
}

// This parser accepts the exact uppercase token alphabet supported by the
// pinned PostgreSQL ImportSnapshot, not SQL/path/URI or an arbitrary pattern.
func validSnapshot(value string) bool {
	if len(value) < 5 || len(value) > 128 {
		return false
	}
	parts := strings.Split(value, "-")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, b := range []byte(part) {
			if (b < '0' || b > '9') && (b < 'A' || b > 'F') {
				return false
			}
		}
	}
	return true
}

func toolEnvironment() []string {
	// The native Windows implementation may require SystemRoot for OS DLLs;
	// no PATH, HOME, APPDATA, PGSERVICE, PGOPTIONS, preload or credential variable
	// is inherited. This is not a sandbox against a compromised executable/OS.
	result := []string{"LANG=C", "LC_ALL=C"}
	if root := os.Getenv("SystemRoot"); runtime.GOOS == "windows" && root != "" {
		result = append(result, "SystemRoot="+root)
	}
	return result
}

func connectionEnvironment(c Connection) []string {
	certMode := "disable"
	if c.ClientCertificate != "" {
		certMode = "allow"
	}
	env := append(toolEnvironment(), "PGHOST="+c.Host, "PGPORT="+strconv.Itoa(int(c.Port)), "PGDATABASE="+c.Database,
		"PGUSER="+c.Username, "PGPASSWORD="+c.Password, "PGSSLMODE="+c.SSLMode, "PGCHANNELBINDING="+c.ChannelBinding,
		"PGAPPNAME=mii-backup", "PGCONNECT_TIMEOUT=10", "PGCLIENTENCODING=UTF8", "PGGSSENCMODE=disable",
		"PGREQUIREAUTH=scram-sha-256,md5,password", "PGSSLCERTMODE="+certMode)
	if c.RootCertificate != "" {
		env = append(env, "PGSSLROOTCERT="+c.RootCertificate)
	}
	if c.ClientCertificate != "" {
		env = append(env, "PGSSLCERT="+c.ClientCertificate, "PGSSLKEY="+c.ClientKey)
	}
	// An omitted sslcrl still consults the OS account's default root.crl even
	// when HOME/APPDATA are absent. Explicit empty input prevents that fallback;
	// libpq 18.6 treats this empty device as no CRL, not a different trust source.
	crl := c.RevocationList
	if crl == "" {
		crl = os.DevNull
	}
	env = append(env, "PGSSLCRL="+crl)
	return env
}

var versionLine = regexp.MustCompile(`^pg_dump \(PostgreSQL\) 18\.6( \([A-Za-z0-9 .+:~_-]{1,96}\))?$`)

func verifyTool(ctx context.Context, path string) error {
	versionCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var output bytes.Buffer
	bounded := &dumpOutput{destination: &output, limit: 256, sum: sha256.New()}
	stderr := &rejectOutput{}
	err := executeNative(versionCtx, nativeProcessSpec{path: path, args: []string{"--version"}, env: toolEnvironment(), dir: filepath.Dir(path), stdout: bounded, stderr: stderr})
	if ctx.Err() != nil {
		return ErrCanceled
	}
	if err != nil || stderr.seen || bounded.failure != nil || !versionLine.MatchString(strings.TrimSuffix(strings.TrimSuffix(output.String(), "\n"), "\r")) {
		return ErrVersion
	}
	return nil
}

type dumpOutput struct {
	destination  io.Writer
	limit, count int64
	sum          hash.Hash
	header       []byte
	failure      error
}

func (w *dumpOutput) Write(p []byte) (written int, resultErr error) {
	defer func() {
		if recover() != nil {
			w.failure = ErrOutput
			written, resultErr = 0, ErrOutput
		}
	}()
	if w.failure != nil {
		return 0, w.failure
	}
	if int64(len(p)) > w.limit-w.count {
		w.failure = ErrLimit
		return 0, w.failure
	}
	n, err := w.destination.Write(p)
	if n < 0 || n > len(p) {
		w.failure = ErrOutput
		return 0, w.failure
	}
	if n > 0 {
		_, _ = w.sum.Write(p[:n])
		w.header = append(w.header, p[:min(n, 5-len(w.header))]...)
		w.count += int64(n)
	}
	if err != nil || n != len(p) {
		w.failure = ErrOutput
	}
	return n, w.failure
}

// Treat even a successful pg_dump with warnings as unpublishable; warnings
// need explicit diagnosis, not silent omission. Never retain stderr contents.
type rejectOutput struct{ seen bool }

func (w *rejectOutput) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.seen = true
	return 0, ErrProcess
}
