//go:build pgbackup_integration

package repository

import (
	"bytes"
	"context"
	"crypto/md5" // #nosec G501 -- PostgreSQL's built-in md5 is only a synthetic data oracle, never authentication.
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/pgbackup"
)

// The explicit integration tag is a hard dependency contract: no missing
// database or tool may turn this suite into a successful skip. Every source
// and destination below is a freshly created, uniquely owned database. The
// configured control database is never migrated, restored into, or dropped.
type postgresDumpFixture struct {
	control       *sql.DB
	base          *url.URL
	connection    pgbackup.Connection
	dump, restore string
	owned         map[string]bool
}

func newPostgresDumpFixture(t *testing.T) *postgresDumpFixture {
	t.Helper()
	f := &postgresDumpFixture{owned: make(map[string]bool)}
	f.dump = postgresDumpTestTool(t, "MII_TEST_PG_DUMP", "pg_dump")
	f.restore = postgresDumpTestTool(t, "MII_TEST_PG_RESTORE", "pg_restore")
	dsn := os.Getenv("MII_TEST_PG_BACKUP_DSN")
	parsed, err := url.Parse(dsn)
	if err != nil || dsn == "" || parsed == nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.User == nil || parsed.Fragment != "" {
		t.Fatal("explicit MII_TEST_PG_BACKUP_DSN test URL is required")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if (ip == nil || !ip.IsLoopback()) && (os.Getenv("GITHUB_ACTIONS") != "true" || host != "postgres") {
		t.Fatal("plaintext fixture must use loopback or the dedicated GitHub container service")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil || len(query) != 1 || query.Get("sslmode") != "disable" || len(query["sslmode"]) != 1 {
		t.Fatal("test URL must explicitly select only sslmode=disable")
	}
	port, err := strconv.ParseUint(parsed.Port(), 10, 16)
	password, hasPassword := parsed.User.Password()
	if err != nil || port == 0 || !hasPassword || password == "" || parsed.User.Username() == "" || strings.TrimPrefix(parsed.Path, "/") == "" {
		t.Fatal("incomplete explicit PostgreSQL fixture connection")
	}
	f.base = parsed
	f.connection = pgbackup.Connection{Host: host, Port: uint16(port), Database: strings.TrimPrefix(parsed.Path, "/"),
		Username: parsed.User.Username(), Password: password, SSLMode: "disable", ChannelBinding: "prefer"}
	f.control, err = sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("open dedicated database test control connection")
	}
	t.Cleanup(func() {
		if err := f.control.Close(); err != nil {
			t.Error("close dedicated database test control connection")
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	var version int
	var canCreate bool
	if err := f.control.QueryRowContext(ctx, "SELECT current_setting('server_version_num')::integer, rolcreatedb FROM pg_roles WHERE rolname=current_user").Scan(&version, &canCreate); err != nil || version != 180006 || !canCreate {
		t.Fatal("PostgreSQL 18.6 and the test role's CREATEDB capability are required")
	}
	if err := postgresDumpVerifyTestIsolation(ctx, f.control, os.Getenv("MII_TEST_POSTGRES_DSN")); err != nil {
		t.Fatal("backup integration requires a physically separate PostgreSQL test cluster from the general suite")
	}
	return f
}

// DROP DATABASE checkpoints the whole cluster, including unrelated general
// test schemas. Merely using another database on the same server is insufficient.
// These are admin FIXTURE connections only, not privileges required by Dump.
// A standalone CI native job has no general DSN; when both suites are configured,
// require different actual system identifiers rather than comparing URL text.
func postgresDumpVerifyTestIsolation(ctx context.Context, backup *sql.DB, generalDSN string) error {
	if generalDSN == "" {
		return nil
	}
	general, err := sql.Open("pgx", generalDSN)
	if err != nil {
		return ErrConfiguration
	}
	defer func() { _ = general.Close() }()
	var backupID, generalID string
	const identityQuery = "SELECT system_identifier::text FROM pg_catalog.pg_control_system()"
	if err := backup.QueryRowContext(ctx, identityQuery).Scan(&backupID); err != nil {
		return ErrConfiguration
	}
	if err := general.QueryRowContext(ctx, identityQuery).Scan(&generalID); err != nil {
		return ErrConfiguration
	}
	for _, value := range []string{backupID, generalID} {
		if parsed, err := strconv.ParseUint(value, 10, 64); err != nil || parsed == 0 {
			return ErrConfiguration
		}
	}
	if backupID == generalID {
		return ErrConfiguration
	}
	return nil
}

func TestPostgresDumpFixtureRejectsSharedCluster(t *testing.T) {
	f := newPostgresDumpFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// No test database is created: even a different URL pointing at the same
	// actual cluster must be refused before any fixture mutation.
	sameServer := *f.base
	sameServer.Scheme = "postgresql"
	if err := postgresDumpVerifyTestIsolation(ctx, f.control, sameServer.String()); !errors.Is(err, ErrConfiguration) {
		t.Fatal("alternate URL spelling hid shared physical PostgreSQL cluster")
	}
}

func postgresDumpTestTool(t *testing.T, variable, name string) string {
	t.Helper()
	path := os.Getenv(variable)
	if path == "" || !filepath.IsAbs(path) {
		t.Fatalf("%s must name the pinned absolute test executable", variable)
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatal("pinned PostgreSQL tool is not a regular file")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	// #nosec G204 G702 -- Explicit absolute operator test-tool path, regular-file checked above; fixed arguments, no shell or untrusted argument interpolation.
	cmd := exec.CommandContext(ctx, path, "--version")
	cmd.Dir = filepath.Dir(path)
	cmd.Env = postgresDumpTestEnvironment(pgbackup.Connection{})
	cmd.WaitDelay = time.Second
	var output postgresDumpTestBoundedBuffer
	cmd.Stdout, cmd.Stderr = &output, io.Discard
	if err := cmd.Run(); err != nil || output.failed {
		t.Fatal("pinned PostgreSQL version probe failed without exposing tool output")
	}
	pattern := regexp.MustCompile(`^` + regexp.QuoteMeta(name) + ` \(PostgreSQL\) 18\.6( \([A-Za-z0-9 .+:~_-]{1,96}\))?$`)
	line := strings.TrimSuffix(strings.TrimSuffix(output.String(), "\n"), "\r")
	if !pattern.MatchString(line) {
		t.Fatal("PostgreSQL test tool version must be exactly 18.6")
	}
	return path
}

type postgresDumpTestBoundedBuffer struct {
	bytes.Buffer
	failed bool
}

func (b *postgresDumpTestBoundedBuffer) Write(p []byte) (int, error) {
	if b.failed || len(p) > 512-b.Len() {
		b.failed = true
		return 0, errors.New("bounded test output exceeded")
	}
	return b.Buffer.Write(p)
}

func postgresDumpTestEnvironment(c pgbackup.Connection) []string {
	env := []string{"LANG=C", "LC_ALL=C"}
	if runtime.GOOS == "windows" {
		env = append(env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	if c.Host != "" {
		env = append(env, "PGHOST="+c.Host, "PGPORT="+strconv.Itoa(int(c.Port)), "PGUSER="+c.Username,
			"PGPASSWORD="+c.Password, "PGDATABASE="+c.Database, "PGSSLMODE=disable", "PGGSSENCMODE=disable",
			"PGCONNECT_TIMEOUT=10", "PGREQUIREAUTH=scram-sha-256,md5,password", "PGSSLCERTMODE=disable", "PGSSLCRL="+os.DevNull)
	}
	return env
}

var postgresDumpOwnedDatabase = regexp.MustCompile(`^mii_dump_(src|dst)_[1-9][0-9]{0,18}$`)

func (f *postgresDumpFixture) createDatabase(t *testing.T, kind string) (Config, pgbackup.Connection) {
	t.Helper()
	id, err := NewID()
	name := fmt.Sprintf("mii_dump_%s_%d", kind, id)
	if err != nil || !postgresDumpOwnedDatabase.MatchString(name) || name == f.connection.Database {
		t.Fatal("invalid newly owned test database identity")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if _, err := f.control.ExecContext(ctx, `CREATE DATABASE "`+name+`" TEMPLATE template0`); err != nil {
		t.Fatal("create new isolated PostgreSQL dump test database")
	}
	f.owned[name] = true
	t.Cleanup(func() { f.dropDatabase(t, name) })
	parsed := *f.base
	parsed.Path, parsed.RawPath = "/"+name, ""
	c := f.connection
	c.Database = name
	return Config{Driver: "postgres", DSN: parsed.String(), AuditSigner: testAuditSigner{}}, c
}

// Release one exact database actually created by this fixture, after closing
// every source connection. Successful early release is remembered so cleanup
// never repeats DROP; a failure remains a failed test even if cleanup recovers.
// The original ten-second deadline, fsync and no-FORCE policy are unchanged.
func (f *postgresDumpFixture) dropDatabase(t *testing.T, name string) bool {
	t.Helper()
	active, known := f.owned[name]
	if !known || !postgresDumpOwnedDatabase.MatchString(name) || name == f.connection.Database {
		t.Error("refused unsafe test database cleanup identity")
		return false
	}
	if !active {
		return true
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cleanupCancel()
	cleanupConn, err := f.control.Conn(cleanupCtx)
	if err != nil {
		t.Error("acquire owned test database cleanup connection")
		return false
	}
	defer func() { _ = cleanupConn.Close() }()
	var cleanupPID int
	if err := cleanupConn.QueryRowContext(cleanupCtx, "SELECT pg_backend_pid()").Scan(&cleanupPID); err != nil {
		t.Error("identify owned test database cleanup connection")
		return false
	}
	observeCtx, stopObserve := context.WithCancel(cleanupCtx)
	observations := make(chan map[string]int, 1)
	go postgresDumpObserveCleanup(observeCtx, f.control, cleanupPID, observations)
	_, dropErr := cleanupConn.ExecContext(cleanupCtx, `DROP DATABASE "`+name+`"`)
	stopObserve()
	observed := <-observations
	if dropErr != nil {
		code := "unclassified"
		var pgErr *pgconn.PgError
		if errors.As(dropErr, &pgErr) && regexp.MustCompile(`^[0-9A-Z]{5}$`).MatchString(pgErr.Code) {
			code = pgErr.Code
		}
		t.Errorf("cleanup newly owned PostgreSQL dump test database: kind=%s context_expired=%t sqlstate=%s waits=%v", strings.Split(name, "_")[2], cleanupCtx.Err() != nil, code, observed)
		return false
	}
	var exists bool
	if err := cleanupConn.QueryRowContext(cleanupCtx, "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_database WHERE datname=$1)", name).Scan(&exists); err != nil || exists {
		t.Error("confirm successful owned PostgreSQL test database removal")
		return false
	}
	f.owned[name] = false
	return true
}

func postgresDumpObserveCleanup(ctx context.Context, control *sql.DB, pid int, done chan<- map[string]int) {
	counts := make(map[string]int)
	defer func() { done <- counts }()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		// Only a closed wait category is returned, never query text or values.
		var wait string
		err := control.QueryRowContext(ctx, `SELECT CASE WHEN wait_event IN
('CheckpointStart','CheckpointDone','ProcSignalBarrier','ClientRead','ClientWrite','DataFileWrite','DataFileSync','WALWrite','WALSync')
THEN wait_event WHEN wait_event_type='Lock' THEN 'Lock' WHEN wait_event IS NULL THEN 'running' ELSE 'other' END
FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&wait)
		if err == nil {
			counts[wait]++
		} else if ctx.Err() == nil {
			counts["probe_failed"]++
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func postgresDumpOpenTestStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	s, err := Open(t.Context(), cfg)
	if err != nil {
		t.Fatal("open newly owned PostgreSQL test database")
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error("close newly owned PostgreSQL test database")
		}
	})
	return s
}

func postgresDumpTestFile(t *testing.T) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "synthetic-postgres-*.dump")
	if err != nil {
		t.Fatal("create synthetic dump test output")
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func (f *postgresDumpFixture) restoreDatabase(t *testing.T, file *os.File) *Store {
	t.Helper()
	cfg, c := f.createDatabase(t, "dst")
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal("rewind complete synthetic dump for actual restore")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	// Test-only restoration of this trusted synthetic archive. This is not
	// the product's authenticated restore coordinator or an arbitrary-SQL sandbox.
	// #nosec G204 -- Fixed tool, closed arguments, newly generated destination identity, no DSN/password argv or shell.
	cmd := exec.CommandContext(ctx, f.restore, "--single-transaction", "--exit-on-error", "--no-owner", "--no-acl", "--no-password", "--dbname="+c.Database)
	cmd.Dir, cmd.Env, cmd.Stdin = filepath.Dir(f.restore), postgresDumpTestEnvironment(c), file
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = io.Discard, io.Discard, time.Second
	if err := cmd.Run(); err != nil {
		t.Fatal("actual pg_restore into the newly owned database failed")
	}
	return postgresDumpOpenTestStore(t, cfg)
}

func TestPostgresDumpRoundTripUsesExportedSnapshot(t *testing.T) {
	f := newPostgresDumpFixture(t)
	cfg, c := f.createDatabase(t, "src")
	s := postgresDumpOpenTestStore(t, cfg)
	requireMigrate(t, s)
	initial := requireInitialize(t, s)
	if err := s.db.Exec("CREATE TABLE mii_dump_fixture(id integer PRIMARY KEY, payload text NOT NULL)").Error; err != nil {
		t.Fatal("create owned large-dump fixture")
	}
	if err := s.db.Exec("INSERT INTO mii_dump_fixture SELECT g, repeat('A',1048576) FROM generate_series(1,26) g").Error; err != nil {
		t.Fatal("populate 26 MiB synthetic PostgreSQL data")
	}
	file := postgresDumpTestFile(t)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	var receipt pgbackup.DumpReceipt
	var inventory snapshotAuditInventory
	err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		if err := view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
			var err error
			inventory, err = s.snapshotAuditInventory(ctx, tx)
			if err != nil || len(inventory.anchors) != 1 {
				t.Fatal("read complete initialized audit inventory in exported snapshot")
			}
			// These commits use a different physical connection after export.
			auditSnapshotTestAppend(t, s, initial.Organization.ID, initial.User.ID, 1)
			if err := s.db.WithContext(ctx).Exec("UPDATE mii_dump_fixture SET payload=repeat('B',1048576) WHERE id=1").Error; err != nil {
				t.Fatal("commit independent post-snapshot synthetic data change")
			}
			if err := s.db.WithContext(ctx).Exec("INSERT INTO mii_dump_fixture VALUES(27,'later')").Error; err != nil {
				t.Fatal("commit independent post-snapshot synthetic row")
			}
			return nil
		}); err != nil {
			return err
		}
		var err error
		receipt, err = s.dumpPostgresSnapshot(ctx, view, f.dump, c, pgbackup.DumpRequest{WholeDatabase: true, MaxBytes: 64 << 20}, file)
		return err
	})
	if err != nil {
		t.Fatalf("actual same-snapshot dump failed: %v", err)
	}
	if receipt.Bytes <= 26<<20 || receipt.Bytes > 64<<20 || receipt.ToolVersion != "18.6" || len(receipt.SHA256) != 64 {
		t.Fatal("large streaming dump has no complete bounded receipt")
	}
	if err := file.Sync(); err != nil {
		t.Fatal("sync complete synthetic dump")
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal("rewind dump for independent hash")
	}
	hash := sha256.New()
	n, err := io.CopyBuffer(hash, file, make([]byte, 64<<10))
	if err != nil || n != receipt.Bytes || hex.EncodeToString(hash.Sum(nil)) != receipt.SHA256 {
		t.Fatal("actual dump file identity differs from successful stream receipt")
	}
	// Prove all live-source assertions before releasing the source. DROP's
	// checkpoint is cluster-wide: keeping another freshly migrated database
	// alive adds its unrelated pending fsyncs to destination cleanup. Once the
	// complete archive and audit anchors are owned, restoration needs no source.
	var liveCount int64
	if err := s.sql.QueryRowContext(t.Context(), "SELECT count(*) FROM mii_dump_fixture").Scan(&liveCount); err != nil || liveCount != 27 {
		t.Fatal("source database lost its independently committed late row")
	}
	tenant, _ := s.WithOrganization(ctx, initial.Organization.ID)
	live, err := tenant.VerifyAuditFull()
	if err != nil || live.EventCount != 2 || live.VerifiedCount != 2 {
		t.Fatal("source audit chain lost its later committed event")
	}
	if err := s.Close(); err != nil || !f.dropDatabase(t, c.Database) {
		t.Fatal("release source before creating the independent restore destination")
	}
	restored := f.restoreDatabase(t, file)
	if err := restored.CheckSchema(t.Context()); err != nil {
		t.Fatal("restored actual migration ledger mismatch")
	}
	var count, bytesCount int64
	if err := restored.sql.QueryRowContext(t.Context(), "SELECT count(*),sum(octet_length(payload)) FROM mii_dump_fixture").Scan(&count, &bytesCount); err != nil || count != 26 || bytesCount != 26<<20 {
		t.Fatal("actual restored rows include late data or lose original data")
	}
	expected := fmt.Sprintf("%x", md5.Sum(bytes.Repeat([]byte("A"), 1<<20))) // #nosec G401 -- Synthetic equality oracle only; archive integrity uses SHA-256.
	if err := restored.sql.QueryRowContext(t.Context(), "SELECT count(*) FROM mii_dump_fixture WHERE md5(payload)=$1", expected).Scan(&count); err != nil || count != 26 {
		t.Fatal("actual restored payload bytes differ from exported snapshot")
	}
	err = restored.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		return view.use(func(tx *gorm.DB, _ string, _ postgresSnapshotMetadata) error {
			actual, err := restored.snapshotAuditInventory(ctx, tx)
			if err != nil || !reflect.DeepEqual(actual.anchors, inventory.anchors) {
				t.Fatal("actual restored audit anchors differ from the same dump snapshot")
			}
			return nil
		})
	})
	if err != nil {
		t.Fatal("verify actual restored snapshot inventory")
	}
}

func TestPostgresDumpExactSchemaAndFailureReceipts(t *testing.T) {
	f := newPostgresDumpFixture(t)
	cfg, c := f.createDatabase(t, "src")
	s := postgresDumpOpenTestStore(t, cfg)
	for _, statement := range []string{`CREATE SCHEMA "Exact_Case"`, `CREATE SCHEMA exact_case`,
		`CREATE TABLE "Exact_Case".chosen(id integer PRIMARY KEY)`, `INSERT INTO "Exact_Case".chosen VALUES(1)`,
		`CREATE TABLE exact_case.excluded(id integer PRIMARY KEY)`} {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("create exact schema pattern fixture")
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	file := postgresDumpTestFile(t)
	var exported string
	err := s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		return view.use(func(_ *gorm.DB, id string, _ postgresSnapshotMetadata) error {
			exported = id
			r := pgbackup.DumpRequest{Snapshot: id, Schema: "Exact_Case", MaxBytes: 1 << 20}
			for _, mode := range []string{"byte_limit", "writer_failure", "wrong_password"} {
				t.Run(mode, func(t *testing.T) {
					connection, request := c, r
					destination := io.Discard
					want := pgbackup.ErrProcess
					switch mode {
					case "byte_limit":
						request.MaxBytes, want = 6, pgbackup.ErrLimit
					case "writer_failure":
						destination, want = postgresDumpFaultWriter{}, pgbackup.ErrOutput
					case "wrong_password":
						connection.Password += "-wrong-synthetic-password"
					}
					receipt, err := pgbackup.Dump(ctx, f.dump, connection, request, destination)
					if !errors.Is(err, want) || receipt != (pgbackup.DumpReceipt{}) {
						t.Fatalf("actual dump failure did not return its closed error and zero receipt: %v", err)
					}
				})
			}
			_, err := pgbackup.Dump(ctx, f.dump, c, r, file)
			return err
		})
	})
	if err != nil {
		t.Fatalf("actual exact-schema dump failed: %v", err)
	}
	// The stale snapshot must fail while its source database still exists:
	// deleting the source first would make this an unrelated connection failure.
	receipt, err := pgbackup.Dump(ctx, f.dump, c, pgbackup.DumpRequest{Snapshot: exported, Schema: "Exact_Case", MaxBytes: 1 << 20}, io.Discard)
	if !errors.Is(err, pgbackup.ErrProcess) || receipt != (pgbackup.DumpReceipt{}) {
		t.Fatal("actual dump accepted a snapshot after its exporting transaction ended")
	}
	if err := s.Close(); err != nil || !f.dropDatabase(t, c.Database) {
		t.Fatal("release exact-schema source before creating the restore destination")
	}
	restored := f.restoreDatabase(t, file)
	var included, excluded bool
	if err := restored.sql.QueryRowContext(ctx, `SELECT to_regclass('"Exact_Case".chosen') IS NOT NULL,to_regclass('exact_case.excluded') IS NOT NULL`).Scan(&included, &excluded); err != nil || !included || excluded {
		t.Fatal("actual pg_dump schema pattern did not preserve exact case selection")
	}
}

type postgresDumpFaultWriter struct{}

func (postgresDumpFaultWriter) Write([]byte) (int, error) {
	return 0, errors.New("synthetic-private-output-error")
}

func TestPostgresDumpCancellationStopsActualServerLockWait(t *testing.T) {
	f := newPostgresDumpFixture(t)
	cfg, c := f.createDatabase(t, "src")
	s := postgresDumpOpenTestStore(t, cfg)
	if err := s.db.Exec("CREATE TABLE public.mii_dump_lock_fixture(id integer PRIMARY KEY)").Error; err != nil {
		t.Fatal("create actual dump lock-wait fixture")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	lock, err := s.sql.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal("open independent exclusive-lock transaction")
	}
	defer func() { _ = lock.Rollback() }()
	if _, err := lock.ExecContext(ctx, "LOCK TABLE public.mii_dump_lock_fixture IN ACCESS EXCLUSIVE MODE"); err != nil {
		t.Fatal("hold actual relation lock before starting pg_dump")
	}
	err = s.withPostgresSnapshot(ctx, func(view *postgresSnapshot) error {
		dumpCtx, dumpCancel := context.WithCancel(ctx)
		defer dumpCancel()
		type outcome struct {
			receipt pgbackup.DumpReceipt
			err     error
		}
		done := make(chan outcome, 1)
		go func() {
			receipt, err := s.dumpPostgresSnapshot(dumpCtx, view, f.dump, c, pgbackup.DumpRequest{WholeDatabase: true, MaxBytes: 1 << 20}, io.Discard)
			done <- outcome{receipt, err}
		}()
		observeCtx, stopObserve := context.WithTimeout(ctx, 10*time.Second)
		defer stopObserve()
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		observed := false
		for !observed {
			if err := s.sql.QueryRowContext(observeCtx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND usename=$2 AND application_name ~ '^mii-backup-[0-9a-f]{32}$' AND wait_event_type='Lock')", c.Database, c.Username).Scan(&observed); err != nil {
				dumpCancel()
				t.Fatal("observe actual pg_dump server relation-lock wait")
			}
			if observed {
				break
			}
			select {
			case <-done:
				t.Fatal("pg_dump ended without reaching the actual blocked server query")
			case <-observeCtx.Done():
				dumpCancel()
				t.Fatal("pg_dump did not reach the actual bounded lock-wait observation")
			case <-ticker.C:
			}
		}
		dumpCancel()
		select {
		case result := <-done:
			if !errors.Is(result.err, pgbackup.ErrCanceled) || result.receipt != (pgbackup.DumpReceipt{}) {
				t.Fatal("in-flight canceled pg_dump published a receipt or lost its closed cancellation error")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("actual blocked pg_dump did not terminate within two seconds of cancellation")
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(ctx, 2*time.Second)
		defer cleanupCancel()
		for {
			var waiting bool
			if err := s.sql.QueryRowContext(cleanupCtx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=$1 AND usename=$2 AND application_name ~ '^mii-backup-[0-9a-f]{32}$' AND wait_event_type='Lock')", c.Database, c.Username).Scan(&waiting); err != nil {
				t.Fatal("observe server-side canceled dump cleanup")
			}
			if !waiting {
				break // The exclusive lock is still held: it did not unblock the dump.
			}
			select {
			case <-cleanupCtx.Done():
				t.Fatal("canceled dump left its actual server lock wait running")
			case <-ticker.C:
			}
		}
		return nil
	})
	// view.use retains a sticky failure even when consume inspects the result.
	// The outer snapshot must refuse commit/publication and preserve the same
	// closed cancellation result, not silently normalize it or return success.
	if !errors.Is(err, pgbackup.ErrCanceled) {
		t.Fatalf("bounded actual dump cancellation fixture failed: %v", err)
	}
}
