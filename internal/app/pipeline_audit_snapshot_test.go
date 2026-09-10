package app

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

var errPipelineAuditSnapshot = errors.New("pipeline audit snapshot verification failed")

// The application only uses full-chain verification BEFORE starting its Worker.
// This test-only observer must not borrow the live SQLite Store's sole writer
// connection while an arbitrary test writer rechecks the entire history. It
// uses production audit.Verify for each MAC and independently checks the full
// frozen head/count/sequence/previous-hash relation, not a new crypto algorithm.
type pipelineAuditReader struct {
	pool   *sql.DB
	driver string
}

func openPipelineAuditReader(t *testing.T, cfg Config) *pipelineAuditReader {
	t.Helper()
	driver, dsn := "pgx", cfg.DatabaseDSN
	if cfg.DatabaseDriver == "sqlite" {
		driver = "sqlite"
		path := filepath.ToSlash(cfg.DatabasePath)
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u := url.URL{Scheme: "file", Path: path}
		u.RawQuery = url.Values{"mode": {"ro"}, "_pragma": {"query_only(1)", "busy_timeout(5000)"}}.Encode()
		dsn = u.String()
	}
	pool, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal("open private audit observer")
	}
	pool.SetMaxOpenConns(1)
	pool.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Error("close private audit observer")
		}
	})
	return &pipelineAuditReader{pool: pool, driver: cfg.DatabaseDriver}
}

func (r *pipelineAuditReader) verify(ctx context.Context, signer audit.MAC) error {
	conn, err := r.pool.Conn(ctx)
	if err != nil {
		return errPipelineAuditSnapshot
	}
	defer func() { _ = conn.Close() }()
	if r.driver == "sqlite" {
		err = conn.Raw(func(raw any) error {
			reader, ok := raw.(interface{ IsReadOnly(string) (bool, error) })
			if !ok {
				return errPipelineAuditSnapshot
			}
			readOnly, err := reader.IsReadOnly("main")
			if err != nil || !readOnly {
				return errPipelineAuditSnapshot
			}
			return nil
		})
		if err != nil {
			return errPipelineAuditSnapshot
		}
	}
	options := &sql.TxOptions{ReadOnly: true}
	if r.driver == "postgres" {
		options.Isolation = sql.LevelRepeatableRead
	}
	actual, err := conn.BeginTx(ctx, options)
	if err != nil {
		return errPipelineAuditSnapshot
	}
	defer func() { _ = actual.Rollback() }()
	dialector := postgres.New(postgres.Config{Conn: actual})
	if r.driver == "sqlite" {
		dialector = sqlite.New(sqlite.Config{DriverName: "sqlite", Conn: actual})
	}
	read, err := gorm.Open(dialector, &gorm.Config{DisableAutomaticPing: true, SkipDefaultTransaction: true, Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return errPipelineAuditSnapshot
	}
	read = read.WithContext(ctx)
	if r.driver == "postgres" {
		var valid bool
		if read.Raw("SELECT current_setting('transaction_isolation')='repeatable read' AND current_setting('transaction_read_only')='on'").Scan(&valid).Error != nil || !valid {
			return errPipelineAuditSnapshot
		}
	}
	var organizations []int64
	if read.Table("organizations").Order("id").Limit(101).Pluck("id", &organizations).Error != nil || len(organizations) == 0 || len(organizations) > 100 {
		return errPipelineAuditSnapshot
	}
	for _, org := range organizations {
		var head struct {
			EventCount            int64
			EventHash, KeyVersion string
		}
		if read.Table("integrity_audit_chain_heads").Select("event_count,event_hash,key_version").Where("organization_id=?", org).Take(&head).Error != nil || head.EventCount < 1 || head.EventCount > 65536 {
			return errPipelineAuditSnapshot
		}
		var total int64
		if read.Table("integrity_audit_logs").Where("organization_id=?", org).Count(&total).Error != nil || total != head.EventCount {
			return errPipelineAuditSnapshot
		}
		var sequence int64
		previous, keyVersion := "", ""
		for sequence < head.EventCount {
			var events []audit.Event
			if read.Where("organization_id=? AND sequence>?", org, sequence).Order("sequence").Limit(100).Find(&events).Error != nil || len(events) == 0 {
				return errPipelineAuditSnapshot
			}
			for _, event := range events {
				if event.OrganizationID != org || event.Sequence != sequence+1 || event.PreviousHash != previous || audit.Verify(event, signer) != nil {
					return errPipelineAuditSnapshot
				}
				sequence, previous, keyVersion = event.Sequence, event.EventHMAC, event.KeyVersion
			}
		}
		if sequence != head.EventCount || previous != head.EventHash || keyVersion != head.KeyVersion {
			return errPipelineAuditSnapshot
		}
	}
	if ctx.Err() != nil {
		return errPipelineAuditSnapshot
	}
	return nil
}

type pipelineAuditBarrier struct {
	signer           audit.MAC
	armed            atomic.Bool
	entered, release chan struct{}
	once             sync.Once
}

func (b *pipelineAuditBarrier) ActiveVersion() string { return b.signer.ActiveVersion() }
func (b *pipelineAuditBarrier) AuditMAC(version string, data []byte) ([]byte, error) {
	if b.armed.Load() {
		b.once.Do(func() { close(b.entered) })
		<-b.release
	}
	return b.signer.AuditMAC(version, data)
}

// Both barriers must stop their observer before test cleanup can close its
// pool, including a fatal return before entry or after consuming the result.
// Completion has its own channel: cleanup never consumes finished a second time.
func startPipelineAuditVerifier(parent context.Context, release func(), verify func(context.Context) error) (<-chan error, func()) {
	ctx, cancel := context.WithCancel(parent)
	finished, done := make(chan error, 1), make(chan struct{})
	go func() {
		defer close(done)
		finished <- verify(ctx)
	}()
	return finished, func() {
		cancel()
		release()
		<-done
	}
}

// A deterministic slow-verifier barrier models CPU/scheduling delay without
// changing Worker deadlines, polling, concurrency, or retry behavior. The old
// live verifier keeps the sole Store connection while running the MAC; the new
// physically read-only observer must let a normal queue claim finish meanwhile.
func TestPipelineFullAuditObserverDoesNotBlockLiveClaim(t *testing.T) {
	cfg := testConfig(t)
	key, err := secret.LoadKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion)
	if err != nil {
		t.Fatal("load fixture signing key")
	}
	barrier := &pipelineAuditBarrier{signer: key, entered: make(chan struct{}), release: make(chan struct{})}
	store, err := repository.Open(t.Context(), repository.Config{Driver: "sqlite", DSN: cfg.DatabasePath, AuditSigner: barrier})
	if err != nil {
		t.Fatal("open isolated live Store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Migrate(t.Context()); err != nil {
		t.Fatal("migrate isolated Store")
	}
	ctx := audit.WithActor(t.Context(), audit.Actor{ReasonCode: "pipeline.audit.test"})
	if _, err := store.Initialize(ctx, repository.Initialization{OrganizationName: "Audit observation", Username: "root", PasswordHash: "synthetic-test-only", AdminRole: "admin", Roles: []repository.InitialRole{{Name: "admin", Permissions: []string{"run.read"}}}}); err != nil {
		t.Fatal("initialize real signed history")
	}
	queue, err := store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal("acquire real consumer")
	}
	t.Cleanup(func() { _ = queue.Close(context.Background()) })
	reader := openPipelineAuditReader(t, cfg)
	barrier.armed.Store(true)
	var unblock sync.Once
	release := func() { unblock.Do(func() { close(barrier.release) }) }
	finished, stopVerifier := startPipelineAuditVerifier(t.Context(), release, func(ctx context.Context) error { return reader.verify(ctx, barrier) })
	defer stopVerifier()
	select {
	case <-barrier.entered:
	case err := <-finished:
		t.Fatalf("observer failed before verifier barrier: success=%t", err == nil)
	case <-time.After(5 * time.Second):
		t.Fatal("verifier barrier not reached")
	}
	claimCtx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	lease, claimErr := queue.Claim(claimCtx)
	cancel()
	release()
	verifyErr := <-finished
	if claimErr != nil || lease != nil || verifyErr != nil {
		t.Fatalf("full-audit observation blocked healthy claim: claim=%s verify_success=%t", applicationFailureClass(claimErr), verifyErr == nil)
	}
}

type pipelineAuditWrongMAC struct{ audit.MAC }

func (s pipelineAuditWrongMAC) AuditMAC(version string, data []byte) ([]byte, error) {
	sum, err := s.MAC.AuditMAC(version, data)
	if err == nil && len(sum) > 0 {
		sum[0] ^= 1
	}
	return sum, err
}

func TestPipelineFullAuditObserverChecksAllPagesAndFrozenHead(t *testing.T) {
	cfg := testConfig(t)
	app, err := prepare(t.Context(), cfg)
	if err != nil {
		t.Fatal("prepare isolated real application")
	}
	t.Cleanup(func() { _ = app.close() })
	key, err := secret.LoadKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion)
	if err != nil {
		t.Fatal("load actual audit verifier")
	}
	actor := audit.WithActor(t.Context(), audit.Actor{ReasonCode: "pipeline.audit.test"})
	initial, err := app.store.Initialize(actor, repository.Initialization{OrganizationName: "Audit observation", Username: "root", PasswordHash: "synthetic-test-only", AdminRole: "admin", Roles: []repository.InitialRole{{Name: "admin", Permissions: []string{"run.read"}}}})
	if err != nil {
		t.Fatal("initialize actual audit fixture")
	}
	actor = audit.WithActor(t.Context(), audit.Actor{ActorID: initial.User.ID, ReasonCode: "pipeline.audit.test"})
	tenant, err := app.store.WithOrganization(actor, initial.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	for range 201 {
		if err := tenant.AppendAudit(repository.AuditCommand{Action: "pipeline.audit.test", ObjectType: "test", ObjectID: "observer", Result: "success"}); err != nil {
			t.Fatal("append authentic historical event")
		}
	}
	reader := openPipelineAuditReader(t, cfg)
	if err := reader.verify(t.Context(), key); err != nil {
		t.Fatal("complete three-page observer failed")
	}
	if err := reader.verify(t.Context(), pipelineAuditWrongMAC{key}); !errors.Is(err, errPipelineAuditSnapshot) {
		t.Fatal("observer skipped actual production MAC verification")
	}
	db := openPipelineDatabase(t, cfg)
	var count int64
	var hash, keyVersion string
	if err := db.QueryRowContext(t.Context(), "SELECT event_count,event_hash,key_version FROM integrity_audit_chain_heads WHERE organization_id=$1", initial.Organization.ID).Scan(&count, &hash, &keyVersion); err != nil {
		t.Fatal("read original observer head")
	}
	for _, test := range []struct {
		name, statement string
		value           any
	}{
		{"missing-count", "UPDATE integrity_audit_chain_heads SET event_count=$1 WHERE organization_id=$2", count - 1},
		{"extra-count", "UPDATE integrity_audit_chain_heads SET event_count=$1 WHERE organization_id=$2", count + 1},
		{"hash", "UPDATE integrity_audit_chain_heads SET event_hash=$1 WHERE organization_id=$2", strings.Repeat("0", 64)},
		{"key", "UPDATE integrity_audit_chain_heads SET key_version=$1 WHERE organization_id=$2", "uninstalled-key"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := db.ExecContext(t.Context(), test.statement, test.value, initial.Organization.ID); err != nil {
				t.Fatal("inject isolated head discrepancy")
			}
			verifyErr := reader.verify(t.Context(), key)
			if _, err := db.ExecContext(t.Context(), "UPDATE integrity_audit_chain_heads SET event_count=$1,event_hash=$2,key_version=$3 WHERE organization_id=$4", count, hash, keyVersion, initial.Organization.ID); err != nil {
				t.Fatal("restore exact observer head")
			}
			if !errors.Is(verifyErr, errPipelineAuditSnapshot) {
				t.Fatal("observer ignored frozen head mismatch")
			}
		})
	}
	// Appends remain enabled on the production writer while the read-only
	// observer verifies its already-established historical snapshot.
	barrier := &pipelineAuditBarrier{signer: key, entered: make(chan struct{}), release: make(chan struct{})}
	barrier.armed.Store(true)
	var once sync.Once
	release := func() { once.Do(func() { close(barrier.release) }) }
	finished, stopVerifier := startPipelineAuditVerifier(t.Context(), release, func(ctx context.Context) error { return reader.verify(ctx, barrier) })
	defer stopVerifier()
	select {
	case <-barrier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("historical reader barrier not reached")
	}
	appendCtx, stopAppend := context.WithTimeout(actor, 2*time.Second)
	appendTenant, scopeErr := app.store.WithOrganization(appendCtx, initial.Organization.ID)
	if scopeErr != nil {
		stopAppend()
		release()
		t.Fatal("bind bounded concurrent append")
	}
	appendErr := appendTenant.AppendAudit(repository.AuditCommand{Action: "pipeline.audit.later", ObjectType: "test", ObjectID: "observer", Result: "success"})
	stopAppend()
	release()
	verifyErr := <-finished
	if appendErr != nil || verifyErr != nil {
		t.Fatal("independent reader blocked append or mixed frozen head", applicationFailureClass(appendErr), verifyErr == nil)
	}
	if err := reader.verify(t.Context(), key); err != nil {
		t.Fatal("fresh snapshot did not verify new signed event")
	}
}

func TestPipelineDisplayGrantDiagnosticNeverFormatsOpaqueError(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{nil, "none"}, {errPipelineGrantCounts, "count"}, {errPipelineGrantBinding, "binding"}, {errPipelineAuditSnapshot, "audit_snapshot"}, {diagnosticOpaqueError{}, "unknown"}, {diagnosticOpaqueError{errPipelineAuditSnapshot}, "audit_snapshot"},
	} {
		if pipelineDisplayGrantClass(test.err) != test.want {
			t.Fatal("grant diagnostic escaped closed phase projection")
		}
	}
}

func TestPipelineAuditVerifierLifetimeJoinsEveryReturn(t *testing.T) {
	for _, mode := range []string{"before-entry", "during-verification", "result-already-consumed"} {
		t.Run(mode, func(t *testing.T) {
			released, entered := make(chan struct{}), make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(released) }) }
			var exited atomic.Bool
			finished, stop := startPipelineAuditVerifier(t.Context(), release, func(ctx context.Context) error {
				defer exited.Store(true)
				if mode == "before-entry" {
					<-ctx.Done()
				}
				close(entered)
				if mode == "result-already-consumed" {
					return nil
				}
				<-released
				// Cleanup must cancel before releasing the signer, preventing the
				// resumed verifier from starting a further query on a closing pool.
				return ctx.Err()
			})
			defer stop()
			if mode == "during-verification" {
				<-entered
			}
			if mode == "result-already-consumed" {
				if err := <-finished; err != nil {
					t.Fatal("normal verifier failed")
				}
			}
			stop()
			if !exited.Load() {
				t.Fatal("cleanup returned with a detached verifier")
			}
			if mode != "result-already-consumed" {
				if err := <-finished; !errors.Is(err, context.Canceled) {
					t.Fatal("cleanup did not cancel before release")
				}
			}
			// The deferred second stop also joins done, not the consumed result.
		})
	}
}
