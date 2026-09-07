package repository

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	modernsqlite "modernc.org/sqlite" // Registers the CGO-free driver, not the default sqlite3 driver.

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

var (
	ErrConfiguration     = errors.New("DATABASE_CONFIGURATION_INVALID")
	ErrUnavailable       = errors.New("DATABASE_UNAVAILABLE")
	ErrOrganizationScope = errors.New("ORGANIZATION_SCOPE_REQUIRED")
	ErrNotFound          = errors.New("RECORD_NOT_FOUND")
	ErrConflict          = errors.New("RECORD_CONFLICT")
	ErrSchemaMismatch    = errors.New("DATABASE_SCHEMA_MISMATCH")
	ErrMigrationFailed   = errors.New("DATABASE_MIGRATION_FAILED")
)

// Config is infrastructure configuration. DSN must never be logged or serialized.
type Config struct {
	Driver       string    `json:"-"`
	DSN          string    `json:"-"`
	MaxOpenConns int       `json:"-"`
	AuditSigner  audit.MAC `json:"-"`
}

// Store owns the connection pool; the underlying unscoped ORM is not exported.
type Store struct {
	db          *gorm.DB
	sql         *sql.DB
	driver      string
	auditSigner audit.MAC
}

// Open verifies connectivity, but does not create or change the schema.
// Only the server/all startup path may subsequently call Migrate.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.DSN == "" || cfg.MaxOpenConns < 0 {
		return nil, ErrConfiguration
	}
	var dialector gorm.Dialector
	var pool *sql.DB
	var err error
	switch cfg.Driver {
	case "sqlite":
		// A single connection prevents concurrent SQLite writers in this process.
		// Separate process exclusion is a runtime role/lease concern, not an ORM pool.
		dsn, dsnErr := sqliteDSN(cfg.DSN)
		if dsnErr != nil {
			return nil, dsnErr
		}
		pool, err = sql.Open("sqlite", dsn)
		if err != nil {
			return nil, ErrUnavailable
		}
		pool.SetMaxOpenConns(1)
		pool.SetMaxIdleConns(1)
		dialector = sqlite.New(sqlite.Config{DriverName: "sqlite", Conn: pool})
	case "postgres":
		dialector = postgres.New(postgres.Config{DSN: cfg.DSN})
	default:
		return nil, ErrConfiguration
	}
	// Silent means driver errors cannot emit interpolated SQL, credentials or bodies.
	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent), DisableAutomaticPing: true,
		SkipDefaultTransaction: true,
	})
	if err != nil {
		if pool != nil {
			_ = pool.Close()
		}
		return nil, ErrUnavailable
	}
	pool, err = db.DB()
	if err != nil {
		return nil, ErrUnavailable
	}
	if cfg.Driver == "postgres" {
		maxOpen := cfg.MaxOpenConns
		if maxOpen == 0 {
			maxOpen = 20
		}
		pool.SetMaxOpenConns(maxOpen)
		pool.SetMaxIdleConns(min(maxOpen, 5))
		pool.SetConnMaxLifetime(30 * time.Minute)
	}
	if err := pool.PingContext(ctx); err != nil {
		_ = pool.Close()
		return nil, ErrUnavailable
	}
	return &Store{db: db, sql: pool, driver: cfg.Driver, auditSigner: cfg.AuditSigner}, nil
}

func sqliteDSN(dsn string) (string, error) {
	base, raw, _ := strings.Cut(dsn, "?")
	query, err := url.ParseQuery(raw)
	if err != nil {
		return "", ErrConfiguration
	}
	// Callers cannot override safety pragmas or transaction locking mode.
	query.Del("_pragma")
	query.Del("_txlock")
	query.Add("_pragma", "foreign_keys(1)")
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Add("_pragma", "synchronous(FULL)")
	query.Set("_txlock", "immediate")
	return base + "?" + query.Encode(), nil
}

func (s *Store) Close() error { return s.sql.Close() }

func (s *Store) Ping(ctx context.Context) error {
	if err := s.sql.PingContext(ctx); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Store) Driver() string { return s.driver }

// Tenant is a mandatory organization capability for business persistence.
// Identity lookup is intentionally separate because login precedes tenant selection.
type Tenant struct {
	store *Store
	ctx   context.Context
	orgID int64
}

func (s *Store) WithOrganization(ctx context.Context, organizationID int64) (*Tenant, error) {
	if organizationID <= 0 {
		return nil, ErrOrganizationScope
	}
	return &Tenant{store: s, ctx: ctx, orgID: organizationID}, nil
}

func (t *Tenant) scoped() *gorm.DB {
	return t.store.db.WithContext(t.ctx).Where("organization_id = ?", t.orgID)
}

// NewID supplies portable positive int64 primary keys from the OS CSPRNG.
func NewID() (int64, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 63)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return 0, errors.New("ID_GENERATION_FAILED")
		}
		if n.Sign() > 0 {
			return n.Int64(), nil
		}
	}
}

func persistenceError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return ErrNotFound
	}
	for _, known := range []error{ErrNotFound, ErrConflict, ErrConfiguration, ErrAlreadyInitialized, ErrOrganizationScope, audit.ErrUnavailable, audit.ErrActorRequired, audit.ErrIntegrity} {
		if errors.Is(err, known) {
			return known
		}
	}
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) && strings.HasPrefix(pgError.Code, "23") {
		return ErrConflict // PostgreSQL integrity-constraint violation class.
	}
	var sqliteError *modernsqlite.Error
	if errors.As(err, &sqliteError) && sqliteError.Code()&0xff == 19 {
		return ErrConflict // SQLite SQLITE_CONSTRAINT, including extended codes.
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) || errors.Is(err, gorm.ErrForeignKeyViolated) {
		return ErrConflict
	}
	// No database error is returned verbatim: PostgreSQL details may quote values.
	// Context cancellation, connection failures and unclassified errors fail closed
	// as unavailable; they are not incorrectly reported as user data conflicts.
	return ErrUnavailable
}
