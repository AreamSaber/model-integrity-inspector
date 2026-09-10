package repository

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/migrations"
)

const migrationLockID int64 = 0x4d4949534348454d

const migrationTableSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
 version INTEGER PRIMARY KEY CHECK (version > 0),
 name TEXT NOT NULL,
 checksum TEXT NOT NULL,
 status TEXT NOT NULL CHECK (status = 'applied'),
 applied_at TIMESTAMP NOT NULL
)`

// SchemaVersion is diagnostic metadata and never contains credentials.
type SchemaVersion struct {
	Version   int       `json:"version"`
	Name      string    `json:"name"`
	Checksum  string    `json:"checksum"`
	Status    string    `json:"status"`
	AppliedAt time.Time `json:"applied_at"`
}

// Migrate holds a database-wide lock and atomically applies the full pending chain.
// PostgreSQL uses a transaction advisory lock, while SQLite uses BEGIN IMMEDIATE
// from its forced _txlock connection option. Rollback includes transactional DDL.
func (s *Store) Migrate(ctx context.Context) error {
	set, err := migrations.ForDialect(s.driver)
	if err != nil {
		return ErrMigrationFailed
	}
	return s.migrate(ctx, set)
}

func (s *Store) migrate(ctx context.Context, set []migrations.Migration) error {
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if s.driver == "postgres" {
			if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", migrationLockID).Error; err != nil {
				return ErrMigrationFailed
			}
		}
		if err := tx.Exec(migrationTableSQL).Error; err != nil {
			return ErrMigrationFailed
		}
		var applied []SchemaVersion
		if err := tx.Table("schema_migrations").Order("version").Find(&applied).Error; err != nil {
			return ErrMigrationFailed
		}
		if err := verifyHistory(set, applied, false); err != nil {
			return err
		}
		for _, migration := range set[len(applied):] {
			// Files contain one top-level statement per semicolon-terminated line.
			// Trigger/function bodies must occupy one physical line in these files;
			// this restricted migration format is not a general-purpose SQL parser.
			for _, statement := range migrationStatements(migration.SQL) {
				if err := tx.Exec(statement).Error; err != nil {
					return fmt.Errorf("%w: version %d", ErrMigrationFailed, migration.Version)
				}
			}
			row := SchemaVersion{Version: migration.Version, Name: migration.Name,
				Checksum: migration.Checksum, Status: "applied", AppliedAt: time.Now().UTC()}
			if err := tx.Table("schema_migrations").Create(&row).Error; err != nil {
				return ErrMigrationFailed
			}
		}
		return nil
	})
	if err == nil || errors.Is(err, ErrSchemaMismatch) || errors.Is(err, ErrMigrationFailed) {
		return err
	}
	return ErrMigrationFailed
}

func migrationStatements(script string) []string {
	var statements []string
	var current strings.Builder
	for _, line := range strings.Split(script, "\n") {
		// A comment ending in ';' is not SQL. Some SQLite drivers return a nil
		// result for comment-only Exec, which GORM cannot treat as a statement.
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		current.WriteString(line)
		current.WriteByte('\n')
		if strings.HasSuffix(trimmed, ";") {
			statements = append(statements, current.String())
			current.Reset()
		}
	}
	if value := strings.TrimSpace(current.String()); value != "" && !strings.HasPrefix(value, "--") {
		statements = append(statements, value)
	}
	return statements
}

func verifyHistory(expected []migrations.Migration, applied []SchemaVersion, requireCurrent bool) error {
	for i, migration := range expected {
		if migration.Version != i+1 || migration.Checksum == "" || migration.Name == "" {
			return ErrSchemaMismatch
		}
	}
	if len(applied) > len(expected) || (requireCurrent && len(applied) != len(expected)) {
		return ErrSchemaMismatch
	}
	for i, row := range applied {
		want := expected[i]
		if row.Version != want.Version || row.Name != want.Name || row.Checksum != want.Checksum || row.Status != "applied" {
			return fmt.Errorf("%w: version %d", ErrSchemaMismatch, row.Version)
		}
	}
	return nil
}

// CheckSchema is read-only. A worker must fail startup on missing/newer/modified schema.
func (s *Store) CheckSchema(ctx context.Context) error {
	_, err := s.SchemaStatus(ctx)
	return err
}

func (s *Store) SchemaStatus(ctx context.Context) ([]SchemaVersion, error) {
	expected, err := migrations.ForDialect(s.driver)
	if err != nil {
		return nil, ErrSchemaMismatch
	}
	var applied []SchemaVersion
	if err := s.db.WithContext(ctx).Table("schema_migrations").Order("version").Find(&applied).Error; err != nil {
		return nil, ErrSchemaMismatch
	}
	if err := verifyHistory(expected, applied, true); err != nil {
		return nil, err
	}
	return applied, nil
}
