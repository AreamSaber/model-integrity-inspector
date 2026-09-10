package capturefixture

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func captureDatabase(t *testing.T, driver string) repository.Config {
	t.Helper()
	if driver == "sqlite" {
		return repository.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "capture.db")}
	}
	if driver != "postgres" {
		t.Fatal("unsupported capture test database")
	}
	dsn := os.Getenv("MII_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL test DSN not configured")
	}
	id, err := repository.NewID()
	if err != nil || id <= 0 {
		t.Fatal("isolated capture schema identity unavailable")
	}
	// The only destructive cleanup target is this freshly allocated test-owned
	// numeric name; no external string selects public or an existing schema.
	schema := "mii_capture_" + strconv.FormatInt(id, 10)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal("isolated capture database connection failed")
	}
	if _, err := db.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		_ = db.Close()
		t.Fatal("isolated capture schema allocation failed")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := db.ExecContext(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error("isolated capture schema cleanup failed")
		}
		_ = db.Close()
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal("invalid isolated capture database DSN")
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + schema
	}
	return repository.Config{Driver: "postgres", DSN: dsn}
}
