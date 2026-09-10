# PostgreSQL migrations

PostgreSQL migration files share sequence numbers with SQLite. The matching `../common/` file is applied first in the same transaction. Dialect-specific SQL is kept here; their combined, LF-normalized SQL bytes form the SHA-256 recorded in `schema_migrations`.

`repository.Store.Migrate` uses GORM / pgx and a transaction-scoped PostgreSQL advisory lock. All pending expansion steps and their ledger entries commit atomically. Partial indexes support pending-job claims, expired leases and live sessions without indexing large JSON/body fields. IDs are application-generated positive `int64` values, matching SQLite semantics.

Set `MII_TEST_POSTGRES_DSN` to a disposable PostgreSQL database and run `CGO_ENABLED=0 go test ./internal/integrity/repository -v`. Each test creates a uniquely named schema and drops only that schema during cleanup. The test user needs `CREATE` schema permission. Without the variable, PostgreSQL integration cases explicitly skip; SQLite success is not evidence of PostgreSQL success.

Server/all startup may migrate; Worker startup is read-only and rejects missing, changed or unknown migration versions. Runtime production accounts should not receive migration DDL privileges; use a dedicated migration account before starting restricted runtime Server/Worker connections. Audit-table runtime privileges are `SELECT/INSERT` only; maintenance deletion requires the separate maintenance role described by ADR-0006. Application rollback preserves this expand-only schema.
