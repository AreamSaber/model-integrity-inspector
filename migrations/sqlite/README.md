# SQLite migrations

SQLite migration files use the `NNNNNN_name.up.sql` naming convention. The matching `../common/` file is applied first in the same transaction. Their combined, LF-normalized SQL bytes form the SHA-256 recorded in `schema_migrations`. Destructive down migrations are not supported.

`repository.Store.Migrate` uses the pure-Go modernc SQLite engine through GORM, forces foreign keys, WAL, FULL synchronous durability, a five-second busy timeout and `BEGIN IMMEDIATE` transactions. A pool has one connection; application startup must additionally enforce SQLite's single `all` process / job claimant policy.

All primary keys are positive CSPRNG-generated `int64` values assigned by the repository. This avoids dialect-specific auto-increment behavior. Composite organization foreign keys prevent cross-tenant references. JSON is stored as text and excluded from default list projections. Schema 1 is an expand-only baseline.

Run the actual engine integration tests with `CGO_ENABLED=0 go test ./internal/integrity/repository`. Worker startup calls only `CheckSchema`; it must not call `Migrate`. A failed migration rolls back both DDL and its ledger entry; an applied checksum mismatch or unknown version fails closed. Restore from a separately verified backup, never a destructive down migration.
