package app

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// Real SQL rejection is installed only after authentic Seal/WriteNew. The
// adapter cannot reach these completion INSERTs until its own physical Read,
// AEAD Open, exact manifest inventory and original receipt checks succeeded.
func TestBackupArchiveCompletionFinalDatabaseRollback(t *testing.T) {
	for _, stage := range []string{"receipt", "event", "audit", "state"} {
		t.Run(stage, func(t *testing.T) {
			for _, driver := range []string{"sqlite", "postgres"} {
				t.Run(driver, func(t *testing.T) {
					f := newBackupCompletionFixture(t, driver)
					f.publish(t, "")
					// #nosec G304 -- exact authenticated private ciphertext created by this fixture.
					before, err := os.ReadFile(f.path())
					if err != nil {
						t.Fatal("original encrypted fixture read")
					}
					statements := []string{}
					if driver == "sqlite" {
						switch stage {
						case "receipt":
							statements = []string{"CREATE TRIGGER completion_fixture_fail AFTER INSERT ON system_backup_receipts BEGIN SELECT RAISE(ABORT,'completion private canary'); END"}
						case "event":
							statements = []string{"CREATE TRIGGER completion_fixture_fail AFTER INSERT ON system_maintenance_events WHEN NEW.action='complete' BEGIN SELECT RAISE(ABORT,'completion private canary'); END"}
						case "audit":
							statements = []string{"CREATE TRIGGER completion_fixture_fail AFTER INSERT ON integrity_audit_logs WHEN NEW.action='system.maintenance.complete' BEGIN SELECT RAISE(ABORT,'completion private canary'); END"}
						case "state":
							statements = []string{"CREATE TRIGGER completion_fixture_fail AFTER UPDATE ON system_maintenance WHEN NEW.mode='normal' BEGIN SELECT RAISE(ABORT,'completion private canary'); END"}
						}
					} else {
						statements = []string{"CREATE FUNCTION completion_fixture_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'completion private canary'; END $$"}
						switch stage {
						case "receipt":
							statements = append(statements, "CREATE TRIGGER completion_fixture_fail AFTER INSERT ON system_backup_receipts FOR EACH ROW EXECUTE FUNCTION completion_fixture_reject()")
						case "event":
							statements = append(statements, "CREATE TRIGGER completion_fixture_fail AFTER INSERT ON system_maintenance_events FOR EACH ROW WHEN (NEW.action='complete') EXECUTE FUNCTION completion_fixture_reject()")
						case "audit":
							statements = append(statements, "CREATE TRIGGER completion_fixture_fail AFTER INSERT ON integrity_audit_logs FOR EACH ROW WHEN (NEW.action='system.maintenance.complete') EXECUTE FUNCTION completion_fixture_reject()")
						case "state":
							statements = append(statements, "CREATE TRIGGER completion_fixture_fail AFTER UPDATE ON system_maintenance FOR EACH ROW WHEN (NEW.mode='normal') EXECUTE FUNCTION completion_fixture_reject()")
						}
					}
					for _, statement := range statements {
						if _, err := f.db.ExecContext(t.Context(), statement); err != nil {
							t.Fatal("install exact completion rejection trigger")
						}
					}
					got, err := f.finish()
					want := repository.ErrUnavailable
					if driver == "sqlite" {
						want = repository.ErrConflict
					} // RAISE(ABORT) is SQLITE_CONSTRAINT_TRIGGER, not an I/O failure.
					if !errors.Is(err, want) || got != (repository.BackupCompletionReceipt{}) || strings.Contains(err.Error(), "canary") {
						t.Fatal("completion trigger failure was not closed database failure", err)
					}
					f.assertNotReady(t)
					if err := f.app.store.VerifyAllAudit(f.ctx, true); err != nil {
						t.Fatal("rollback corrupted original complete audit chain")
					}
					// #nosec G304 -- identical private ciphertext must survive DB rollback unchanged.
					after, err := os.ReadFile(f.path())
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("database failure removed/changed private original archive")
					}
					// Remove only the explicit fault, then require the same previously
					// verified archive/lease to complete. This controlled recovery proves
					// rollback and causality; production does not retry a failed finish.
					drop := "DROP TRIGGER completion_fixture_fail"
					if driver == "postgres" {
						table := map[string]string{"receipt": "system_backup_receipts", "event": "system_maintenance_events", "audit": "integrity_audit_logs", "state": "system_maintenance"}[stage]
						drop += " ON " + table
					}
					if _, err := f.db.ExecContext(t.Context(), drop); err != nil {
						t.Fatal("remove exact completion fault")
					}
					if driver == "postgres" {
						if _, err := f.db.ExecContext(t.Context(), "DROP FUNCTION completion_fixture_reject()"); err != nil {
							t.Fatal("remove exact completion trigger function")
						}
					}
					completed, err := f.finish()
					if err != nil || completed.ArchiveSHA256 != f.sealed.ArchiveSHA256 {
						t.Fatal("controlled removal of DB fault did not restore authentic completion", err)
					}
					read, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, f.manifest.BackupID)
					if err != nil || read != completed {
						t.Fatal("completed rollback recovery not durably authorized")
					}
				})
			}
		})
	}
}

func TestBackupArchiveCompletionRevokedSessionNeverReady(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			f := newBackupCompletionFixture(t, driver)
			f.publish(t, "")
			// This is an actual normal repository logout, not a mocked authority.
			// It happens before finish; the exact post-read concurrent revocation
			// window is intentionally not claimed without a production barrier.
			if err := f.app.store.RevokeSession(f.ctx, f.auth.UserID, f.session.SessionHash, time.Now().UTC()); err != nil {
				t.Fatal("actual live-session revocation", err)
			}
			// #nosec G304 -- exact already authenticated fixture ciphertext only.
			before, err := os.ReadFile(f.path())
			if err != nil {
				t.Fatal("read pre-revocation archive")
			}
			got, err := f.finish()
			if !errors.Is(err, repository.ErrManagementSession) || got != (repository.BackupCompletionReceipt{}) {
				t.Fatal("revoked principal finalized backup", err)
			}
			f.assertNotReady(t)
			// #nosec G304 -- compare only the same retained private original.
			after, err := os.ReadFile(f.path())
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("revoked-authority failure removed original archive")
			}
		})
	}
}
