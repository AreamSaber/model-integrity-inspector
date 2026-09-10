package repository

import (
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestOperationalAuditVerification(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		requireMigrate(t, store)
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal(err)
		}
		initial := requireInitialize(t, store)
		for _, full := range []bool{false, true} {
			if err := store.VerifyAllAudit(t.Context(), full); err != nil {
				t.Fatal(err)
			}
		}
		// Simulate offline database tampering, never an application API mutation.
		if err := store.db.Exec("UPDATE integrity_audit_logs SET object_id = ? WHERE organization_id = ?", "tampered", initial.Organization.ID).Error; err != nil {
			t.Fatal(err)
		}
		for _, full := range []bool{false, true} {
			if err := store.VerifyAllAudit(t.Context(), full); !errors.Is(err, audit.ErrIntegrity) {
				t.Fatalf("tamper not detected: %v", err)
			}
		}
	})
}
