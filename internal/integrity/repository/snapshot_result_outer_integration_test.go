package repository

import (
	"context"
	"reflect"
	"testing"

	"gorm.io/gorm"
)

// Actual original row mutations run only in this test's disposable database.
// The shared outer oracle also requires PG to reject reimport after cleanup.
func snapshotResultInventoryFailureSource(t *testing.T, s *Store, mode string) (func(context.Context, *gorm.DB) error, error) {
	t.Helper()
	_, run, _, _ := snapshotResultTestFixture(t, s)
	limit := snapshotReferenceLimit
	want := errSnapshotResultReferenceInvalid
	body := ""
	switch mode {
	case "result_invalid":
		body = `{"schema_version":"mii.analysis.v1","scores":{"RulesHash":null}}`
	case "result_limit":
		limit, want = 1, errSnapshotResultReferenceLimit
	case "result_unsupported":
		body, want = "[]", errSnapshotResultReferenceUnsupported
	default:
		t.Fatal("unknown result failure fixture")
	}
	if body != "" {
		changed := s.db.Model(&RunResultRecord{}).Where("organization_id=? AND run_id=?", run.OrganizationID, run.ID).Update("conclusion_json", body)
		if changed.Error != nil || changed.RowsAffected != 1 {
			t.Fatal("install original result fault")
		}
	}
	return func(ctx context.Context, tx *gorm.DB) error {
		got, err := s.snapshotResultReferencesLimited(ctx, tx, limit)
		if !reflect.DeepEqual(got, snapshotResultReferences{}) {
			t.Error("failed result observation returned partial references")
		}
		return err
	}, want
}
