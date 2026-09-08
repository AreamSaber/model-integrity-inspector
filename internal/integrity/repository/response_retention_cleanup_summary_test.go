package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestResponseRetentionCleanupPreservesUnavailableDisplayMetadata(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		tenant, q, selection := responseCleanupFixtureWithDisplayState(t, s, false, DisplayUnavailableSeal)
		var before DisplayEvidenceRecord
		if err := s.db.Where("organization_id=? AND attempt_id=?", tenant.orgID, selection.AttemptID).Take(&before).Error; err != nil {
			t.Fatal(err)
		}
		if before.State != DisplayUnavailableSeal || before.Ciphertext != nil || before.Nonce != nil {
			t.Fatal("fixture did not commit a typed metadata-only capture failure")
		}
		derivedFixtureRetention(t, tenant, 0)
		derivedFixtureRetention(t, tenant, 30)
		lease := claimResponseCleanup(t, tenant, q)
		if err := q.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error { return tx.DeleteResponseEvidenceBatch() }); err != nil {
			t.Fatal(err)
		}
		assertCleanupRows(t, s, tenant.orgID, 0, 1, 1)
		var after DisplayEvidenceRecord
		if err := s.db.Where("organization_id=? AND attempt_id=?", tenant.orgID, selection.AttemptID).Take(&after).Error; err != nil || !reflect.DeepEqual(before, after) {
			t.Fatal("raw cleanup rewrote unavailable display metadata", err)
		}
		summary, err := tenant.ReadResponseRetentionSummary(selection.RunID)
		if err != nil || summary.RawDeletedCount != 1 || summary.DisplayDeletedCount != 0 || summary.DisplayRetainedCount != 0 || summary.DisplayExpiredCount != 0 {
			t.Fatal("metadata-only display counted/deleted as ciphertext", summary, err)
		}
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil {
			t.Fatal("prepare unavailable display after raw deletion", err)
		}
		defer source.Close()
		if source.Metadata().Status != DisplayUnavailableSeal {
			t.Fatal("raw deletion forged a deleted display receipt", source.Metadata().Status)
		}
	})
}

func TestResponseRetentionCleanupSummaryRejectsInvalidRetainedMetadata(t *testing.T) {
	for _, boundary := range []string{"future_capture", "outside_attempt", "attempt_status", "body_receipt", "key_version", "payload_hash"} {
		t.Run(boundary, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				tenant, _, selection := responseCleanupFixture(t, s, false)
				var record DisplayEvidenceRecord
				if err := s.db.Where("organization_id=? AND attempt_id=?", tenant.orgID, selection.AttemptID).Take(&record).Error; err != nil {
					t.Fatal(err)
				}
				attempt := s.db.Model(&AttemptRecord{}).Where("organization_id=? AND id=?", tenant.orgID, selection.AttemptID)
				display := s.db.Model(&DisplayEvidenceRecord{}).Where("organization_id=? AND attempt_id=?", tenant.orgID, selection.AttemptID)
				switch boundary {
				case "future_capture":
					captured := time.Now().UTC().Add(time.Hour)
					finished := captured.Add(time.Hour)
					if err := attempt.Update("finished_at", finished).Error; err != nil {
						t.Fatal(err)
					}
					if err := display.Updates(map[string]any{"captured_at_micros": captured.UnixMicro(), "expires_at_micros": captured.Add(30 * 24 * time.Hour).UnixMicro(), "created_at": finished}).Error; err != nil {
						t.Fatal(err)
					}
				case "outside_attempt":
					captured := record.CapturedAtMicros - responseRetentionDayMicros
					if err := display.Updates(map[string]any{"captured_at_micros": captured, "expires_at_micros": captured + 30*responseRetentionDayMicros}).Error; err != nil {
						t.Fatal(err)
					}
				case "attempt_status":
					if err := attempt.Update("status", "UNCERTAIN").Error; err != nil {
						t.Fatal(err)
					}
				case "body_receipt":
					if err := attempt.Update("response_body_receipt", BodyNotRetained).Error; err != nil {
						t.Fatal(err)
					}
				case "key_version":
					if err := display.Update("key_version", ".").Error; err != nil {
						t.Fatal(err)
					}
				case "payload_hash":
					if err := display.Update("payload_hash", strings.Repeat("g", 64)).Error; err != nil {
						t.Fatal(err)
					}
				}
				if summary, err := tenant.ReadResponseRetentionSummary(selection.RunID); !errors.Is(err, ErrRetentionSource) || summary != (ResponseRetentionSummary{}) {
					t.Fatal("invalid display metadata became a retained-count claim", summary, err)
				}
			})
		})
	}
}
