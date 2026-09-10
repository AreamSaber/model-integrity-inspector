package repository

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestSystemMaintenanceAuditReadBoundsBytesBeforeMaterialization(t *testing.T) {
	for _, field := range []struct {
		column, name string
		limit        int
	}{
		{"ip_summary", "IPSummary", 128}, {"user_agent_summary", "UserAgentSummary", 128},
		{"diff_summary", "DiffSummary", 1024}, {"previous_hash", "PreviousHash", 64},
		{"event_hmac", "EventHMAC", 64}, {"canonicalization_version", "CanonicalizationVersion", 128},
		{"key_version", "KeyVersion", 128},
	} {
		t.Run(field.column, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				_ = beginTestMaintenance(t, s, ctx, auth)
				// Test-owned synthetic database corruption, not an application API
				// mutation. No event text/HMAC/identities enter test diagnostics.
				oversized := strings.Repeat("x", 1<<20)
				if err := s.db.Model(&audit.Event{}).Where("action='system.maintenance.begin'").Update(field.column, oversized).Error; err != nil {
					t.Fatal("prepare oversized signed-source column")
				}
				loaded := -1
				if err := s.db.Callback().Query().After("gorm:query").Register("maintenance_test_observe_bounded_audit", func(db *gorm.DB) {
					events, ok := db.Statement.Dest.(*[]audit.Event)
					if ok && len(*events) == 1 && (*events)[0].Action == "system.maintenance.begin" {
						loaded = len(reflect.ValueOf((*events)[0]).FieldByName(field.name).String())
					}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Query().Remove("maintenance_test_observe_bounded_audit") }()
				_, err := s.ReadMaintenanceState(ctx)
				if !errors.Is(err, audit.ErrIntegrity) {
					t.Error("oversized authenticated source was accepted or misclassified", err)
				}
				if loaded < 0 || loaded > field.limit {
					t.Errorf("audit column reached Go outside its byte bound: field=%s bytes=%d limit=%d", field.column, loaded, field.limit)
				}
				if field.column == "ip_summary" {
					// 64 codepoints but 192 encoded bytes: SQL character count is
					// insufficient for the existing 128-byte canonical restriction.
					if err := s.db.Model(&audit.Event{}).Where("action='system.maintenance.begin'").Update(field.column, strings.Repeat("界", 64)).Error; err != nil {
						t.Fatal("prepare UTF-8 byte-bound counterexample")
					}
					loaded = -1
					if _, err := s.ReadMaintenanceState(ctx); !errors.Is(err, audit.ErrIntegrity) || loaded < 0 || loaded > field.limit {
						t.Fatal("audit byte boundary used character count", err)
					}
				}
			})
		})
	}
}
