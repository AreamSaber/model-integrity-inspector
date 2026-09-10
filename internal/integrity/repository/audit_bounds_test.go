package repository

import (
	"errors"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestAuditReadsBoundFieldsBeforeMaterialization(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		tenant, err := s.WithOrganization(testActorContext(t, initial.User.ID), initial.Organization.ID)
		if err != nil {
			t.Fatal("audit scope fixture failed")
		}
		for range 2 {
			if err := tenant.AppendAudit(AuditCommand{Action: "test.append", ObjectType: "test", ObjectID: "bounds", Result: "success"}); err != nil {
				t.Fatal("append audit bounds fixture failed")
			}
		}
		original, err := tenant.ListAudit(0, 10)
		if err != nil || len(original) != 3 {
			t.Fatal("read valid audit fixture failed")
		}
		for _, mode := range []string{"tail", "full_middle", "list"} {
			t.Run(mode, func(t *testing.T) {
				target := original[0]
				if mode == "tail" {
					target = original[2]
				}
				for _, field := range []struct {
					column, name string
					limit        int
				}{
					{"action", "Action", 128}, {"object_type", "ObjectType", 128}, {"object_id", "ObjectID", 128},
					{"result", "Result", 128}, {"ip_summary", "IPSummary", 128}, {"user_agent_summary", "UserAgentSummary", 128},
					{"diff_summary", "DiffSummary", 1024}, {"previous_hash", "PreviousHash", 64}, {"event_hmac", "EventHMAC", 64},
					{"canonicalization_version", "CanonicalizationVersion", 128}, {"key_version", "KeyVersion", 128},
				} {
					t.Run(field.column, func(t *testing.T) {
						prior := reflect.ValueOf(target).FieldByName(field.name).String()
						payloadBytes := 1 << 20
						if field.column == "object_type" || field.column == "object_id" {
							// These participate in a PostgreSQL btree key; its native
							// tuple limit rejects a 1 MiB fixture before our read path.
							payloadBytes = field.limit + 1
						}
						// Only this test-owned database is corrupted. SQL/driver values
						// are never printed; the observer receives actual ORM results.
						if err := s.db.Model(&audit.Event{}).Where("id=?", target.ID).Update(field.column, strings.Repeat("x", payloadBytes)).Error; err != nil {
							t.Fatal("create oversized audit field fixture failed")
						}
						defer func() {
							if err := s.db.Model(&audit.Event{}).Where("id=?", target.ID).Update(field.column, prior).Error; err != nil {
								t.Error("restore original test audit field failed")
							}
						}()
						loaded := -1
						const callback = "audit_test_observe_actual_field_bound"
						if err := s.db.Callback().Query().After("gorm:query").Register(callback, func(db *gorm.DB) {
							events, ok := db.Statement.Dest.(*[]audit.Event)
							if !ok || db.Error != nil {
								return
							}
							for _, event := range *events {
								if event.ID == target.ID {
									loaded = len(reflect.ValueOf(event).FieldByName(field.name).String())
								}
							}
						}); err != nil {
							t.Fatal("install audit materialization observer failed")
						}
						defer func() { _ = s.db.Callback().Query().Remove(callback) }()
						read := func() error {
							switch mode {
							case "tail":
								_, err := tenant.VerifyAuditTail()
								return err
							case "full_middle":
								_, err := tenant.VerifyAuditFull()
								return err
							default:
								_, err := tenant.ListAudit(0, 10)
								return err
							}
						}
						if err := read(); !errors.Is(err, audit.ErrIntegrity) {
							t.Error("oversized audit field was not rejected as corrupt")
						}
						if loaded < 0 || loaded > field.limit {
							t.Errorf("actual audit result exceeded byte bound: loaded=%d limit=%d", loaded, field.limit)
						}
						if field.column == "ip_summary" {
							if err := s.db.Model(&audit.Event{}).Where("id=?", target.ID).Update(field.column, strings.Repeat("界", 64)).Error; err != nil {
								t.Fatal("create UTF-8 byte-bound fixture failed")
							}
							loaded = -1
							if err := read(); !errors.Is(err, audit.ErrIntegrity) || loaded < 0 || loaded > field.limit {
								t.Error("audit read used character count instead of encoded bytes")
							}
						}
					})
				}
			})
		}
		if _, err := tenant.VerifyAuditFull(); err != nil {
			t.Fatal("original signed bytes did not remain verifiable after fixtures")
		}
	})
}

func TestAuditHeadReadsBoundFieldsBeforeMaterialization(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		tenant, _ := s.WithOrganization(testActorContext(t, initial.User.ID), initial.Organization.ID)
		var original auditChainHead
		if err := s.db.Where("organization_id=?", initial.Organization.ID).Take(&original).Error; err != nil {
			t.Fatal("read test audit head failed")
		}
		for _, field := range []struct {
			column, name string
			limit        int
		}{{"event_hash", "EventHash", 64}, {"key_version", "KeyVersion", 128}} {
			t.Run(field.column, func(t *testing.T) {
				prior := reflect.ValueOf(original).FieldByName(field.name).String()
				if err := s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Update(field.column, strings.Repeat("x", 1<<20)).Error; err != nil {
					t.Fatal("create oversized audit head fixture failed")
				}
				defer func() {
					if err := s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Update(field.column, prior).Error; err != nil {
						t.Error("restore original test audit head failed")
					}
				}()
				loaded := -1
				const callback = "audit_test_observe_actual_head_bound"
				if err := s.db.Callback().Query().After("gorm:query").Register(callback, func(db *gorm.DB) {
					if head, ok := db.Statement.Dest.(*auditChainHead); ok && db.Error == nil {
						loaded = len(reflect.ValueOf(*head).FieldByName(field.name).String())
					}
				}); err != nil {
					t.Fatal("install audit head observer failed")
				}
				defer func() { _ = s.db.Callback().Query().Remove(callback) }()
				for _, appendEvent := range []bool{false, true} {
					loaded = -1
					var err error
					if appendEvent {
						err = tenant.AppendAudit(AuditCommand{Action: "test.append", ObjectType: "test", ObjectID: "must-rollback", Result: "success"})
					} else {
						_, err = tenant.VerifyAuditFull()
					}
					if !errors.Is(err, audit.ErrIntegrity) || loaded < 0 || loaded > field.limit {
						t.Errorf("corrupt audit head reached Go or was accepted: loaded=%d limit=%d", loaded, field.limit)
					}
				}
			})
		}
	})
}

func TestInitialAuditAnchorReadIsBounded(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		original := strconv.FormatInt(initial.Organization.ID, 10)
		if err := s.db.Table("system_settings").Where("setting_key='initial_organization_id'").Update("value_json", strings.Repeat("1", 2<<20)).Error; err != nil {
			t.Fatal("create oversized initial audit anchor fixture failed")
		}
		// The 2 MiB fixture and its write are excluded. Observe the real SELECT
		// plus parser, not an approximation from SQL text or a post-read mock.
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		org, err := initialAuditOrganization(s.db.WithContext(t.Context()))
		runtime.ReadMemStats(&after)
		if org != 0 || !errors.Is(err, audit.ErrIntegrity) {
			t.Error("oversized initial audit anchor accepted")
		}
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 512<<10 {
			t.Errorf("initial audit anchor SELECT allocated oversized input: bytes=%d", allocated)
		}
		if err := s.db.Table("system_settings").Where("setting_key='initial_organization_id'").Update("value_json", original).Error; err != nil {
			t.Fatal("restore original anchor fixture failed")
		}
		if org, err := initialAuditOrganization(s.db.WithContext(t.Context())); err != nil || org != initial.Organization.ID {
			t.Fatal("valid initial audit anchor rejected")
		}
	})
}

func TestAuditReadsPreserveCanonicalLimitsAndRejectEmptyReplay(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		tenant, _ := s.WithOrganization(testActorContext(t, initial.User.ID), initial.Organization.ID)
		events, err := tenant.ListAudit(0, 10)
		if err != nil || len(events) != 1 {
			t.Fatal("read valid canonical-boundary fixture failed")
		}
		event := events[0]
		event.Action, event.ObjectType, event.Result = strings.Repeat("a", 128), strings.Repeat("b", 128), strings.Repeat("c", 128)
		event.ObjectID = strings.Repeat("界", 42) + "ab" // Exactly 128 UTF-8 bytes.
		event.IPSummary, event.UserAgentSummary = strings.Repeat("i", 128), strings.Repeat("u", 128)
		event.DiffSummary = strings.Repeat("d", 1024)
		writeSignedFixture := func() {
			t.Helper()
			var err error
			event, err = audit.Seal(event, s.auditSigner)
			if err != nil {
				t.Fatal("seal canonical-boundary fixture failed")
			}
			// Test-only signed seed, not a public update route or an assertion
			// that a corrupt database can forge the external signing key.
			if err := s.db.Model(&audit.Event{}).Where("id=?", event.ID).Updates(map[string]any{
				"action": event.Action, "object_type": event.ObjectType, "result": event.Result,
				"object_id": event.ObjectID, "ip_summary": event.IPSummary, "user_agent_summary": event.UserAgentSummary,
				"diff_summary": event.DiffSummary, "event_hmac": event.EventHMAC,
			}).Error; err != nil {
				t.Fatal("store canonical-boundary fixture failed")
			}
			if err := s.db.Model(&auditChainHead{}).Where("organization_id=?", initial.Organization.ID).Update("event_hash", event.EventHMAC).Error; err != nil {
				t.Fatal("bind canonical-boundary test head failed")
			}
		}
		writeSignedFixture()
		for _, full := range []bool{false, true} {
			if result, err := tenant.verifyAudit(full); err != nil || result.VerifiedCount != 1 {
				t.Fatal("exact canonical limits rejected by verification")
			}
		}
		if got, err := tenant.ListAudit(0, 10); err != nil || len(got) != 1 || got[0].EventHMAC != event.EventHMAC || got[0].ObjectID != event.ObjectID || got[0].DiffSummary != event.DiffSummary {
			t.Fatal("listing changed authenticated canonical-boundary bytes")
		}
		// Empty is a legitimate signed summary. Replacing an oversized value
		// with empty would silently recreate its valid original MAC. The SQL
		// overflow projection must remain invalid instead.
		event.DiffSummary = ""
		writeSignedFixture()
		if err := s.db.Model(&audit.Event{}).Where("id=?", event.ID).Update("diff_summary", strings.Repeat("x", 1025)).Error; err != nil {
			t.Fatal("create empty-summary replay counterexample failed")
		}
		if _, err := tenant.VerifyAuditFull(); !errors.Is(err, audit.ErrIntegrity) {
			t.Error("oversized summary recreated valid empty-summary MAC")
		}
		if got, err := tenant.ListAudit(0, 10); !errors.Is(err, audit.ErrIntegrity) || len(got) != 0 {
			t.Error("listing returned a partial page or empty-summary replay")
		}
	})
}
