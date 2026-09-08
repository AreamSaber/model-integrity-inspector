package repository

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/migrations"
)

func maintenanceInitializationCounts(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	counts := make(map[string]int64)
	for _, table := range []string{"organizations", "users", "organization_members", "roles", "permissions", "role_permissions", "member_roles", "system_settings", "integrity_rule_bundles", "integrity_template_bundles", "integrity_audit_logs", "integrity_audit_chain_heads"} {
		var count int64
		if err := s.db.Table(table).Count(&count).Error; err != nil {
			t.Fatal("read initialization fixture count", table, err)
		}
		counts[table] = count
	}
	return counts
}

func assertMaintenanceInitializationUnchanged(t *testing.T, s *Store, before map[string]int64) {
	t.Helper()
	if after := maintenanceInitializationCounts(t, s); !reflect.DeepEqual(before, after) {
		t.Fatalf("initialization left rows: before=%v after=%v", before, after)
	}
}

func TestSystemMaintenanceInitializationRejectsIsolatedEmptyDatabase(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		// This is a synthetic isolated intermediate state, not a restore API.
		if err := s.db.Model(&maintenanceState{}).Where("id=1").Updates(map[string]any{"mode": MaintenanceRestoreIsolated, "version": 2, "updated_at_micros": time.Now().UTC().UnixMicro()}).Error; err != nil {
			t.Fatal(err)
		}
		before := maintenanceInitializationCounts(t, s)
		initialized, err := s.SetupStatus(t.Context())
		if err != nil || initialized {
			t.Fatal("fixture unexpectedly initialized", initialized, err)
		}
		result, err := s.Initialize(testActorContext(t, 0), initialState())
		if !errors.Is(err, ErrRestoreIsolated) || result.Organization.ID != 0 || result.User.ID != 0 {
			t.Errorf("isolated empty database accepted initialization: error=%v organization_created=%t user_created=%t", err, result.Organization.ID != 0, result.User.ID != 0)
		}
		assertMaintenanceInitializationUnchanged(t, s, before)
	})
}

func TestSystemMaintenanceInitializationNormalAndFrozen(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		initial := requireInitialize(t, s)
		if initial.Organization.ID <= 0 || initial.User.ID <= 0 {
			t.Fatal("normal first initialization missing identity")
		}
		if initialized, err := s.SetupStatus(t.Context()); err != nil || !initialized {
			t.Fatal("normal initialization missing marker", err)
		}
		if err := s.VerifyAllAudit(t.Context(), true); err != nil {
			t.Fatal("normal initialization audit invalid", err)
		}
		before := maintenanceInitializationCounts(t, s)
		if _, err := s.Initialize(testActorContext(t, 0), initialState()); !errors.Is(err, ErrAlreadyInitialized) {
			t.Fatal("normal duplicate initialization", err)
		}
		assertMaintenanceInitializationUnchanged(t, s, before)
		auth := managementSession(t, s, initial.User)
		ctx := testActorContext(t, initial.User.ID)
		lease := beginTestMaintenance(t, s, ctx, auth)
		before = maintenanceInitializationCounts(t, s)
		if _, err := s.Initialize(testActorContext(t, 0), initialState()); !errors.Is(err, ErrSystemMaintenance) {
			t.Fatal("frozen initialization did not enter persistent gate first", err)
		}
		assertMaintenanceInitializationUnchanged(t, s, before)
		if err := lease.Abort(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestSystemMaintenanceInitializationMissingGateFailsClosed(t *testing.T) {
	for _, missing := range []string{"row", "table"} {
		t.Run(missing, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				requireMigrate(t, s)
				want := ErrMaintenanceSource
				if missing == "row" {
					if err := s.db.Where("id=1").Delete(&maintenanceState{}).Error; err != nil {
						t.Fatal(err)
					}
				} else {
					if err := s.db.Exec("DROP TABLE system_maintenance").Error; err != nil {
						t.Fatal(err)
					}
					want = ErrUnavailable
				}
				before := maintenanceInitializationCounts(t, s)
				if _, err := s.Initialize(testActorContext(t, 0), initialState()); !errors.Is(err, want) {
					t.Fatal("missing gate allowed initialization or leaked driver failure", err)
				}
				assertMaintenanceInitializationUnchanged(t, s, before)
			})
		})
	}
}

func TestSystemMaintenanceInitializationTransactionFailureRollsBack(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
		requireMigrate(t, s)
		before := maintenanceInitializationCounts(t, s)
		invalid := initialState()
		invalid.AdminRole = "absent-role"
		if _, err := s.Initialize(testActorContext(t, 0), invalid); !errors.Is(err, ErrConfiguration) {
			t.Fatal("mid-transaction configuration rejection", err)
		}
		assertMaintenanceInitializationUnchanged(t, s, before)
		inserted := false
		const callback = "maintenance_initialization_after_audit"
		if err := s.db.Callback().Create().After("gorm:create").Register(callback, func(db *gorm.DB) {
			event, ok := db.Statement.Dest.(*audit.Event)
			if ok && event.Action == "system.initialize" && db.Error == nil {
				inserted = true
				_ = db.AddError(errors.New("synthetic initialization failure must never escape"))
			}
		}); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = s.db.Callback().Create().Remove(callback) }()
		result, err := s.Initialize(testActorContext(t, 0), initialState())
		if !inserted || !errors.Is(err, ErrUnavailable) || result.Organization.ID != 0 || result.User.ID != 0 {
			t.Fatal("actual post-audit insertion failure was not rolled back safely", inserted, err)
		}
		assertMaintenanceInitializationUnchanged(t, s, before)
		assertMaintenanceNoOperation(t, s, t.Context())
	})
}

func TestSystemMaintenanceInitializationHistoricalFixtureMatchesNormal(t *testing.T) {
	for _, mode := range []string{"normal", "schema17"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				var initial InitializationResult
				if mode == "normal" {
					requireMigrate(t, s)
					initial = requireInitialize(t, s)
				} else {
					set, err := migrations.ForDialect(s.driver)
					if err != nil {
						t.Fatal(err)
					}
					if err := s.migrate(t.Context(), set[:17]); err != nil {
						t.Fatal(err)
					}
					initial = derivedUpgradeLegacyInitialization(t, s)
					if s.db.Migrator().HasTable("system_maintenance") {
						t.Fatal("historical fixture invented a current gate")
					}
				}
				org, user := initial.Organization, initial.User
				if org.ID <= 0 || org.Name != "Example" || org.Status != "active" || org.Timezone != "UTC" || org.QuotaJSON != "{}" || org.Version != 1 || org.FullResponseRetentionDays != 30 || org.ResponseEvidenceNotBeforeMicros != 0 {
					t.Fatal("initial organization semantics differ")
				}
				if user.ID <= 0 || user.Username != "Admin" || user.UsernameNormalized != "admin" || user.PasswordHash != initialState().PasswordHash || user.Status != "active" || !user.IsSystemAdmin || user.MustChangePassword || user.Version != 1 || user.FailedLoginCount != 0 || user.LockedUntil != nil {
					t.Fatal("initial user semantics differ")
				}
				wantCounts := map[string]int64{"organizations": 1, "users": 1, "organization_members": 1, "roles": 2, "permissions": 3, "role_permissions": 4, "member_roles": 1, "system_settings": 2, "integrity_rule_bundles": 0, "integrity_template_bundles": 0, "integrity_audit_logs": 1, "integrity_audit_chain_heads": 1}
				assertMaintenanceInitializationUnchanged(t, s, wantCounts)
				var grants []string
				if err := s.db.Table("roles r").Select("r.name || ':' || p.permission_code").Joins("JOIN role_permissions p ON p.organization_id=r.organization_id AND p.role_id=r.id").Where("r.organization_id=? AND r.is_builtin=?", org.ID, true).Order("r.name,p.permission_code").Find(&grants).Error; err != nil || !reflect.DeepEqual(grants, []string{"administrator:run.create", "administrator:target.read", "administrator:target.write", "viewer:target.read"}) {
					t.Fatal("historical role grants differ", err)
				}
				var assigned []string
				if err := s.db.Table("organization_members m").Select("r.name").Joins("JOIN member_roles mr ON mr.organization_id=m.organization_id AND mr.member_id=m.id").Joins("JOIN roles r ON r.organization_id=mr.organization_id AND r.id=mr.role_id").Where("m.organization_id=? AND m.user_id=? AND m.status='active' AND m.version=1", org.ID, user.ID).Find(&assigned).Error; err != nil || !reflect.DeepEqual(assigned, []string{"administrator"}) {
					t.Fatal("historical member grants differ", err)
				}
				for key, value := range map[string]string{"initialized": "true", "initial_organization_id": strconv.FormatInt(org.ID, 10)} {
					var actual string
					if err := s.db.Table("system_settings").Select("value_json").Where("setting_key=? AND version=1", key).Take(&actual).Error; err != nil || actual != value {
						t.Fatal("historical setup setting differs", key, err)
					}
				}
				var event audit.Event
				if err := s.db.Take(&event).Error; err != nil || event.OrganizationID != org.ID || event.ActorID == nil || *event.ActorID != user.ID || event.Action != "system.initialize" || event.ObjectType != "organization" || event.ObjectID != strconv.FormatInt(org.ID, 10) || event.Result != "success" || event.DiffSummary != `{"reason_code":"integration.test"}` {
					t.Fatal("historical initialization audit differs", err)
				}
				if err := s.VerifyAllAudit(t.Context(), true); err != nil {
					t.Fatal("historical initialization audit not authenticated", err)
				}
			})
		})
	}
}
