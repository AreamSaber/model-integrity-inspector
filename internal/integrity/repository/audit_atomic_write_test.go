package repository

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestAuditAtomicWritesRollbackRealOperations(t *testing.T) {
	for _, fault := range []string{"event_insert", "head_update"} {
		t.Run(fault, func(t *testing.T) {
			for _, operation := range []string{"append", "provider", "password"} {
				t.Run(operation, func(t *testing.T) {
					eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
						requireMigrate(t, s)
						initial := requireInitialize(t, s)
						ctx := testActorContext(t, initial.User.ID)
						tenant, err := s.WithOrganization(ctx, initial.Organization.ID)
						if err != nil {
							t.Fatal("create real audit scope", err)
						}
						invoke := func() error {
							switch operation {
							case "provider":
								return tenant.CreateProvider(&Provider{Name: "Atomic audit provider"})
							case "password":
								return s.ChangePassword(ctx, initial.User.ID, initial.User.PasswordHash, "test-only-replacement-hash", time.Now().UTC())
							default:
								return tenant.AppendAudit(AuditCommand{Action: "test.atomic_append", ObjectType: "test", ObjectID: "atomic", Result: "success"})
							}
						}
						before := readAuditAtomicState(t, s)
						remove := suppressAuditAtomicWrite(t, s, fault)
						if err := invoke(); !errors.Is(err, audit.ErrIntegrity) {
							t.Fatal("silently suppressed audit write must fail as integrity error", err)
						}
						if !reflect.DeepEqual(before, readAuditAtomicState(t, s)) {
							t.Fatal("audit failure changed business state, events or chain heads")
						}
						remove()
						if err := invoke(); err != nil {
							t.Fatal("real operation failed after removing only the SQL fault", err)
						}
						after := readAuditAtomicState(t, s)
						if len(after.Events) != len(before.Events)+1 || len(after.Heads) != 1 || after.Heads[0].EventCount != before.Heads[0].EventCount+1 {
							t.Fatal("recovered operation did not append exactly one event and advance head")
						}
						if operation == "provider" && len(after.Providers) != len(before.Providers)+1 {
							t.Fatal("recovered provider mutation missing")
						}
						if operation == "password" && (len(after.Users) != 1 || after.Users[0].PasswordHash != "test-only-replacement-hash") {
							t.Fatal("recovered password mutation missing")
						}
						if err := s.VerifyAllAudit(t.Context(), true); err != nil {
							t.Fatal("recovered actual HMAC chain did not verify", err)
						}
					})
				})
			}
		})
	}
}

func TestAuditAtomicWritesRollbackInitialization(t *testing.T) {
	for _, fault := range []string{"event_insert", "head_update"} {
		t.Run(fault, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				requireMigrate(t, s)
				before := readAuditAtomicInitializationCounts(t, s)
				remove := suppressAuditAtomicWrite(t, s, fault)
				result, err := s.Initialize(testActorContext(t, 0), initialState())
				if !errors.Is(err, audit.ErrIntegrity) || !reflect.DeepEqual(result, InitializationResult{}) {
					t.Fatal("suppressed genesis audit committed or returned partial initialization", err)
				}
				if !reflect.DeepEqual(before, readAuditAtomicInitializationCounts(t, s)) {
					t.Fatal("suppressed genesis audit left initialization state")
				}
				remove()
				initial := requireInitialize(t, s)
				tenant, err := s.WithOrganization(t.Context(), initial.Organization.ID)
				if err != nil {
					t.Fatal(err)
				}
				verified, err := tenant.VerifyAuditFull()
				if err != nil || verified.EventCount != 1 || verified.VerifiedCount != 1 {
					t.Fatal("real initialization did not recover with one authentic genesis event", err)
				}
			})
		})
	}
}

type auditAtomicState struct {
	Events    []audit.Event
	Heads     []auditChainHead
	Providers []Provider
	Users     []User
	Sessions  []Session
}

// Only controlled test data is compared. Neither password values nor event
// contents/hashes are printed when an assertion fails.
func readAuditAtomicState(t *testing.T, s *Store) auditAtomicState {
	t.Helper()
	var out auditAtomicState
	for _, item := range []struct {
		dest  any
		order string
	}{{&out.Events, "organization_id,sequence"}, {&out.Heads, "organization_id"}, {&out.Providers, "id"}, {&out.Users, "id"}, {&out.Sessions, "id"}} {
		if err := s.db.Order(item.order).Find(item.dest).Error; err != nil {
			t.Fatal("read actual atomic audit fixture", err)
		}
	}
	return out
}

func readAuditAtomicInitializationCounts(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	out := make(map[string]int64)
	for _, table := range []string{"organizations", "users", "organization_members", "roles", "permissions", "role_permissions", "member_roles", "system_settings", "integrity_audit_logs", "integrity_audit_chain_heads"} {
		var count int64
		if err := s.db.Table(table).Count(&count).Error; err != nil {
			t.Fatal("read initialization fixture table count", err)
		}
		out[table] = count
	}
	return out
}

// This fixture uses the database's actual affected-row semantics, not an ORM
// callback that fabricates RowsAffected. Identifiers are fixed closed literals.
func suppressAuditAtomicWrite(t *testing.T, s *Store, fault string) func() {
	t.Helper()
	table, operation := "integrity_audit_logs", "INSERT"
	if fault == "head_update" {
		table, operation = "integrity_audit_chain_heads", "UPDATE"
	} else if fault != "event_insert" {
		t.Fatal("unknown atomic audit fixture fault")
	}
	statements := []string{"CREATE TRIGGER audit_atomic_suppress BEFORE " + operation + " ON " + table + " BEGIN SELECT RAISE(IGNORE); END"}
	if s.driver == "postgres" {
		statements = []string{
			"CREATE FUNCTION audit_atomic_suppress_write() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$",
			"CREATE TRIGGER audit_atomic_suppress BEFORE " + operation + " ON " + table + " FOR EACH ROW EXECUTE FUNCTION audit_atomic_suppress_write()",
		}
	}
	for _, statement := range statements {
		if err := s.db.Exec(statement).Error; err != nil {
			t.Fatal("install exact atomic audit SQL fault")
		}
	}
	removed := false
	remove := func() {
		t.Helper()
		if removed {
			return
		}
		removed = true
		drop := "DROP TRIGGER audit_atomic_suppress"
		if s.driver == "postgres" {
			drop += " ON " + table
		}
		if err := s.db.Exec(drop).Error; err != nil {
			t.Error("remove exact atomic audit SQL fault")
		}
		if s.driver == "postgres" {
			if err := s.db.Exec("DROP FUNCTION audit_atomic_suppress_write()").Error; err != nil {
				t.Error("remove exact atomic audit SQL function")
			}
		}
	}
	t.Cleanup(remove)
	return remove
}
