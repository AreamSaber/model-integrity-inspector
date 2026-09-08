package repository

import (
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestSystemMaintenanceDigestBindsEveryEventFactAndObjectBound(t *testing.T) {
	base := maintenanceEvent{OperationID: math.MaxInt64, Sequence: 1, Scope: "system", Action: "begin", ActorID: 1, SessionID: 2, ReasonCode: "backup.manual", BeforeMode: MaintenanceNormal, AfterMode: MaintenanceBackupFreeze, BeforeVersion: 1, AfterVersion: 2, BeforeGeneration: 0, AfterGeneration: 1, Generation: 1, InitiatedBy: 1, InitiatingSessionID: 2, PreviousStatus: "none", Status: "active", ObservedAtMicros: 1000000, LeaseUntilMicros: 61000000, DeadlineMicros: 3601000000}
	digest, err := maintenanceEventDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Digest = digest
	if len(maintenanceEventObject(base)) != 84 {
		t.Fatal("system event ObjectID exceeded or changed its existing audit bound")
	}
	for i := 0; i < reflect.TypeFor[maintenanceEvent]().NumField(); i++ {
		field := reflect.TypeFor[maintenanceEvent]().Field(i)
		if field.Name == "Digest" {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			changed := base
			value := reflect.ValueOf(&changed).Elem().Field(i)
			switch value.Kind() {
			case reflect.Int64:
				value.SetInt(value.Int() ^ 1)
			case reflect.String:
				value.SetString(value.String() + "x")
			default:
				t.Fatal("new event fact needs an explicit mutation oracle")
			}
			actual, err := maintenanceEventDigest(changed)
			if err == nil && actual == digest {
				t.Fatal("event fact was not bound to the authenticated digest")
			}
		})
	}
}

// The fixture performs the actual indexed source reads, then injects a corrupt
// row set in the ORM result only. Re-sealing selected cases with the synthetic
// signer distinguishes scope/reason/time rejection from a mere invalid MAC.
// This does not claim an attacker can forge production audit signatures.
func TestSystemMaintenanceAuthenticatesAuditActorReasonTimeAndRowSet(t *testing.T) {
	for _, mode := range []string{"mac", "actor", "reason", "time", "missing", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				_ = beginTestMaintenance(t, s, ctx, auth)
				var current maintenanceState
				if err := s.db.Where("id=1").Take(&current).Error; err != nil {
					t.Fatal(err)
				}
				injected := false
				if err := s.db.Callback().Query().After("gorm:query").Register("maintenance_test_corrupt_audit_source", func(db *gorm.DB) {
					events, ok := db.Statement.Dest.(*[]audit.Event)
					if !ok || len(*events) != 1 || (*events)[0].Action != "system.maintenance.begin" || db.Error != nil {
						return
					}
					injected = true
					event := (*events)[0]
					switch mode {
					case "mac":
						event.EventHMAC = strings.Repeat("0", 64)
						*events = []audit.Event{event}
						return
					case "actor":
						other := auth.UserID + 1
						event.ActorID = &other
					case "reason":
						event.DiffSummary = `{"reason_code":"backup.upgrade"}`
					case "time":
						event.CreatedAt = time.UnixMicro(current.UpdatedAtMicros - 1)
					case "missing":
						*events = nil
						return
					case "duplicate":
						*events = []audit.Event{event, event}
						return
					}
					sealed, err := audit.Seal(event, s.auditSigner)
					if err != nil {
						_ = db.AddError(err)
						return
					}
					*events = []audit.Event{sealed}
				}); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.db.Callback().Query().Remove("maintenance_test_corrupt_audit_source") }()
				_, err := s.ReadMaintenanceState(ctx)
				want := ErrMaintenanceSource
				if mode == "mac" {
					want = audit.ErrIntegrity
				}
				if !injected || !errors.Is(err, want) {
					t.Fatal("maintenance accepted mismatched signed audit source", mode, err)
				}
			})
		})
	}
}
