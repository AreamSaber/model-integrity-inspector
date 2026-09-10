package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

// These are explicitly synthetic coordinator facts. This repository suite proves
// persistence and authority, not that a physical archive was produced/restored.
func testBackupPublication(t *testing.T, lease *MaintenanceLease) BackupPublication {
	t.Helper()
	id, started := lease.BackupIdentity()
	if id <= 0 || started <= 0 {
		t.Fatal("begin identity absent")
	}
	return BackupPublication{BackupID: id, SnapshotAtMicros: started, ManifestVersion: backupmanifest.VersionV3, ManifestSHA256: strings.Repeat("a", 64), DatabaseSHA256: strings.Repeat("b", 64), ArchiveSHA256: strings.Repeat("c", 64), ArchiveBytes: 4096, PlaintextBytes: 2048, Entries: 3, WrappingKeyVersion: "test-v1", ObjectID: fmt.Sprintf("%064x", id)}
}

func TestBackupCompletionLifecycleAndHistoricalAuthorizedRead(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		initial, auth, ctx := managementFixture(t, s)
		viewer := managementFixtureUser(t, s, ctx, auth, "backup-viewer")
		viewerAuth := managementSession(t, s, viewer)
		lease := beginTestMaintenance(t, s, ctx, auth)
		p := testBackupPublication(t, lease)
		if _, err := s.ReadBackupCompletion(ctx, auth, p.BackupID); !errors.Is(err, ErrNotFound) {
			t.Fatal("active backup downloadable", err)
		}
		got, err := lease.CompleteBackup(ctx, p)
		if err != nil || got.BackupPublication != p || got.InitiatedBy != initial.User.ID || got.Generation != lease.generation {
			t.Fatal("complete", err)
		}
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		read, err := other.ReadBackupCompletion(ctx, auth, p.BackupID)
		if err != nil || read != got {
			t.Fatal("durable receipt read", err)
		}
		state, err := other.ReadMaintenanceState(ctx)
		if err != nil || state.Mode != MaintenanceNormal || state.Version != 3 {
			t.Fatal("successful completion did not reopen authenticated gate", err)
		}
		if _, err := s.ManageCreateUser(ctx, auth, ManagedUserCreate{Username: "after-backup", PasswordHash: "synthetic-only"}); err != nil {
			t.Fatal("business still frozen", err)
		}
		if value, err := lease.CompleteBackup(ctx, p); !errors.Is(err, ErrMaintenanceLeaseLost) || value != (BackupCompletionReceipt{}) {
			t.Fatal("duplicate completion", err)
		}
		if err := lease.Abort(ctx); !errors.Is(err, ErrMaintenanceLeaseLost) {
			t.Fatal("completed owner aborted", err)
		}
		next := beginTestMaintenance(t, s, ctx, auth)
		if value, err := other.ReadBackupCompletion(ctx, auth, p.BackupID); err != nil || value != got {
			t.Fatal("historical receipt lost under later freeze", err)
		}
		if err := next.Abort(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := other.ReadBackupCompletion(testActorContext(t, viewer.ID), viewerAuth, p.BackupID); !errors.Is(err, ErrManagementPermission) {
			t.Fatal("organization member read system backup", err)
		}
		if err := s.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("revoked_at", time.Now().UTC()).Error; err != nil {
			t.Fatal(err)
		}
		if value, err := other.ReadBackupCompletion(ctx, auth, p.BackupID); !errors.Is(err, ErrManagementSession) || value != (BackupCompletionReceipt{}) {
			t.Fatal("revoked session read completion", err)
		}
		for _, field := range []string{"archive_sha256", "object_id", "digest"} {
			if err := s.db.Model(&BackupCompletionReceipt{}).Where("backup_id=?", p.BackupID).Update(field, strings.Repeat("e", 64)).Error; err == nil {
				t.Fatal("immutable receipt updated", field)
			}
		}
		if err := s.db.Where("backup_id=?", p.BackupID).Delete(&BackupCompletionReceipt{}).Error; err == nil {
			t.Fatal("immutable receipt deleted")
		}
		if err := s.VerifyAllAudit(ctx, true); err != nil {
			t.Fatal("completion audit chain", err)
		}
	})
}

func TestBackupCompletionFailureIsAtomicAndZeroReceipt(t *testing.T) {
	for _, stage := range []string{"receipt", "event", "audit", "state", "canceled"} {
		t.Run(stage, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, s *Store, _ Config) {
				_, auth, ctx := managementFixture(t, s)
				lease := beginTestMaintenance(t, s, ctx, auth)
				p := testBackupPublication(t, lease)
				var original maintenanceState
				if err := s.db.Where("id=1").Take(&original).Error; err != nil {
					t.Fatal(err)
				}
				injected := false
				cancelCtx, cancel := context.WithCancel(ctx)
				defer cancel()
				callback := func(db *gorm.DB) {
					matched := false
					switch value := db.Statement.Dest.(type) {
					case *BackupCompletionReceipt:
						matched = stage == "receipt"
					case *maintenanceEvent:
						matched = stage == "event" && value.Action == "complete"
					case *audit.Event:
						matched = (stage == "audit" || stage == "canceled") && value.Action == "system.maintenance.complete"
					}
					if stage == "state" && db.Statement.Table == "system_maintenance" {
						matched = true
					}
					if !matched || db.Error != nil {
						return
					}
					injected = true
					if stage == "canceled" {
						cancel()
					} else {
						_ = db.AddError(errors.New("synthetic completion canary; must not escape"))
					}
				}
				if err := s.db.Callback().Create().After("gorm:create").Register("backup_completion_failure", callback); err != nil {
					t.Fatal(err)
				}
				if err := s.db.Callback().Update().After("gorm:update").Register("backup_completion_failure", callback); err != nil {
					t.Fatal(err)
				}
				value, err := lease.CompleteBackup(cancelCtx, p)
				if !injected || err == nil || value != (BackupCompletionReceipt{}) || strings.Contains(err.Error(), "canary") {
					t.Fatal("late failure accepted", injected, err)
				}
				if err := s.db.Callback().Create().Remove("backup_completion_failure"); err != nil {
					t.Fatal(err)
				}
				if err := s.db.Callback().Update().Remove("backup_completion_failure"); err != nil {
					t.Fatal(err)
				}
				var after maintenanceState
				if err := s.db.Where("id=1").Take(&after).Error; err != nil || !reflect.DeepEqual(original, after) {
					t.Fatal("failed completion changed gate", err)
				}
				for _, table := range []string{"system_backup_receipts", "system_maintenance_events", "integrity_audit_logs"} {
					q := s.db.Table(table)
					if table == "system_maintenance_events" {
						q = q.Where("action='complete'")
					}
					if table == "integrity_audit_logs" {
						q = q.Where("action='system.maintenance.complete'")
					}
					var count int64
					if err := q.Count(&count).Error; err != nil || count != 0 {
						t.Fatal("completion failure left facts", table, err)
					}
				}
				if _, err := lease.CompleteBackup(ctx, p); err != nil {
					t.Fatal("known rolled-back failure could not retry", err)
				}
			})
		})
	}
}

func TestBackupCompletionConcurrentOwnersOnlyOneCommit(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		_, auth, ctx := managementFixture(t, s)
		lease := beginTestMaintenance(t, s, ctx, auth)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		copyLease := *lease
		copyLease.store = other
		p := testBackupPublication(t, lease)
		var wg sync.WaitGroup
		results := make(chan error, 2)
		for _, candidate := range []*MaintenanceLease{lease, &copyLease} {
			wg.Go(func() {
				r, e := candidate.CompleteBackup(ctx, p)
				if e != nil && r != (BackupCompletionReceipt{}) {
					results <- errors.New("failure leaked receipt")
					return
				}
				results <- e
			})
		}
		wg.Wait()
		close(results)
		success, lost := 0, 0
		for err := range results {
			if err == nil {
				success++
			} else if errors.Is(err, ErrMaintenanceLeaseLost) {
				lost++
			} else {
				t.Fatal("unexpected competing result", err)
			}
		}
		if success != 1 || lost != 1 {
			t.Fatal("not exactly one completed owner", success, lost)
		}
	})
}

func TestBackupCompletionDigestBindsEveryFactAndRedacts(t *testing.T) {
	p := BackupPublication{BackupID: 1, SnapshotAtMicros: 2, ManifestVersion: backupmanifest.VersionV3, ManifestSHA256: strings.Repeat("a", 64), DatabaseSHA256: strings.Repeat("b", 64), ArchiveSHA256: strings.Repeat("c", 64), ArchiveBytes: 4096, PlaintextBytes: 2048, Entries: 3, WrappingKeyVersion: "key-v1", ObjectID: strings.Repeat("d", 64)}
	base := BackupCompletionReceipt{BackupPublication: p, Generation: 1, InitiatedBy: 1, InitiatingSessionID: 2, CompletedBy: 1, CompletingSessionID: 2, ReasonCode: "backup.manual", StartedAtMicros: 1, CompletedAtMicros: 3}
	want, err := backupCompletionDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	for _, publication := range []bool{false, true} {
		target := reflect.ValueOf(base)
		if publication {
			target = reflect.ValueOf(p)
		}
		for i := 0; i < target.NumField(); i++ {
			name := target.Type().Field(i).Name
			if name == "Digest" || name == "BackupPublication" {
				continue
			}
			changed := base
			value := reflect.ValueOf(&changed).Elem()
			if publication {
				value = value.FieldByName("BackupPublication")
			}
			value = value.Field(i)
			switch value.Kind() {
			case reflect.Int, reflect.Int64:
				value.SetInt(value.Int() + 1)
			case reflect.String:
				value.SetString(value.String() + "x")
			default:
				t.Fatal("new fact mutation missing")
			}
			actual, err := backupCompletionDigest(changed)
			if err == nil && actual == want {
				t.Fatal("unbound fact", name)
			}
		}
	}
	for _, v := range []any{p, base} {
		if data, err := json.Marshal(v); err == nil || len(data) != 0 {
			t.Fatal("serialized protected facts")
		}
		if strings.Contains(fmt.Sprintf("%+v", v), p.ObjectID) {
			t.Fatal("object name leaked")
		}
	}
	for _, version := range []string{"has/slash", "has:colon", strings.Repeat("a", 65)} {
		changed := p
		changed.WrappingKeyVersion = version
		if validBackupPublication(changed) {
			t.Fatal("invalid wrapping version accepted")
		}
	}
}

func TestBackupCompletionPreservesOriginalV1CanonicalBytes(t *testing.T) {
	e := maintenanceEvent{OperationID: 1, Sequence: 1, Scope: "system", Action: "begin", ActorID: 1, SessionID: 2, ReasonCode: "backup.manual", BeforeMode: MaintenanceNormal, AfterMode: MaintenanceBackupFreeze, BeforeVersion: 1, AfterVersion: 2, BeforeGeneration: 0, AfterGeneration: 1, Generation: 1, InitiatedBy: 1, InitiatingSessionID: 2, PreviousStatus: "none", Status: "active", ObservedAtMicros: 1000000, LeaseUntilMicros: 61000000, DeadlineMicros: 3601000000}
	original := `{"Version":"mii.system-maintenance-event.v1","OperationID":1,"Sequence":1,"Scope":"system","Action":"begin","ActorID":1,"SessionID":2,"ReasonCode":"backup.manual","BeforeMode":"normal","AfterMode":"backup_freeze","BeforeVersion":1,"AfterVersion":2,"BeforeGeneration":0,"AfterGeneration":1,"Generation":1,"InitiatedBy":1,"InitiatingSessionID":2,"PreviousStatus":"none","Status":"active","ObservedAtMicros":1000000,"LeaseUntilMicros":61000000,"DeadlineMicros":3601000000}`
	sum := sha256.Sum256(append([]byte("mii/system-maintenance/event/v1\x00"), []byte(original)...))
	got, err := maintenanceEventDigest(e)
	if err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatal("historical canonical bytes changed", err)
	}
}
