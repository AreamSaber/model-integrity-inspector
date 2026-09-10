package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

type backupCompletionFixture struct {
	app                 *application
	cfg                 Config
	db                  *sql.DB
	ctx                 context.Context
	auth                repository.ManagementAuthority
	session             repository.Session
	lease               *repository.MaintenanceLease
	directory, objectID string
	manifest            backupmanifest.Manifest
	body                map[string][]byte
	scope               secret.BackupScope
	sealer              *secret.BackupSealer
	opener              *secret.BackupOpener
	limits              secret.BackupLimits
	sealed              secret.BackupReceipt
	written             privatefile.Receipt
}

func backupCompletionDigest(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func newBackupCompletionFixture(t *testing.T, driver string) *backupCompletionFixture {
	t.Helper()
	cfg := pipelineDatabase(t, testConfig(t), driver)
	app, err := prepare(t.Context(), cfg)
	if err != nil {
		t.Fatal("prepare actual backup completion app", err)
	}
	t.Cleanup(func() {
		if err := app.close(); err != nil {
			t.Error("completion app close")
		}
	})
	ctx := audit.WithActor(t.Context(), audit.Actor{ReasonCode: "backup.manual"})
	initial, err := app.store.Initialize(ctx, repository.Initialization{OrganizationName: "Backup completion fixture", Username: "root", PasswordHash: "synthetic-test-only-hash", AdminRole: "admin", Roles: []repository.InitialRole{{Name: "admin", Permissions: []string{"run.read"}}}})
	if err != nil {
		t.Fatal("initialize actual completion app", err)
	}
	ctx = audit.WithActor(t.Context(), audit.Actor{ActorID: initial.User.ID, ReasonCode: "backup.manual"})
	now := time.Now().UTC().Truncate(time.Microsecond)
	tokenHash := backupCompletionDigest([]byte(fmt.Sprintf("completion-test-session-%d", initial.User.ID)))
	session := repository.Session{UserID: initial.User.ID, SessionHash: tokenHash, CSRFHash: tokenHash, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := app.store.CreateSessionIfPasswordCurrent(ctx, &session, initial.User.PasswordHash, now); err != nil {
		t.Fatal("create actual live completion session", err)
	}
	auth := repository.ManagementAuthority{UserID: initial.User.ID, SessionID: session.ID}
	state, err := app.store.ReadMaintenanceState(ctx)
	if err != nil {
		t.Fatal("read initial maintenance", err)
	}
	lease, err := app.store.BeginBackupMaintenance(ctx, auth, repository.BackupMaintenanceRequest{ExpectedVersion: state.Version, ReasonCode: "backup.manual", MaxDuration: time.Hour})
	if err != nil {
		t.Fatal("begin actual backup maintenance", err)
	}
	key, err := secret.LoadKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion)
	if err != nil {
		t.Fatal("load actual fixture key")
	}
	sealer, opener, err := key.NewBackupCapabilities()
	if err != nil {
		t.Fatal("derive actual backup purpose keys")
	}
	id, started := lease.BackupIdentity()
	f := &backupCompletionFixture{app: app, cfg: cfg, db: openPipelineDatabase(t, cfg), ctx: ctx, auth: auth, session: session, lease: lease, directory: backupCompletionPrivateDirectory(t), objectID: fmt.Sprintf("%064x", id), body: make(map[string][]byte), sealer: sealer, opener: opener, limits: secret.BackupLimits{MaxBytes: 2 << 20, MaxEntries: 16, Timeout: 10 * time.Second}}
	file := func(id string) backupmanifest.File {
		body := []byte("explicitly synthetic completion payload: " + id)
		f.body[id] = body
		return backupmanifest.File{EntryID: id, Bytes: int64(len(body)), SHA256: backupCompletionDigest(body)}
	}
	// These bounded manifest/database/artifact facts are deliberately synthetic.
	// Only lease identity, live authority and the physical AEAD/DB flow are real;
	// this adapter test does NOT acquire a full product database snapshot.
	f.manifest = backupmanifest.Manifest{SchemaVersion: backupmanifest.Version, BackupID: id, StartedAtMicros: started, SnapshotAtMicros: started, ApplicationVersion: "0.1.0-dev", SourceCommit: strings.Repeat("c", 40), Database: backupmanifest.Database{Driver: "sqlite", ServerVersion: "3.52.0", SnapshotMethod: "sqlite_online_backup", File: file("database-snapshot")}, Migrations: []backupmanifest.Migration{{Version: 1, Name: "synthetic_fixture", SHA256: backupCompletionDigest([]byte("synthetic fixture migration"))}}, KeyVersions: []string{cfg.MasterKeyVersion}, AuditHistory: "complete", AuditAnchors: []backupmanifest.AuditAnchor{{OrganizationID: initial.Organization.ID, CanonicalizationVersion: "mii.audit.v1"}}, Jobs: []backupmanifest.JobSummary{{OrganizationID: initial.Organization.ID}}, ConfigTemplate: file("config-template")}
	if driver == "postgres" {
		f.manifest.Database.Driver = "postgres"
		f.manifest.Database.ServerVersion = "18.6"
		f.manifest.Database.SnapshotMethod = "pg_dump_snapshot"
	}
	for _, category := range []string{"rule", "template", "tokenizer", "scoring"} {
		f.manifest.Artifacts = append(f.manifest.Artifacts, backupmanifest.Artifact{Category: category, Version: "fixture-v1", File: file(category + "-fixture")})
	}
	encoded, sum, err := backupmanifest.Encode(f.manifest)
	if err != nil {
		t.Fatal("encode real manifest grammar", err)
	}
	f.body["backup-manifest"] = encoded
	f.scope = secret.BackupScope{BackupID: id, ManifestHash: sum}
	return f
}

func (f *backupCompletionFixture) path() string {
	return filepath.Join(f.directory, f.objectID+".mii-backup")
}

func (f *backupCompletionFixture) publish(t *testing.T, mode string) {
	t.Helper()
	entries, err := backupmanifest.Entries(f.manifest)
	if err != nil {
		t.Fatal("derive manifest entry plan", err)
	}
	f.written, err = privatefile.WriteNew(f.ctx, f.path(), privatefile.Limits{MaxBytes: 3 << 20, Timeout: 10 * time.Second}, func(ctx context.Context, dst io.Writer) error {
		var err error
		f.sealed, err = f.sealer.Seal(ctx, f.scope, f.limits, dst, func(_ context.Context, a *secret.BackupArchiveWriter) error {
			for _, planned := range entries {
				entry := secret.BackupEntry{Kind: planned.Kind, ID: planned.File.EntryID}
				body := f.body[entry.ID]
				if planned.File.EntryID == "config-template" {
					switch mode {
					case "wrong_entry":
						entry.ID = "unexpected-entry"
					case "wrong_kind":
						entry.Kind = "rule"
					case "missing_entry":
						continue
					case "wrong_body":
						body = []byte(strings.Repeat("x", len(body)))
					case "short_body":
						body = body[:len(body)-1]
					}
				}
				if err := a.WriteEntry(entry, func(_ context.Context, w io.Writer) error { _, err := w.Write(body); return err }); err != nil {
					return err
				}
			}
			return nil
		})
		return err
	})
	if err != nil || !f.written.Published || f.sealed.Version != secret.BackupFormatVersion {
		t.Fatal("actual Seal/WriteNew failed", err)
	}
	// Independently prove every malformed-inventory fixture is nevertheless a
	// complete authentic AEAD archive with the original real write receipt.
	var opened secret.BackupReceipt
	verified, err := privatefile.Read(f.ctx, f.path(), privatefile.Limits{MaxBytes: f.written.Size, Timeout: 10 * time.Second}, func(ctx context.Context, r io.Reader) error {
		var err error
		opened, err = f.opener.Open(ctx, f.scope, f.limits, r, func(_ context.Context, _ secret.BackupEntry, r io.Reader) error {
			_, err := io.Copy(io.Discard, r)
			return err
		})
		return err
	})
	if err != nil || opened != f.sealed || verified.Size != f.written.Size || verified.SHA256 != f.written.SHA256 {
		t.Fatal("fixture did not independently authenticate entire original archive", err)
	}
}

func (f *backupCompletionFixture) finish() (repository.BackupCompletionReceipt, error) {
	return finishBackupArchive(f.ctx, f.lease, f.directory, f.objectID, f.manifest, f.opener, f.limits, f.sealed, f.written)
}

func (f *backupCompletionFixture) assertNotReady(t *testing.T) {
	t.Helper()
	var receipts, completeEvents, completeAudit int
	if err := f.db.QueryRowContext(t.Context(), "SELECT (SELECT count(*) FROM system_backup_receipts),(SELECT count(*) FROM system_maintenance_events WHERE action='complete'),(SELECT count(*) FROM integrity_audit_logs WHERE action='system.maintenance.complete')").Scan(&receipts, &completeEvents, &completeAudit); err != nil {
		t.Fatal("read failed completion facts")
	}
	if receipts != 0 || completeEvents != 0 || completeAudit != 0 {
		t.Fatal("failed completion left ready facts")
	}
	var mode, status string
	id, _ := f.lease.BackupIdentity()
	if err := f.db.QueryRowContext(t.Context(), "SELECT mode FROM system_maintenance WHERE id=1").Scan(&mode); err != nil {
		t.Fatal("read gate after failure")
	}
	if err := f.db.QueryRowContext(t.Context(), "SELECT status FROM system_maintenance_operations WHERE id=$1", id).Scan(&status); err != nil {
		t.Fatal("read operation after failure")
	}
	if mode != string(repository.MaintenanceBackupFreeze) || status != "active" {
		t.Fatal("failed completion aborted or reopened admission")
	}
	if _, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, id); err == nil {
		t.Fatal("failed completion became authorized downloadable")
	}
}

func TestBackupArchiveCompletionActualFlow(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		t.Run(driver, func(t *testing.T) {
			f := newBackupCompletionFixture(t, driver)
			f.publish(t, "")
			if _, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, f.manifest.BackupID); !errors.Is(err, repository.ErrNotFound) {
				t.Fatal("ready before readback", err)
			}
			got, err := f.finish()
			if err != nil {
				t.Fatal("actual archive completion", err)
			}
			read, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, f.manifest.BackupID)
			if err != nil || read != got {
				t.Fatal("authorized durable completion differs", err)
			}
			if got.ArchiveSHA256 != f.sealed.ArchiveSHA256 || got.ArchiveBytes != f.written.Size || got.ObjectID != f.objectID || got.Entries != 7 || got.StartedAtMicros != f.manifest.StartedAtMicros {
				t.Fatal("completion did not bind original physical observations")
			}
			state, err := f.app.store.ReadMaintenanceState(f.ctx)
			if err != nil || state.Mode != repository.MaintenanceNormal {
				t.Fatal("successful completion did not release admission")
			}
			if err := f.app.store.VerifyAllAudit(f.ctx, true); err != nil {
				t.Fatal("completion full audit verification", err)
			}
			if _, err := os.Stat(f.path()); err != nil {
				t.Fatal("completed archive removed")
			}
		})
	}
}

func TestBackupArchiveCompletionPhysicalFailuresNeverReady(t *testing.T) {
	for _, mode := range []string{"wrong_key", "wrong_entry", "wrong_kind", "missing_entry", "wrong_body", "short_body", "truncate_tail", "extra_tail", "wrong_manifest", "wrong_backup_identity", "wrong_started_identity", "unpublished_receipt", "wrong_write_size", "wrong_write_hash", "wrong_seal_receipt", "missing_file", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			for _, driver := range []string{"sqlite", "postgres"} {
				t.Run(driver, func(t *testing.T) {
					f := newBackupCompletionFixture(t, driver)
					f.publish(t, mode)
					switch mode {
					case "wrong_key":
						key, err := secret.NewKeyRing(f.cfg.MasterKeyVersion, map[string][]byte{f.cfg.MasterKeyVersion: bytes.Repeat([]byte{0x19}, 32)})
						if err != nil {
							t.Fatal("wrong key fixture")
						}
						_, f.opener, err = key.NewBackupCapabilities()
						if err != nil {
							t.Fatal("wrong opener fixture")
						}
					case "truncate_tail":
						if err := os.Truncate(f.path(), f.written.Size-1); err != nil {
							t.Fatal("truncate fault fixture")
						}
					case "extra_tail":
						// #nosec G304 -- exact newly published test-owned encrypted archive.
						file, err := os.OpenFile(f.path(), os.O_APPEND|os.O_WRONLY, 0)
						if err != nil {
							t.Fatal("append fault fixture")
						}
						_, writeErr := file.Write([]byte{1})
						closeErr := file.Close()
						if writeErr != nil || closeErr != nil {
							t.Fatal("append tail fixture")
						}
					case "wrong_manifest":
						f.manifest.SourceCommit = strings.Repeat("e", 40)
					case "wrong_backup_identity":
						f.manifest.BackupID++
					case "wrong_started_identity":
						f.manifest.StartedAtMicros--
						f.manifest.SnapshotAtMicros--
					case "unpublished_receipt":
						f.written.Published = false
					case "wrong_write_size":
						f.written.Size++
					case "wrong_write_hash":
						f.written.SHA256 = strings.Repeat("e", 64)
					case "wrong_seal_receipt":
						f.sealed.PlaintextBytes++
					case "missing_file":
						if err := os.Remove(f.path()); err != nil {
							t.Fatal("missing archive fixture")
						}
					case "cancel":
						ctx, cancel := context.WithCancel(f.ctx)
						cancel()
						f.ctx = ctx
					}
					var before []byte
					var beforeInfo os.FileInfo
					if mode != "missing_file" {
						// #nosec G304 -- original bytes of this exact test-owned archive before adapter entry.
						var err error
						before, err = os.ReadFile(f.path())
						if err != nil {
							t.Fatal("read original encrypted fault fixture")
						}
						beforeInfo, err = os.Stat(f.path())
						if err != nil {
							t.Fatal("stat original encrypted fixture")
						}
					}
					if mode == "truncate_tail" || mode == "extra_tail" {
						consumed := 0
						opened, openErr := f.opener.Open(f.ctx, f.scope, f.limits, bytes.NewReader(before), func(_ context.Context, _ secret.BackupEntry, r io.Reader) error {
							_, err := io.Copy(io.Discard, r)
							if err == nil {
								consumed++
							}
							return err
						})
						if openErr == nil || opened != (secret.BackupReceipt{}) || consumed != f.sealed.Entries {
							t.Fatal("late-tail counterexample did not pass every plaintext callback before failing")
						}
					}
					got, err := f.finish()
					if err == nil || got != (repository.BackupCompletionReceipt{}) || strings.Contains(err.Error(), f.directory) {
						t.Fatal("bad archive returned success or leaked path", err)
					}
					f.assertNotReady(t)
					if mode != "missing_file" {
						// #nosec G304 -- compare only the exact original encrypted fixture, never an input path.
						after, err := os.ReadFile(f.path())
						if err != nil || !bytes.Equal(before, after) {
							t.Fatal("failed readback removed/modified private archive")
						}
						afterInfo, err := os.Stat(f.path())
						if err != nil || !os.SameFile(beforeInfo, afterInfo) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
							t.Fatal("failed readback replaced/touched source identity")
						}
					}
				})
			}
		})
	}
}
