package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func targetFixture(t *testing.T, store *Store) (InitializationResult, *Tenant) {
	t.Helper()
	requireMigrate(t, store)
	initial := requireInitialize(t, store)
	tenant, err := store.WithOrganization(testActorContext(t, initial.User.ID), initial.Organization.ID)
	if err != nil {
		t.Fatal(err)
	}
	return initial, tenant
}

// Structurally valid encrypted fixture; crypto correctness is tested through
// the real KeyRing in target and secret service tests, not this persistence test.
func encryptedFixture(t *testing.T, orgID int64) SecretRecord {
	t.Helper()
	id, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	return SecretRecord{ID: id, OrganizationID: orgID, SecretVersion: 1, EncryptedDataKey: []byte("opaque-wrap-fixture"),
		Ciphertext: bytes.Repeat([]byte{0xa7}, 32), Nonce: bytes.Repeat([]byte{0xa3}, 12), KeyVersion: "v1", PayloadKeyVersion: "v1", Fingerprint: strings.Repeat("a", 64), LastFour: "1234"}
}

func targetRecordFixture() TargetRecord {
	return TargetRecord{Name: "target", Endpoint: "https://upstream.example/v1", EndpointFingerprint: strings.Repeat("b", 64), Protocol: "openai_chat", Model: "served-model", AuthType: "bearer", Status: "active", TagsJSON: "[]", OptionsJSON: `{"tls_verify":true}`}
}

func mustCreateTarget(t *testing.T, tenant *Tenant) TargetState {
	t.Helper()
	state, err := tenant.CreateTargetWithSecret(targetRecordFixture(), encryptedFixture(t, tenant.orgID))
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestTargetPersistenceLifecycleAndTenantIsolation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant := targetFixture(t, store)
		created := mustCreateTarget(t, tenant)
		if created.Target.ID <= 0 || created.Target.OrganizationID != initial.Organization.ID || created.Target.Version != 1 || created.Secret.Version != 1 || created.Secret.Mask != "********1234" {
			t.Fatal("invalid initial metadata")
		}
		got, err := tenant.GetTarget(created.Target.ID)
		if err != nil || got.Target.SecretID != created.Secret.ID || got.Secret.Mask != created.Secret.Mask {
			t.Fatalf("target read: %v", err)
		}
		listed, err := tenant.ListTargets(ListOptions{})
		if err != nil || len(listed) != 1 || listed[0].Secret.ID != created.Secret.ID {
			t.Fatalf("list: %v", err)
		}
		listed, err = tenant.ListTargets(ListOptions{AfterID: created.Target.ID})
		if err != nil || len(listed) != 0 {
			t.Fatal("cursor ignored")
		}
		otherID, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		other, _ := store.WithOrganization(testActorContext(t, initial.User.ID), otherID)
		if _, err := other.GetTarget(created.Target.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-org get: %v", err)
		}
		if _, err := other.GetSecretMetadata(created.Secret.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-org metadata: %v", err)
		}
		if _, err := other.GetSecretForWorker(created.Secret.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-org secret: %v", err)
		}
		if _, err := other.UpdateTarget(created.Target.ID, 1, targetRecordFixture()); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-org update: %v", err)
		}
		if err := other.DeleteTarget(created.Target.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-org delete: %v", err)
		}
		if _, err := tenant.GetSecretForWorker(created.Secret.ID, 2); !errors.Is(err, ErrNotFound) {
			t.Fatal("stale version substituted")
		}
		replacement := got.Target
		replacement.Name = "updated"
		replacement.Environment = "production"
		replacement.ChannelID = "channel-a"
		replacement.TagsJSON = `["tag"]`
		replacement.Status = "disabled"
		updated, err := tenant.UpdateTarget(created.Target.ID, 1, replacement)
		if err != nil || updated.Target.Version != 2 || updated.Target.Environment != "production" {
			t.Fatalf("update: %v", err)
		}
		if _, err := tenant.GetSecretForWorker(created.Secret.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("disabled target exposed worker credentials")
		}
		if _, err := tenant.UpdateTarget(created.Target.ID, 1, replacement); !errors.Is(err, ErrConflict) {
			t.Fatal("stale target overwritten")
		}
		replacement.Status = "active"
		replacement.Environment = ""
		replacement.ChannelID = ""
		replacement.TagsJSON = "[]"
		updated, err = tenant.UpdateTarget(created.Target.ID, 2, replacement)
		if err != nil || updated.Target.Version != 3 || updated.Target.Environment != "" {
			t.Fatalf("clear fields: %v", err)
		}
		var expired *TenantTransaction
		if err := tenant.InTransaction(func(tx *TenantTransaction) error {
			expired = tx
			locked, err := tx.LockTargetForRun(created.Target.ID, 3)
			if err != nil {
				return err
			}
			if locked.Secret.Version != 1 {
				return ErrConflict
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := expired.LockTargetForRun(created.Target.ID, 3); !errors.Is(err, ErrTransactionClosed) {
			t.Fatal("escaped transaction used")
		}
		rotated := encryptedFixture(t, tenant.orgID)
		rotated.ID = created.Secret.ID
		rotated.SecretVersion = 2
		rotated.LastFour = "5678"
		rotated.Ciphertext = bytes.Repeat([]byte{0x44}, 32)
		rotatedState, err := tenant.ReplaceTargetSecret(created.Target.ID, 3, 1, "custom_header", "X-Api-Key", rotated)
		if err != nil || rotatedState.Target.Version != 4 || rotatedState.Secret.Version != 2 || rotatedState.Secret.RotatedAt == nil {
			t.Fatalf("rotate: %v", err)
		}
		if _, err := tenant.GetSecretForWorker(created.Secret.ID, 1); !errors.Is(err, ErrNotFound) {
			t.Fatal("old credential retained")
		}
		fresh, err := tenant.GetSecretForWorker(created.Secret.ID, 2)
		if err != nil || !bytes.Equal(fresh.Ciphertext, rotated.Ciphertext) {
			t.Fatalf("new credential: %v", err)
		}
		if _, err := json.Marshal(fresh); !errors.Is(err, ErrSecretSerialization) {
			t.Fatal("encrypted record serializable")
		}
		if output := fmt.Sprintf("%+v %#v %s", fresh, fresh, fresh); strings.Contains(output, "opaque-wrap") || strings.Contains(output, "5678") {
			t.Fatal("encrypted record formatting leaked")
		}
		if err := tenant.DeleteTarget(created.Target.ID, 3); !errors.Is(err, ErrConflict) {
			t.Fatal("stale delete accepted")
		}
		if err := tenant.DeleteTarget(created.Target.ID, 4); err != nil {
			t.Fatal(err)
		}
		if _, err := tenant.GetTarget(created.Target.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("deleted target returned")
		}
		if _, err := tenant.GetSecretForWorker(created.Secret.ID, 2); !errors.Is(err, ErrNotFound) {
			t.Fatal("deleted secret readable")
		}
		var erased SecretRecord
		if err := store.db.Where("organization_id = ? AND id = ?", tenant.orgID, created.Secret.ID).First(&erased).Error; err != nil {
			t.Fatal(err)
		}
		if erased.DeletedAt == nil || len(erased.Ciphertext) != 0 || len(erased.EncryptedDataKey) != 0 || len(erased.Nonce) != 0 || erased.LastFour != "" || erased.Fingerprint != "" {
			t.Fatal("delete retained credential material")
		}
		verified, err := tenant.VerifyAuditFull()
		if err != nil || verified.EventCount != 9 {
			t.Fatalf("atomic audit sequence count=%d: %v", verified.EventCount, err)
		}
	})
}

func TestTargetAuditFailureRollsBackEveryMutation(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		_, tenant := targetFixture(t, store)
		signer := &switchAuditSigner{}
		store.auditSigner = signer
		signer.fail.Store(true)
		if _, err := tenant.CreateTargetWithSecret(targetRecordFixture(), encryptedFixture(t, tenant.orgID)); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("create did not fail closed: %v", err)
		}
		for _, table := range []string{"integrity_targets", "integrity_secrets"} {
			var count int64
			if err := store.db.Table(table).Count(&count).Error; err != nil || count != 0 {
				t.Fatal("partial create persisted")
			}
		}
		signer.fail.Store(false)
		original := mustCreateTarget(t, tenant)
		signer.fail.Store(true)
		replacement := original.Target
		replacement.Name = "uncommitted"
		if _, err := tenant.UpdateTarget(original.Target.ID, 1, replacement); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("update ignored audit: %v", err)
		}
		credential := encryptedFixture(t, tenant.orgID)
		credential.ID = original.Secret.ID
		credential.SecretVersion = 2
		credential.LastFour = "7890"
		if _, err := tenant.ReplaceTargetSecret(original.Target.ID, 1, 1, "bearer", "", credential); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("rotation ignored audit: %v", err)
		}
		if err := tenant.DeleteTarget(original.Target.ID, 1); !errors.Is(err, audit.ErrUnavailable) {
			t.Fatalf("deletion ignored audit: %v", err)
		}
		got, err := tenant.GetTarget(original.Target.ID)
		if err != nil || got.Target.Version != 1 || got.Target.Name != original.Target.Name || got.Secret.Version != 1 || got.Secret.Mask != original.Secret.Mask {
			t.Fatal("audit failure partially committed")
		}
		signer.fail.Store(false)
		verified, err := tenant.VerifyAuditFull()
		if err != nil || verified.EventCount != 3 {
			t.Fatal("audit chain modified by failed mutation")
		}
	})
}

func TestTargetOptimisticConcurrencyAcrossConnections(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		initial, tenant := targetFixture(t, store)
		original := mustCreateTarget(t, tenant)
		second, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = second.Close() }()
		secondTenant, _ := second.WithOrganization(testActorContext(t, initial.User.ID), tenant.orgID)
		results := make(chan error, 8)
		var group sync.WaitGroup
		for i := range 8 {
			group.Go(func() {
				candidate := tenant
				if i%2 != 0 {
					candidate = secondTenant
				}
				replacement := original.Target
				replacement.Name = fmt.Sprintf("writer-%d", i)
				_, err := candidate.UpdateTarget(original.Target.ID, 1, replacement)
				results <- err
			})
		}
		group.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatalf("unexpected race result: %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("CAS winners: %d", wins)
		}
		got, err := tenant.GetTarget(original.Target.ID)
		if err != nil || got.Target.Version != 2 {
			t.Fatal("CAS version incorrect")
		}
		verified, err := tenant.VerifyAuditFull()
		if err != nil || verified.EventCount != 4 {
			t.Fatal("losing writers produced audit or corruption")
		}
	})
}

func TestTargetConcurrentSecretReplacementOneWinner(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, cfg Config) {
		initial, tenant := targetFixture(t, store)
		original := mustCreateTarget(t, tenant)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		otherTenant, _ := other.WithOrganization(testActorContext(t, initial.User.ID), tenant.orgID)
		results := make(chan error, 8)
		var group sync.WaitGroup
		for i := range 8 {
			credential := encryptedFixture(t, tenant.orgID)
			credential.ID, credential.SecretVersion = original.Secret.ID, 2
			credential.LastFour = fmt.Sprintf("%04d", i)
			group.Go(func() {
				candidate := tenant
				if i%2 != 0 {
					candidate = otherTenant
				}
				_, err := candidate.ReplaceTargetSecret(original.Target.ID, 1, 1, "bearer", "", credential)
				results <- err
			})
		}
		group.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrConflict) {
				t.Fatalf("rotation race: %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("rotation winners: %d", wins)
		}
		got, err := tenant.GetTarget(original.Target.ID)
		if err != nil || got.Target.Version != 2 || got.Secret.Version != 2 {
			t.Fatal("rotation CAS changed inconsistent versions")
		}
		verified, err := tenant.VerifyAuditFull()
		if err != nil || verified.EventCount != 5 {
			t.Fatal("rotation CAS audit sequence inconsistent")
		}
	})
}

func TestTargetReferenceScopeAndDeleteActiveRun(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant := targetFixture(t, store)
		provider := Provider{Name: "provider"}
		if err := tenant.CreateProvider(&provider); err != nil {
			t.Fatal(err)
		}
		profile := ModelProfile{ModelProfileSummary: ModelProfileSummary{ProviderID: provider.ID, Model: "canonical", Protocol: "openai_chat"}}
		if err := tenant.CreateModelProfile(&profile); err != nil {
			t.Fatal(err)
		}
		record := targetRecordFixture()
		record.ProviderID = &provider.ID
		record.ModelProfileID = &profile.ID
		created, err := tenant.CreateTargetWithSecret(record, encryptedFixture(t, tenant.orgID))
		if err != nil {
			t.Fatal(err)
		}
		missingID, _ := NewID()
		record.ProviderID = &missingID
		if _, err := tenant.CreateTargetWithSecret(record, encryptedFixture(t, tenant.orgID)); !errors.Is(err, ErrNotFound) {
			t.Fatal("foreign/nonexistent provider accepted")
		}
		other := Provider{Name: "other"}
		if err := tenant.CreateProvider(&other); err != nil {
			t.Fatal(err)
		}
		record.ProviderID = &other.ID
		if _, err := tenant.CreateTargetWithSecret(record, encryptedFixture(t, tenant.orgID)); !errors.Is(err, ErrConflict) {
			t.Fatal("mismatched profile/provider accepted")
		}
		runID, _ := NewID()
		now := time.Now().UTC()
		row := map[string]any{"id": runID, "organization_id": tenant.orgID, "target_id": created.Target.ID, "package": "quick", "status": "pending", "config_snapshot": "{}", "rule_bundle_version": "v1", "template_bundle_version": "v1", "scoring_version": "v1", "tokenizer_bundle_version": "v1", "request_budget": 1, "token_budget": 1, "created_by": initial.User.ID, "created_at": now}
		if err := store.db.Table("integrity_runs").Create(row).Error; err != nil {
			t.Fatal("create active run fixture")
		}
		if err := tenant.DeleteTarget(created.Target.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatalf("active run deletion not blocked: %v", err)
		}
		if _, err := tenant.GetSecretForWorker(created.Secret.ID, 1); err != nil {
			t.Fatal("blocked deletion destroyed credential")
		}
		if err := store.db.Table("integrity_runs").Where("organization_id = ? AND id = ?", tenant.orgID, runID).Updates(map[string]any{"execution_closed_at": now, "status": "canceled"}).Error; err != nil {
			t.Fatal(err)
		}
		pending, err := tenant.Enqueue(JobSpec{Type: JobRunPlan, ObjectID: runID, IdempotencyKey: "unfinished-target-work"})
		if err != nil {
			t.Fatal(err)
		}
		if err := tenant.DeleteTarget(created.Target.ID, 1); !errors.Is(err, ErrConflict) {
			t.Fatal("closed run hid unfinished outbound job")
		}
		if err := store.db.Model(&Job{}).Where("organization_id = ? AND id = ?", tenant.orgID, pending.ID).Updates(map[string]any{"status": "cancelled", "completed_at": now}).Error; err != nil {
			t.Fatal(err)
		}
		if err := tenant.DeleteTarget(created.Target.ID, 1); err != nil {
			t.Fatal(err)
		}
		var historical int64
		if err := store.db.Table("integrity_runs").Where("organization_id = ? AND id = ?", tenant.orgID, runID).Count(&historical).Error; err != nil || historical != 1 {
			t.Fatal("historical run deleted")
		}
	})
}
