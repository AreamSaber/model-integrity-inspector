package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func displayReadFixture(t *testing.T, store *Store) (*Tenant, DisplaySelection) {
	t.Helper()
	tenant, run, queue, sample, attempt, lease := legacyBodyFixture(t, store)
	body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
	if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
		return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, successOutcome(), 0, body)
	}); err != nil {
		t.Fatal(err)
	}
	analysisLease, err := queue.Claim(tenant.ctx)
	if err != nil || analysisLease == nil {
		t.Fatal("claim analysis", err)
	}
	source, err := queue.LoadRunAnalysis(tenant.ctx, *analysisLease)
	if err != nil {
		t.Fatal(err)
	}
	run, _ = tenant.GetRun(run.ID)
	samples, _ := tenant.ListExecutionSamples(run.ID)
	if err := queue.CompleteWith(tenant.ctx, *analysisLease, func(tx *TenantTransaction) error {
		return tx.PublishRunAnalysis(source, analysisPublicationFixture(t, run, samples))
	}); err != nil {
		t.Fatal(err)
	}
	readPermissions(t, tenant)
	if err := store.db.Exec("INSERT INTO permissions(code) VALUES ('evidence.body') ON CONFLICT(code) DO NOTHING").Error; err != nil {
		t.Fatal(err)
	}
	if err := store.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) SELECT organization_id,id,'evidence.body' FROM roles WHERE organization_id=? AND name='administrator'", tenant.orgID).Error; err != nil {
		t.Fatal(err)
	}
	return tenant, DisplaySelection{RunID: run.ID, SampleID: sample.ID, AttemptID: attempt.ID, AnalysisRevision: 1}
}

func displaySummaryFixture() DisclosureSummary {
	hash := sha256.Sum256([]byte(`{"fixture":"bounded-display-output"}`))
	return DisclosureSummary{FormatVersion: DisclosureFormatVersion, OutputHash: hex.EncodeToString(hash[:]), OutputBytes: 36}
}

func noDisplayGrants(t *testing.T, store *Store) {
	t.Helper()
	for _, query := range []*gorm.DB{store.db.Model(&evidenceDisclosureReceipt{}), store.db.Table("integrity_audit_logs").Where("action='evidence.body.read'")} {
		var count int64
		if err := query.Count(&count).Error; err != nil || count != 0 {
			t.Fatal("failed disclosure committed grant", err)
		}
	}
}

func TestEvidenceDisplayReadBoundedPrivateSourceGrantAndReplay(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, selection := displayReadFixture(t, store)
		selection.AttemptID = 0
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil {
			t.Fatal("prepare display", err)
		}
		defer source.Close()
		metadata := source.Metadata()
		if metadata.Status != DisplayReadAvailable || !metadata.IsFinal || metadata.Selection.AttemptID <= 0 {
			t.Fatal("wrong display metadata")
		}
		var borrowed []byte
		if err := source.WithEnvelope(func(envelope DisplayReadEnvelope) error {
			if !validDisplayRecord(envelope.Record) {
				t.Fatal("bad cipher projection")
			}
			borrowed = envelope.Record.Ciphertext
			envelope.Record.Ciphertext[0] ^= 0xff
			envelope.Record.RunID++
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
			t.Fatal("borrowed cipher buffer not cleared")
		}
		if err := source.WithEnvelope(func(envelope DisplayReadEnvelope) error {
			if envelope.Record.RunID != selection.RunID || envelope.Record.Ciphertext[0] != 4 {
				t.Fatal("borrower mutated private source")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		noDisplayGrants(t, store)
		summary := displaySummaryFixture()
		permit, err := tenant.CommitEvidenceDisplayRead(source, summary)
		if err != nil || permit == nil {
			t.Fatal("grant display", err)
		}
		copyPermit := *permit
		source.Close()
		if err := permit.Revalidate(tenant.ctx); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("unbegun permit usable")
		}
		var wg sync.WaitGroup
		outcomes := make(chan error, 2)
		for _, candidate := range []*DisclosurePermit{permit, &copyPermit} {
			wg.Go(func() { outcomes <- candidate.Begin(tenant.ctx, summary) })
		}
		wg.Wait()
		close(outcomes)
		begun, denied := 0, 0
		for err := range outcomes {
			if err == nil {
				begun++
			} else if errors.Is(err, ErrDisplaySource) {
				denied++
			} else {
				t.Fatal("begin permit", err)
			}
		}
		if begun != 1 || denied != 1 {
			t.Fatal("copied permits did not share atomic consumption")
		}
		if err := permit.Revalidate(tenant.ctx); err != nil {
			t.Fatal("validate permit", err)
		}
		if err := permit.Begin(tenant.ctx, summary); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("permit replayed")
		}
		if err := copyPermit.Begin(tenant.ctx, summary); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("copied permit replayed")
		}
		if _, err := tenant.CommitEvidenceDisplayRead(source, summary); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("source replayed")
		}
		permit.Close()
		if err := permit.Revalidate(tenant.ctx); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("closed permit usable")
		}
		var receipt evidenceDisclosureReceipt
		if err := store.db.First(&receipt).Error; err != nil {
			t.Fatal(err)
		}
		storedHash := receipt.ReceiptHash
		receipt.ReceiptHash = ""
		actualHash, err := hashDisplayJSON(receipt)
		if err != nil || storedHash != actualHash || receipt.OutputHash != summary.OutputHash || receipt.ActorID != tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity.UserID || receipt.Result != "authorized" {
			t.Fatal("receipt binding drift", err)
		}
		var event audit.Event
		if err := store.db.Where("action='evidence.body.read'").First(&event).Error; err != nil || event.ObjectID != fmt.Sprint(receipt.ID)+":"+storedHash {
			t.Fatal("audit did not bind canonical receipt", err)
		}
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
		if err := store.db.Model(&evidenceDisclosureReceipt{}).Where("id=?", receipt.ID).Update("output_bytes", 1).Error; err == nil {
			t.Fatal("receipt update permitted")
		}
		if err := store.db.Where("id=?", receipt.ID).Delete(&evidenceDisclosureReceipt{}).Error; err == nil {
			t.Fatal("receipt deletion permitted")
		}
		if _, err := json.Marshal(permit); !errors.Is(err, ErrEvidenceSerialization) {
			t.Fatal("permit serialized")
		}
	})
}

func TestEvidenceDisplayReadRevocationMutationAndMissingFailClosed(t *testing.T) {
	for _, scenario := range []string{"session", "user", "member", "run_permission", "evidence_permission", "body_permission", "policy_zero", "cipher", "missing", "nonce", "session_context", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, selection := displayReadFixture(t, store)
				ctx, cancel := context.WithCancel(tenant.ctx)
				defer cancel()
				tenant = &Tenant{store: store, orgID: tenant.orgID, ctx: ctx}
				source, err := tenant.PrepareEvidenceDisplay(selection)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				auth := tenant.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
				switch scenario {
				case "session":
					err = store.db.Model(&Session{}).Where("id=?", auth.SessionID).Update("revoked_at", time.Now().UTC()).Error
				case "user":
					err = store.db.Model(&User{}).Where("id=?", auth.UserID).Update("status", "disabled").Error
				case "member":
					err = store.db.Model(&Membership{}).Where("organization_id=? AND user_id=?", tenant.orgID, auth.UserID).Update("status", "disabled").Error
				case "run_permission", "evidence_permission", "body_permission":
					permission := map[string]string{"run_permission": "run.read", "evidence_permission": "evidence.read", "body_permission": "evidence.body"}[scenario]
					err = store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code=?", tenant.orgID, permission).Error
				case "policy_zero":
					derivedFixtureRetention(t, tenant, 0)
				case "cipher":
					err = store.db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Update("ciphertext", bytes.Repeat([]byte{8}, 48)).Error
				case "nonce":
					err = store.db.Model(&DisplayEvidenceRecord{}).Where("attempt_id=?", selection.AttemptID).Update("nonce", bytes.Repeat([]byte{8}, 12)).Error
				case "missing":
					err = store.db.Where("attempt_id=?", selection.AttemptID).Delete(&DisplayEvidenceRecord{}).Error
				case "session_context":
					user, e := store.GetUser(tenant.ctx, auth.UserID)
					if e != nil {
						t.Fatal(e)
					}
					other := managementSession(t, store, user)
					newCtx := bindTargetTestSession(t, store, testActorContext(t, auth.UserID), other.SessionID, tenant.orgID)
					tenant = &Tenant{store: store, orgID: tenant.orgID, ctx: newCtx}
				case "cancel":
					cancel()
				}
				if err != nil {
					t.Fatal("install committed change", err)
				}
				permit, err := tenant.CommitEvidenceDisplayRead(source, displaySummaryFixture())
				if err == nil || permit != nil {
					t.Fatal("changed source/authority released permit")
				}
				noDisplayGrants(t, store)
				if scenario == "missing" {
					derivedFixtureRetention(t, tenant, 0)
					if _, err := tenant.PrepareEvidenceDisplay(selection); !errors.Is(err, ErrDisplaySource) {
						t.Fatal("missing recorded row hidden as normal zero retention", err)
					}
				}
			})
		})
	}
}

func TestEvidenceDisplayReadUnavailableAndAuditFailure(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, config Config) {
		tenant, selection := displayReadFixture(t, store)
		derivedFixtureRetention(t, tenant, 0)
		source, err := tenant.PrepareEvidenceDisplay(selection)
		if err != nil || source.Metadata().Status != DisplayReadPolicyZero {
			t.Fatal("policy unavailable", err)
		}
		defer source.Close()
		if err := source.WithEnvelope(func(DisplayReadEnvelope) error { t.Fatal("unavailable cipher borrowed"); return nil }); !errors.Is(err, ErrDisplaySource) {
			t.Fatal(err)
		}
		statement := "ALTER TABLE integrity_audit_logs ADD CONSTRAINT display_grant_fail CHECK (action <> 'evidence.body.read') NOT VALID"
		if config.Driver == "sqlite" {
			statement = "CREATE TRIGGER display_grant_fail BEFORE INSERT ON integrity_audit_logs WHEN NEW.action='evidence.body.read' BEGIN SELECT RAISE(ABORT,'DISPLAY_GRANT_FAIL'); END"
		}
		if err := store.db.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
		if permit, err := tenant.CommitEvidenceDisplayRead(source, displaySummaryFixture()); err == nil || permit != nil {
			t.Fatal("audit failure returned permit")
		}
		noDisplayGrants(t, store)
		if err := store.VerifyAllAudit(tenant.ctx, true); err != nil {
			t.Fatal(err)
		}
	})
}

func TestEvidenceDisplayReadPermissionPrecedesObjectExistence(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, selection := displayReadFixture(t, store)
		if err := store.db.Exec("DELETE FROM role_permissions WHERE organization_id=? AND permission_code='evidence.body'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		for _, id := range []int64{selection.RunID, selection.RunID + 1} {
			selection.RunID = id
			if _, err := tenant.PrepareEvidenceDisplay(selection); !errors.Is(err, ErrManagementPermission) {
				t.Fatal("object existence leaked before body permission", err)
			}
		}
		noDisplayGrants(t, store)
	})
}

func TestEvidenceDisplayReadFormattingDoesNotExposeCipher(t *testing.T) {
	const canary = "display-cipher-fixture-canary"
	value := DisplayReadEnvelope{Record: DisplayEvidenceRecord{Ciphertext: []byte(canary), SourceHash: canary}}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, value), canary) {
			t.Fatal("envelope formatted sensitive fields")
		}
	}
	if _, err := json.Marshal(value); !errors.Is(err, ErrEvidenceSerialization) {
		t.Fatal("envelope JSON exposed")
	}
	for _, permit := range []*DisclosurePermit{nil, {}, {store: &Store{}, ctx: t.Context()}} {
		if err := permit.Revalidate(t.Context()); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("zero permit not closed", err)
		}
		if err := permit.Begin(t.Context(), displaySummaryFixture()); !errors.Is(err, ErrDisplaySource) {
			t.Fatal("zero permit began", err)
		}
		permit.Close()
	}
}

func TestEvidenceDisplayReadExplicitRetryNeverChoosesFinalInstead(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, run, queue, sample, attempt, lease := legacyBodyFixture(t, store)
		firstID := attempt.ID
		for number := 0; number < 2; number++ {
			body := derivedFixtureBody(t, tenant, queue, lease, sample, attempt)
			outcome := successOutcome()
			if number == 0 {
				outcome = domain.AttemptOutcome{Validity: "INVALID_RETRYABLE", ErrorCode: "MI_RATE_LIMITED", HTTPStatus: 429}
			}
			if err := queue.CompleteWith(tenant.ctx, lease, func(tx *TenantTransaction) error {
				return tx.FinishLegacyAttemptWithCapture(sample.ID, attempt.ID, outcome, 0, body)
			}); err != nil {
				t.Fatal(err)
			}
			if number == 0 {
				if err := store.db.Model(&Job{}).Where("organization_id=? AND type=? AND status='pending'", tenant.orgID, string(JobSampleExecute)).Update("available_at", time.Now().UTC().Add(-time.Second)).Error; err != nil {
					t.Fatal(err)
				}
				next, err := queue.Claim(tenant.ctx)
				if err != nil || next == nil {
					t.Fatal("claim real retry", err)
				}
				lease = *next
				sample, err = tenant.GetExecutionSampleForWorker(sample.ID)
				if err != nil {
					t.Fatal(err)
				}
				attempt = reserveTestAttempt(t, tenant, queue, lease, sample)
			}
		}
		analysisLease, err := queue.Claim(tenant.ctx)
		if err != nil || analysisLease == nil {
			t.Fatal(err)
		}
		analysisSource, err := queue.LoadRunAnalysis(tenant.ctx, *analysisLease)
		if err != nil {
			t.Fatal(err)
		}
		run, _ = tenant.GetRun(run.ID)
		samples, _ := tenant.ListExecutionSamples(run.ID)
		if err := queue.CompleteWith(tenant.ctx, *analysisLease, func(tx *TenantTransaction) error {
			return tx.PublishRunAnalysis(analysisSource, analysisPublicationFixture(t, run, samples))
		}); err != nil {
			t.Fatal(err)
		}
		readPermissions(t, tenant)
		if err := store.db.Exec("INSERT INTO permissions(code) VALUES ('evidence.body') ON CONFLICT(code) DO NOTHING").Error; err != nil {
			t.Fatal(err)
		}
		if err := store.db.Exec("INSERT INTO role_permissions(organization_id,role_id,permission_code) SELECT organization_id,id,'evidence.body' FROM roles WHERE organization_id=? AND name='administrator'", tenant.orgID).Error; err != nil {
			t.Fatal(err)
		}
		for _, id := range []int64{firstID, attempt.ID, 0} {
			selection := DisplaySelection{RunID: run.ID, SampleID: sample.ID, AttemptID: id, AnalysisRevision: 1}
			source, err := tenant.PrepareEvidenceDisplay(selection)
			if err != nil {
				t.Fatal("read explicit retry", err)
			}
			meta := source.Metadata()
			want := id
			if want == 0 {
				want = attempt.ID
			}
			if meta.Selection.AttemptID != want || meta.IsFinal != (want == attempt.ID) {
				t.Fatal("retry selector silently chose another attempt")
			}
			if err := source.WithEnvelope(func(v DisplayReadEnvelope) error {
				if v.Record.AttemptID != want {
					t.Fatal("cipher envelope does not match selected retry")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			source.Close()
		}
	})
}
