package repository

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

type evidenceDisclosureReceipt struct {
	ID, OrganizationID, ActorID            int64
	Action                                 string
	RunID, LogicalSampleID, AttemptID      int64
	AnalysisRevision                       int
	SourceKind, Policy, SourceDigest       string
	PayloadHash, FormatVersion, OutputHash string
	OutputBytes                            int64
	PolicyVersion                          int
	PolicyCutoffMicros                     int64
	AuthorizedAt                           time.Time
	Result, ReceiptHash                    string
}

func (evidenceDisclosureReceipt) TableName() string { return "integrity_evidence_disclosures" }

// Permit keeps no envelope/S2. Closing the source cannot change a granted
// permit's exact authorization facts. No permit exists before confirmed commit.
type DisclosurePermit struct {
	store          *Store
	orgID          int64
	identity       ManagementAuthority
	ctx            context.Context
	deadline       time.Time
	summary        DisclosureSummary
	selection      DisplaySelection
	metadataDigest string
	state          *atomic.Int32 // shared by value copies; 0 minted, 1 begun, 2 closed
}

func (DisclosurePermit) String() string               { return "[private disclosure permit]" }
func (p DisclosurePermit) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, p.String()) }
func (DisclosurePermit) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSerialization }
func (*DisclosurePermit) UnmarshalJSON([]byte) error  { return ErrEvidenceSerialization }
func (p DisclosurePermit) LogValue() slog.Value       { return slog.StringValue(p.String()) }

func (p *DisclosurePermit) Close() {
	if p != nil && p.state != nil {
		p.state.Store(2)
	}
}

func (p *DisclosurePermit) Begin(ctx context.Context, summary DisclosureSummary) error {
	if p == nil || p.state == nil || !validDisclosureSummary(summary) || summary != p.summary || !p.state.CompareAndSwap(0, 1) {
		return ErrDisplaySource
	}
	if err := p.Revalidate(ctx); err != nil {
		p.Close()
		return err
	}
	return nil
}

func (p *DisclosurePermit) checkContext(ctx context.Context) error {
	if p == nil || p.store == nil || p.state == nil || ctx == nil || p.ctx == nil || p.state.Load() != 1 || ctx.Err() != nil || p.ctx.Err() != nil || !p.deadline.After(time.Now()) {
		return ErrDisplaySource
	}
	if err := p.store.RequireControlAuthority(ctx, p.orgID); err != nil {
		return err
	}
	if ctx.Value(controlAuthorityKey{}).(controlAuthority).identity != p.identity {
		return ErrManagementSession
	}
	return nil
}

// Revalidate is read-only and bounded. Grant already authenticated the complete
// cipher digest; after grant, each chunk rechecks identity, policy and original
// object metadata (not 4MiB of ciphertext per 64KiB output chunk). Already sent
// bytes cannot be withdrawn, and no SQL transaction covers a socket write.
func (p *DisclosurePermit) Revalidate(ctx context.Context) error {
	if err := p.checkContext(ctx); err != nil {
		return err
	}
	readCtx, cancel := context.WithDeadline(ctx, p.deadline)
	defer cancel()
	tenant := &Tenant{store: p.store, orgID: p.orgID, ctx: readCtx}
	var business error
	err := tenant.resultReadTransaction(true, func(db *gorm.DB) error {
		if err := displayPermissions(db, p.orgID, p.identity.UserID); err != nil {
			return err
		}
		row, err := loadResponseRetentionOrganization(db, p.store.driver, p.orgID, false)
		if err != nil {
			return err
		}
		policy, err := responseRetentionObservation(row, db, p.store.driver)
		if err != nil {
			return err
		}
		snapshot, err := loadDisplayReadSnapshot(p.store, db, p.orgID, p.selection, policy, false, false)
		if err != nil {
			business = err
			return err
		}
		if snapshot.metadataDigest != p.metadataDigest {
			business = ErrDisplaySource
			return business
		}
		return nil
	})
	if err != nil {
		return displayError(err, business)
	}
	return p.checkContext(ctx)
}

func (t *Tenant) CommitEvidenceDisplayRead(source *DisplayReadSource, summary DisclosureSummary) (*DisclosurePermit, error) {
	if t == nil || t.store == nil || t.ctx == nil || source == nil || source.displayReadSourceState == nil || !validDisclosureSummary(summary) {
		return nil, ErrDisplaySource
	}
	if err := t.store.RequireControlAuthority(t.ctx, t.orgID); err != nil {
		return nil, err
	}
	auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
	source.mu.Lock()
	valid := !source.closed && source.store == t.store && source.orgID == t.orgID && source.identity == auth && source.ctx != nil && source.ctx.Err() == nil && t.ctx.Err() == nil && source.deadline.After(time.Now())
	selection, digest, metadataDigest, expectedStatus := source.snapshot.metadata.Selection, source.snapshot.digest, source.snapshot.metadataDigest, source.snapshot.metadata.Status
	originalCtx, sourceDeadline := source.ctx, source.deadline
	source.mu.Unlock()
	if !valid || source.grant == nil || !source.grant.CompareAndSwap(false, true) {
		return nil, ErrDisplaySource
	}
	var grantDeadline time.Time
	var business error
	err := t.controlTenantTransaction("evidence.body", func(tx *TenantTransaction) error {
		business = func() error {
			if err := displayPermissions(tx.db, t.orgID, auth.UserID); err != nil {
				return err
			}
			policy, err := tx.LockResponseRetentionPolicy()
			if err != nil {
				return err
			}
			snapshot, err := loadDisplayReadSnapshot(t.store, tx.db, t.orgID, selection, policy, true, true)
			defer clear(snapshot.record.Nonce)
			defer clear(snapshot.record.Ciphertext)
			if err != nil {
				return err
			}
			if snapshot.digest != digest || snapshot.metadataDigest != metadataDigest {
				return ErrDisplaySource
			}
			id, err := NewID()
			if err != nil {
				return err
			}
			result := "unavailable"
			if expectedStatus == DisplayReadAvailable {
				result = "authorized"
			}
			receipt := evidenceDisclosureReceipt{ID: id, OrganizationID: t.orgID, ActorID: auth.UserID, Action: "evidence.body.read", RunID: selection.RunID, LogicalSampleID: selection.SampleID, AttemptID: selection.AttemptID, AnalysisRevision: selection.AnalysisRevision, SourceKind: "response-display", Policy: DisplayEvidencePolicy, SourceDigest: digest, PayloadHash: snapshot.metadata.PayloadHash, FormatVersion: summary.FormatVersion, OutputHash: summary.OutputHash, OutputBytes: summary.OutputBytes, PolicyVersion: policy.Version(), PolicyCutoffMicros: policy.NotBeforeMicros(), AuthorizedAt: time.UnixMicro(policy.ObservedAtMicros()).UTC(), Result: result}
			receipt.ReceiptHash, err = hashDisplayJSON(receipt)
			if err != nil {
				return err
			}
			if err := tx.db.Create(&receipt).Error; err != nil {
				return err
			}
			command := AuditCommand{Action: "evidence.body.read", ObjectType: "evidence_disclosure", ObjectID: strconv.FormatInt(id, 10) + ":" + receipt.ReceiptHash, Result: result}
			if err := t.store.appendAudit(tx.ctx, tx.db, t.orgID, command, nil); err != nil {
				return err
			}
			// The audit head may have blocked. Retention and session natural
			// time do not stop under SQL row locks; neither permit nor byte may
			// escape if that wait crossed the original eligibility interval.
			localObserved := time.Now()
			now, err := queueTime(tx.db, t.store.driver)
			if err != nil {
				return err
			}
			policy.observedAtMicros = now.UnixMicro()
			status, err := displayReadStatus(snapshot.facts, snapshot.record, snapshot.present, policy)
			if err != nil || status != expectedStatus {
				return ErrDisplaySource
			}
			remaining := min(2*time.Second, sourceDeadline.Sub(localObserved))
			if deadline, ok := t.ctx.Deadline(); ok {
				remaining = min(remaining, deadline.Sub(localObserved))
			}
			var session Session
			if err := tx.db.Select("expires_at").Where("id=? AND user_id=?", auth.SessionID, auth.UserID).Take(&session).Error; err != nil {
				return err
			}
			remaining = min(remaining, session.ExpiresAt.Sub(localObserved))
			if expectedStatus == DisplayReadAvailable {
				remaining = min(remaining, time.Duration(snapshot.record.ExpiresAtMicros-now.UnixMicro())*time.Microsecond, time.Duration(snapshot.record.CapturedAtMicros+int64(policy.Days())*responseRetentionDayMicros-now.UnixMicro())*time.Microsecond)
			}
			if remaining <= 0 || originalCtx.Err() != nil || t.ctx.Err() != nil {
				return ErrDisplaySource
			}
			grantDeadline = localObserved.Add(remaining)
			return nil
		}()
		return business
	})
	if err != nil {
		return nil, displayError(err, business)
	}
	// This is intentionally outside managementTransaction: even a successful
	// callback cannot create a permit on COMMIT failure/uncertainty.
	source.mu.Lock()
	defer source.mu.Unlock()
	if source.closed || originalCtx.Err() != nil || t.ctx.Err() != nil || !grantDeadline.After(time.Now()) {
		return nil, ErrDisplaySource
	}
	return &DisclosurePermit{store: t.store, orgID: t.orgID, identity: auth, ctx: originalCtx, deadline: grantDeadline, summary: summary, selection: selection, metadataDigest: metadataDigest, state: new(atomic.Int32)}, nil
}
