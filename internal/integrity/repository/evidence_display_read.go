package repository

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"
)

var ErrDisplaySource = errors.New("MI_DISPLAY_SOURCE_INVALID")

const DisclosureFormatVersion = "mii.evidence-display-output.v1"

const (
	DisplayReadAvailable        = "available"
	DisplayReadPolicyZero       = "unavailable_policy_zero"
	DisplayReadNotRetained      = "unavailable_not_retained"
	DisplayReadNotCaptured      = "unavailable_not_captured"
	DisplayReadUncertain        = "unavailable_uncertain"
	DisplayReadExpired          = "unavailable_expired"
	DisplayReadDeleted          = "unavailable_deleted"
	DisplayReadLegacyUnverified = "unavailable_legacy_unverified"
)

type DisplaySelection struct {
	RunID, SampleID, AttemptID int64
	AnalysisRevision           int
}

type DisplayReadMetadata struct {
	Selection   DisplaySelection
	IsFinal     bool
	Status      string
	PayloadHash string
}

type DisplayReadEnvelope struct{ Record DisplayEvidenceRecord }

func (DisplayReadEnvelope) String() string               { return "[protected display read envelope]" }
func (v DisplayReadEnvelope) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, v.String()) }
func (DisplayReadEnvelope) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSerialization }
func (v DisplayReadEnvelope) LogValue() slog.Value       { return slog.StringValue(v.String()) }

type DisclosureSummary struct {
	FormatVersion, OutputHash string
	OutputBytes               int64
}

func validDisclosureSummary(v DisclosureSummary) bool {
	return v.FormatVersion == DisclosureFormatVersion && executionHash.MatchString(v.OutputHash) && v.OutputBytes > 0 && v.OutputBytes <= 8<<20
}

// Source contains at most one encrypted display record, never raw response or
// request snapshots. It authorizes no plaintext release before the final grant.
type DisplayReadSource struct {
	*displayReadSourceState
}

// Exported handles can be copied by value. Every copy must retain one mutex,
// ciphertext owner and closed flag, not merely share the grant atomic.
type displayReadSourceState struct {
	mu       sync.Mutex
	store    *Store
	orgID    int64
	identity ManagementAuthority
	ctx      context.Context
	deadline time.Time
	snapshot displayReadSnapshot
	closed   bool
	grant    *atomic.Bool
}

func (DisplayReadSource) String() string               { return "[protected display read source]" }
func (s DisplayReadSource) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }
func (DisplayReadSource) MarshalJSON() ([]byte, error) { return nil, ErrEvidenceSerialization }
func (*DisplayReadSource) UnmarshalJSON([]byte) error  { return ErrEvidenceSerialization }
func (s DisplayReadSource) LogValue() slog.Value       { return slog.StringValue(s.String()) }

func (s *DisplayReadSource) Metadata() DisplayReadMetadata {
	if s == nil || s.displayReadSourceState == nil {
		return DisplayReadMetadata{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return DisplayReadMetadata{}
	}
	return s.snapshot.metadata
}

func (s *DisplayReadSource) WithEnvelope(fn func(DisplayReadEnvelope) error) error {
	if s == nil || s.displayReadSourceState == nil || fn == nil {
		return ErrDisplaySource
	}
	s.mu.Lock()
	if s.closed || s.ctx == nil || s.ctx.Err() != nil || !s.deadline.After(time.Now()) || s.snapshot.metadata.Status != DisplayReadAvailable {
		s.mu.Unlock()
		return ErrDisplaySource
	}
	record := s.snapshot.record
	record.Nonce, record.Ciphertext = bytes.Clone(record.Nonce), bytes.Clone(record.Ciphertext)
	s.mu.Unlock()
	defer clear(record.Nonce)
	defer clear(record.Ciphertext)
	return fn(DisplayReadEnvelope{Record: record})
}

func (s *DisplayReadSource) Close() {
	if s == nil || s.displayReadSourceState == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	clear(s.snapshot.record.Nonce)
	clear(s.snapshot.record.Ciphertext)
	s.snapshot.record.Nonce, s.snapshot.record.Ciphertext = nil, nil
}

func displayError(err, business error) error {
	for _, known := range []error{ErrDisplaySource, ErrAnalysisLimit, ErrConfiguration, ErrNotFound} {
		if errors.Is(business, known) || errors.Is(err, known) {
			return known
		}
	}
	return err
}

func displayPermissions(db *gorm.DB, orgID, actorID int64) error {
	var count int64
	err := db.Raw(`SELECT COUNT(*) FROM (
 SELECT rp.permission_code FROM role_permissions rp
 JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id
 JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id
 JOIN organizations o ON o.id=om.organization_id
 WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND rp.permission_code IN ('run.read','evidence.read','evidence.body')
 UNION SELECT mp.permission_code FROM member_permissions mp
 JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id
 JOIN organizations o ON o.id=om.organization_id
 WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND mp.permission_code IN ('run.read','evidence.read','evidence.body')
) display_permissions`, orgID, actorID, orgID, actorID).Scan(&count).Error
	if err != nil {
		return err
	}
	if count != 3 {
		return ErrManagementPermission
	}
	return nil
}

func (t *Tenant) PrepareEvidenceDisplay(selection DisplaySelection) (*DisplayReadSource, error) {
	if t == nil || t.store == nil || t.ctx == nil {
		return nil, ErrManagementSession
	}
	if selection.RunID <= 0 || selection.SampleID <= 0 || selection.AttemptID < 0 || selection.AnalysisRevision != 1 {
		return nil, ErrConfiguration
	}
	if err := t.store.RequireControlAuthority(t.ctx, t.orgID); err != nil {
		return nil, err
	}
	auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
	deadline := time.Now().Add(10 * time.Second)
	if d, ok := t.ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	ctx, cancel := context.WithTimeout(t.ctx, 2*time.Second)
	defer cancel()
	reader := &Tenant{store: t.store, orgID: t.orgID, ctx: ctx}
	var snapshot displayReadSnapshot
	var business error
	err := reader.resultReadTransaction(true, func(db *gorm.DB) error {
		if err := displayPermissions(db, t.orgID, auth.UserID); err != nil {
			return err
		}
		var session Session
		if err := db.Select("expires_at").Where("id=? AND user_id=?", auth.SessionID, auth.UserID).Take(&session).Error; err != nil {
			return err
		}
		// Preserve the ORIGINAL session interval even if a later writer extends
		// that row. Convert wall timestamps to a local monotonic deadline.
		now := time.Now()
		deadline = now.Add(min(deadline.Sub(now), session.ExpiresAt.Sub(now)))
		row, err := loadResponseRetentionOrganization(db, t.store.driver, t.orgID, false)
		if err != nil {
			return err
		}
		policy, err := responseRetentionObservation(row, db, t.store.driver)
		if err != nil {
			return err
		}
		snapshot, business = loadDisplayReadSnapshot(t.store, db, t.orgID, selection, policy, false, true)
		return business
	})
	if err != nil {
		clear(snapshot.record.Ciphertext)
		return nil, displayError(err, business)
	}
	if !deadline.After(time.Now()) || t.ctx.Err() != nil {
		clear(snapshot.record.Ciphertext)
		return nil, ErrDisplaySource
	}
	return &DisplayReadSource{displayReadSourceState: &displayReadSourceState{store: t.store, orgID: t.orgID, identity: auth, ctx: t.ctx, deadline: deadline, snapshot: snapshot, grant: new(atomic.Bool)}}, nil
}

func hashDisplayJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", ErrDisplaySource
	}
	defer clear(encoded)
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}
