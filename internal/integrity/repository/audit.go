package repository

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type auditChainHead struct {
	OrganizationID int64
	EventCount     int64
	EventHash      string
	KeyVersion     string
	UpdatedAt      time.Time
}

func (auditChainHead) TableName() string { return "integrity_audit_chain_heads" }

// AuditCommand contains identifiers and a fixed outcome only, never object bodies.
type AuditCommand struct {
	Action     string
	ObjectType string
	ObjectID   string
	Result     string
}

// AuditVerification is safe diagnostic metadata. Chain hashes stay out of DTOs.
type AuditVerification struct {
	OrganizationID int64
	EventCount     int64
	VerifiedCount  int64
	LastEventAt    *time.Time
}

func (s *Store) auditReady(ctx context.Context) error {
	if s.auditSigner == nil {
		return audit.ErrUnavailable
	}
	_, err := audit.ActorFromContext(ctx)
	return err
}

func (s *Store) appendAudit(ctx context.Context, tx *gorm.DB, orgID int64, command AuditCommand, actorOverride *int64) error {
	return s.appendAuditWithClock(ctx, tx, orgID, command, actorOverride, false)
}

// The database-clock option is private to response-retention deletion. Its
// signed event and receipt must use the same clock authority; existing callers
// retain their historical event timestamps and canonicalization unchanged.
func (s *Store) appendAuditWithClock(ctx context.Context, tx *gorm.DB, orgID int64, command AuditCommand, actorOverride *int64, databaseClock bool) error {
	if err := s.auditReady(ctx); err != nil {
		return err
	}
	actor, err := audit.ActorFromContext(ctx)
	if err != nil {
		return err
	}
	if actorOverride != nil {
		actor.ActorID = *actorOverride
	}
	if actor.ActorID == 0 && command.Action != "auth.login_failed" {
		return audit.ErrActorRequired
	}
	// Serializing on the tenant's head also prevents concurrent verification from
	// seeing a half-appended chain. The initial insert handles first-event races.
	now := time.Now().UTC().Truncate(time.Microsecond)
	if databaseClock {
		now, err = queueTime(tx, s.driver)
		if err != nil {
			return err
		}
	}
	head := auditChainHead{OrganizationID: orgID, KeyVersion: s.auditSigner.ActiveVersion(), UpdatedAt: now}
	if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&head).Error; err != nil {
		return persistenceError(err)
	}
	query := tx.Select(auditHeadReadColumns(tx)).Where("organization_id = ?", orgID)
	if s.driver == "postgres" {
		query = query.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := query.First(&head).Error; err != nil {
		return persistenceError(err)
	}
	if _, err := s.verifyAuditTail(tx, head); err != nil {
		return err
	}
	if databaseClock {
		// Reobserve after any audit-head wait, on the transaction's connection.
		now, err = queueTime(tx, s.driver)
		if err != nil {
			return err
		}
	}
	id, err := NewID()
	if err != nil {
		return err
	}
	var actorID *int64
	if actor.ActorID > 0 {
		actorID = &actor.ActorID
	}
	diff, err := json.Marshal(struct {
		ReasonCode string `json:"reason_code"`
	}{actor.ReasonCode})
	if err != nil {
		return audit.ErrIntegrity
	}
	event, err := audit.Seal(audit.Event{ID: id, OrganizationID: orgID, Sequence: head.EventCount + 1,
		ActorID: actorID, Action: command.Action, ObjectType: command.ObjectType, ObjectID: command.ObjectID,
		Result: command.Result, IPSummary: actor.IPSummary, UserAgentSummary: actor.UserAgentSummary,
		DiffSummary: string(diff), PreviousHash: head.EventHash, CreatedAt: now}, s.auditSigner)
	if err != nil {
		return err
	}
	if err := tx.Create(&event).Error; err != nil {
		return persistenceError(err)
	}
	return persistenceError(tx.Model(&auditChainHead{}).Where("organization_id = ?", orgID).
		Updates(map[string]any{"event_count": event.Sequence, "event_hash": event.EventHMAC, "key_version": event.KeyVersion, "updated_at": now}).Error)
}

func (t *Tenant) AppendAudit(command AuditCommand) error {
	return persistenceError(t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		return t.store.appendAudit(t.ctx, tx, t.orgID, command, nil)
	}))
}

func (s *Store) auditUserOrganizations(ctx context.Context, tx *gorm.DB, userID int64, command AuditCommand) error {
	var memberships []Membership
	if err := tx.Where("user_id = ?", userID).Order("organization_id").Find(&memberships).Error; err != nil {
		return persistenceError(err)
	}
	if len(memberships) == 0 {
		orgID, err := initialAuditOrganization(tx)
		if err != nil {
			return err
		}
		return s.appendAudit(ctx, tx, orgID, command, nil)
	}
	for _, membership := range memberships {
		if err := s.appendAudit(ctx, tx, membership.OrganizationID, command, nil); err != nil {
			return err
		}
	}
	return nil
}

// An account without memberships still has an authentication audit trail. This
// anchor grants neither membership nor access to the initial organization.
func initialAuditOrganization(tx *gorm.DB) (int64, error) {
	var value string
	// A positive int64 decimal (including an existing leading plus) needs at
	// most 20 bytes. Reject corrupt documents before allocating their contents.
	if err := tx.Table("system_settings").Select(readBoundedText(tx, "value_json", "value_json", 20)).Where("setting_key = ?", "initial_organization_id").Limit(1).Scan(&value).Error; err != nil {
		return 0, persistenceError(err)
	}
	orgID, err := strconv.ParseInt(value, 10, 64)
	if err != nil || orgID <= 0 {
		return 0, audit.ErrIntegrity
	}
	return orgID, nil
}

func auditObject(action, objectType string, objectID int64) AuditCommand {
	return AuditCommand{Action: action, ObjectType: objectType, ObjectID: strconv.FormatInt(objectID, 10), Result: "success"}
}

func (s *Store) verifyAuditTail(tx *gorm.DB, head auditChainHead) (AuditVerification, error) {
	result := AuditVerification{OrganizationID: head.OrganizationID, EventCount: head.EventCount}
	var events []audit.Event
	if err := tx.Select(auditEventReadColumns(tx)).Where("organization_id = ?", head.OrganizationID).Order("sequence DESC").Limit(2).Find(&events).Error; err != nil {
		return result, persistenceError(err)
	}
	return s.verifyAuditTailRecords(head, events)
}

// Shared pure validation keeps diagnostic readers and append verification on
// the exact same existing chain/hash rules, without exposing event content.
func (s *Store) verifyAuditTailRecords(head auditChainHead, events []audit.Event) (AuditVerification, error) {
	result := AuditVerification{OrganizationID: head.OrganizationID, EventCount: head.EventCount}
	if head.EventCount == 0 {
		if len(events) != 0 || head.EventHash != "" {
			return result, audit.ErrIntegrity
		}
		return result, nil
	}
	if head.EventCount < 0 || len(events) == 0 || events[0].Sequence != head.EventCount || events[0].EventHMAC != head.EventHash || events[0].KeyVersion != head.KeyVersion {
		return result, audit.ErrIntegrity
	}
	for i, event := range events {
		if err := audit.Verify(event, s.auditSigner); err != nil {
			return result, err
		}
		if i == 1 && (events[0].PreviousHash != event.EventHMAC || events[0].Sequence != event.Sequence+1) {
			return result, audit.ErrIntegrity
		}
		result.VerifiedCount++
	}
	if (events[0].Sequence == 1 && events[0].PreviousHash != "") || (events[0].Sequence > 1 && len(events) != 2) {
		return result, audit.ErrIntegrity
	}
	result.LastEventAt = &events[0].CreatedAt
	return result, nil
}

func (t *Tenant) VerifyAuditTail() (AuditVerification, error) { return t.verifyAudit(false) }

func (t *Tenant) VerifyAuditFull() (AuditVerification, error) { return t.verifyAudit(true) }

func (t *Tenant) verifyAudit(full bool) (AuditVerification, error) {
	result := AuditVerification{OrganizationID: t.orgID}
	if t.store.auditSigner == nil {
		return result, audit.ErrUnavailable
	}
	err := t.store.db.WithContext(t.ctx).Transaction(func(tx *gorm.DB) error {
		var head auditChainHead
		query := tx.Select(auditHeadReadColumns(tx)).Where("organization_id = ?", t.orgID)
		if t.store.driver == "postgres" {
			query = query.Clauses(clause.Locking{Strength: "SHARE"})
		}
		if err := query.First(&head).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				// Initialized organizations always get an initial event/head. Missing
				// heads must not silently turn tampered chains into 'empty success'.
				return audit.ErrIntegrity
			}
			return persistenceError(err)
		}
		var err error
		if full {
			result, err = t.store.verifyAuditFull(tx, head)
		} else {
			result, err = t.store.verifyAuditTail(tx, head)
		}
		return err
	})
	return result, persistenceError(err)
}

// One full-chain algorithm serves the original lock-owning public reader and
// the internal caller-owned snapshot reader. The caller supplies either its
// existing head lock or a stable transaction snapshot; this function does not
// start another transaction, change isolation, or acquire a head lock itself.
func (s *Store) verifyAuditFull(tx *gorm.DB, head auditChainHead) (AuditVerification, error) {
	result, err := s.verifyAuditTail(tx, head)
	if err != nil {
		return result, err
	}
	result.VerifiedCount = 0
	previousHash := ""
	// The public caller's SHARE lock serializes appends; snapshot callers instead
	// keep a stable read view. The same 500-event cursor batches bound memory.
	for result.VerifiedCount < head.EventCount {
		var events []audit.Event
		if err := tx.Select(auditEventReadColumns(tx)).Where("organization_id = ? AND sequence > ?", head.OrganizationID, result.VerifiedCount).Order("sequence").Limit(500).Find(&events).Error; err != nil {
			return result, persistenceError(err)
		}
		if len(events) == 0 {
			return result, audit.ErrIntegrity
		}
		for _, event := range events {
			if event.Sequence != result.VerifiedCount+1 || event.PreviousHash != previousHash {
				return result, audit.ErrIntegrity
			}
			if err := audit.Verify(event, s.auditSigner); err != nil {
				return result, err
			}
			result.VerifiedCount++
			previousHash = event.EventHMAC
		}
	}
	if result.VerifiedCount != head.EventCount || previousHash != head.EventHash {
		return result, audit.ErrIntegrity
	}
	return result, nil
}

// ListAudit is scope-bound and append-only: no event update/delete API exists.
func (t *Tenant) ListAudit(afterSequence int64, limit int) ([]audit.Event, error) {
	if afterSequence < 0 || limit < 1 || limit > 100 {
		return nil, ErrConfiguration
	}
	var events []audit.Event
	err := t.scoped().Select(auditEventReadColumns(t.store.db)).Where("sequence > ?", afterSequence).Order("sequence").Limit(limit).Find(&events).Error
	if err != nil {
		return nil, persistenceError(err)
	}
	// Return no partial page or invalid sentinel. This authenticates each event,
	// not the page's completeness or the entire chain; full verification remains
	// a separate API with the unchanged head lock and ordered chain checks.
	for _, event := range events {
		if err := audit.Verify(event, t.store.auditSigner); err != nil {
			return nil, err
		}
	}
	return events, nil
}
