package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gorm.io/gorm"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

type maintenanceOperation struct {
	ID               int64
	Scope            string
	Mode             MaintenanceMode
	Generation       int64
	Owner            string
	InitiatedBy      int64
	SessionID        int64
	ReasonCode       string
	Status           string
	CreatedAtMicros  int64
	UpdatedAtMicros  int64
	LeaseUntilMicros int64
	DeadlineMicros   int64
	EventSequence    int64
	EventDigest      string
}

func (maintenanceOperation) TableName() string            { return "system_maintenance_operations" }
func (maintenanceOperation) String() string               { return "[private maintenance operation]" }
func (v maintenanceOperation) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (maintenanceOperation) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }

// Immutable event facts have no owner token, path, DSN or request text. Their
// fixed canonical digest is authenticated by the existing system audit anchor.
type maintenanceEvent struct {
	OperationID         int64
	Sequence            int64
	Scope               string
	Action              string
	ActorID             int64
	SessionID           int64
	ReasonCode          string
	BeforeMode          MaintenanceMode
	AfterMode           MaintenanceMode
	BeforeVersion       int64
	AfterVersion        int64
	BeforeGeneration    int64
	AfterGeneration     int64
	Generation          int64
	InitiatedBy         int64
	InitiatingSessionID int64
	PreviousStatus      string
	Status              string
	ObservedAtMicros    int64
	LeaseUntilMicros    int64
	DeadlineMicros      int64
	Digest              string
}

func (maintenanceEvent) TableName() string { return "system_maintenance_events" }

func maintenanceEventDigest(e maintenanceEvent) (string, error) {
	if e.OperationID <= 0 || e.Sequence <= 0 || e.Scope != "system" || e.ActorID <= 0 || e.SessionID <= 0 || !validMaintenanceReason(e.ReasonCode) || e.BeforeVersion < 1 || e.AfterVersion < e.BeforeVersion || e.BeforeGeneration < 0 || e.AfterGeneration < e.BeforeGeneration || e.Generation < 1 || e.InitiatedBy <= 0 || e.InitiatingSessionID <= 0 || e.ObservedAtMicros <= 0 || e.LeaseUntilMicros <= 0 || e.DeadlineMicros < e.LeaseUntilMicros {
		return "", ErrMaintenanceSource
	}
	if e.BeforeMode != MaintenanceNormal && e.BeforeMode != MaintenanceBackupFreeze {
		return "", ErrMaintenanceSource
	}
	if e.AfterMode != MaintenanceNormal && e.AfterMode != MaintenanceBackupFreeze {
		return "", ErrMaintenanceSource
	}
	switch e.Action {
	case "begin":
		if e.PreviousStatus != "none" || e.Status != "active" || e.AfterMode != MaintenanceBackupFreeze {
			return "", ErrMaintenanceSource
		}
	case "renew":
		if e.PreviousStatus != "active" || e.Status != "active" || e.BeforeMode != MaintenanceBackupFreeze || e.AfterMode != MaintenanceBackupFreeze {
			return "", ErrMaintenanceSource
		}
	case "abort":
		if e.PreviousStatus != "active" || e.Status != "aborted" || e.BeforeMode != MaintenanceBackupFreeze || e.AfterMode != MaintenanceNormal {
			return "", ErrMaintenanceSource
		}
	case "supersede":
		if e.PreviousStatus != "active" || e.Status != "superseded" || e.BeforeMode != MaintenanceBackupFreeze || e.AfterMode != MaintenanceBackupFreeze {
			return "", ErrMaintenanceSource
		}
	default:
		return "", ErrMaintenanceSource
	}
	// An explicit field list preserves canonical order independently of ORM or
	// later diagnostic fields. The schema/domain are part of the digest.
	canonical := struct {
		Version                                                                                                      string
		OperationID, Sequence                                                                                        int64
		Scope, Action                                                                                                string
		ActorID, SessionID                                                                                           int64
		ReasonCode                                                                                                   string
		BeforeMode, AfterMode                                                                                        MaintenanceMode
		BeforeVersion, AfterVersion, BeforeGeneration, AfterGeneration, Generation, InitiatedBy, InitiatingSessionID int64
		PreviousStatus, Status                                                                                       string
		ObservedAtMicros, LeaseUntilMicros, DeadlineMicros                                                           int64
	}{"mii.system-maintenance-event.v1", e.OperationID, e.Sequence, e.Scope, e.Action, e.ActorID, e.SessionID, e.ReasonCode, e.BeforeMode, e.AfterMode, e.BeforeVersion, e.AfterVersion, e.BeforeGeneration, e.AfterGeneration, e.Generation, e.InitiatedBy, e.InitiatingSessionID, e.PreviousStatus, e.Status, e.ObservedAtMicros, e.LeaseUntilMicros, e.DeadlineMicros}
	data, err := json.Marshal(canonical)
	if err != nil || len(data) > 2048 {
		return "", ErrMaintenanceSource
	}
	sum := sha256.Sum256(append([]byte("mii/system-maintenance/event/v1\x00"), data...))
	return hex.EncodeToString(sum[:]), nil
}

func maintenanceEventObject(e maintenanceEvent) string {
	return strconv.FormatInt(e.OperationID, 10) + ":" + e.Digest
}

func (s *Store) appendMaintenanceEvent(db *gorm.DB, e *maintenanceEvent) error {
	digest, err := maintenanceEventDigest(*e)
	if err != nil {
		return err
	}
	e.Digest = digest
	if err := db.Create(e).Error; err != nil {
		return err
	}
	anchor, err := initialAuditOrganization(db)
	if err != nil {
		return err
	}
	// initial_organization_id is the persistent SYSTEM anchor, not a statement
	// that this cross-organization action affected only that organization. A
	// non-member system administrator is recorded there identically.
	actor, err := audit.ActorFromContext(db.Statement.Context)
	if err != nil || actor.ActorID != e.ActorID {
		return audit.ErrActorRequired
	}
	actor.ReasonCode = e.ReasonCode
	return s.appendAuditWithClock(audit.WithActor(db.Statement.Context, actor), db, anchor, AuditCommand{Action: "system.maintenance." + e.Action, ObjectType: "system_maintenance_operation", ObjectID: maintenanceEventObject(*e), Result: "success"}, nil, true)
}

func (s *Store) verifyMaintenanceOperation(db *gorm.DB, op maintenanceOperation) (maintenanceEvent, error) {
	if op.ID <= 0 || op.Scope != "system" || op.Mode != MaintenanceBackupFreeze || op.Generation <= 0 || !maintenanceOwnerPattern.MatchString(op.Owner) || op.InitiatedBy <= 0 || op.SessionID <= 0 || !validMaintenanceReason(op.ReasonCode) || op.CreatedAtMicros <= 0 || op.UpdatedAtMicros < op.CreatedAtMicros || op.LeaseUntilMicros <= 0 || op.DeadlineMicros < op.LeaseUntilMicros || op.EventSequence <= 0 || !executionHash.MatchString(op.EventDigest) {
		return maintenanceEvent{}, ErrMaintenanceSource
	}
	var event maintenanceEvent
	if err := db.Where("operation_id=?", op.ID).Order("sequence DESC").Take(&event).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return maintenanceEvent{}, ErrMaintenanceSource
		}
		return maintenanceEvent{}, err
	}
	digest, err := maintenanceEventDigest(event)
	if err != nil || event.Sequence != op.EventSequence || digest != event.Digest || digest != op.EventDigest || event.Generation != op.Generation || event.InitiatedBy != op.InitiatedBy || event.InitiatingSessionID != op.SessionID || event.Status != op.Status || event.ReasonCode != op.ReasonCode || event.ObservedAtMicros != op.UpdatedAtMicros || event.LeaseUntilMicros != op.LeaseUntilMicros || event.DeadlineMicros != op.DeadlineMicros {
		return maintenanceEvent{}, ErrMaintenanceSource
	}
	anchor, err := initialAuditOrganization(db)
	if err != nil {
		return maintenanceEvent{}, err
	}
	var events []audit.Event
	columns := "id,organization_id,sequence,actor_id,created_at"
	for _, field := range []struct {
		name  string
		limit int
	}{{"action", 128}, {"object_type", 128}, {"object_id", 128}, {"result", 128}, {"ip_summary", 128}, {"user_agent_summary", 128}, {"diff_summary", 1024}, {"previous_hash", 64}, {"event_hmac", 64}, {"canonicalization_version", 128}, {"key_version", 128}} {
		// Bound encoded bytes before database/sql allocates any string. Even
		// an optional legitimate empty audit field must use an INVALID overflow
		// sentinel, not an empty value that might match the original HMAC.
		columns += "," + strings.Replace(readBoundedText(db, field.name, field.name, field.limit), "ELSE ''", "ELSE '\n'", 1)
	}
	if err := db.Select(columns).Where("organization_id=? AND action=? AND object_type=? AND object_id=?", anchor, "system.maintenance."+event.Action, "system_maintenance_operation", maintenanceEventObject(event)).Limit(2).Find(&events).Error; err != nil {
		return maintenanceEvent{}, err
	}
	if len(events) != 1 || events[0].ActorID == nil || *events[0].ActorID != event.ActorID || events[0].Result != "success" {
		return maintenanceEvent{}, ErrMaintenanceSource
	}
	if err := audit.Verify(events[0], s.auditSigner); err != nil {
		return maintenanceEvent{}, err
	}
	var reason struct {
		ReasonCode string `json:"reason_code"`
	}
	if json.Unmarshal([]byte(events[0].DiffSummary), &reason) != nil || reason.ReasonCode != event.ReasonCode || events[0].CreatedAt.UnixMicro() < event.ObservedAtMicros {
		return maintenanceEvent{}, ErrMaintenanceSource
	}
	return event, nil
}
