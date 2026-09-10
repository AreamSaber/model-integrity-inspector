package audit

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrActorRequired = errors.New("AUDIT_ACTOR_REQUIRED")
	ErrUnavailable   = errors.New("AUDIT_SIGNER_UNAVAILABLE")
	ErrIntegrity     = errors.New("AUDIT_INTEGRITY_FAILED")
)

const CanonicalizationVersion = "mii.audit.v1"

// MAC is implemented by the external key ring. No raw integrity key enters DB.
type MAC interface {
	ActiveVersion() string
	AuditMAC(version string, canonical []byte) ([]byte, error)
}

// Actor is trusted service metadata, never decoded directly from HTTP input.
// ReasonCode is a stable machine code, not user prose or request/response content.
type Actor struct {
	ActorID          int64
	ReasonCode       string
	IPSummary        string
	UserAgentSummary string
}

type actorKey struct{}

func WithActor(ctx context.Context, actor Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func ActorFromContext(ctx context.Context) (Actor, error) {
	actor, ok := ctx.Value(actorKey{}).(Actor)
	if !ok || actor.ActorID < 0 || !codePattern.MatchString(actor.ReasonCode) ||
		!safeSummary(actor.IPSummary, 128) || !safeSummary(actor.UserAgentSummary, 128) {
		return Actor{}, ErrActorRequired
	}
	return actor, nil
}

var codePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func safeSummary(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// Event is the append-only persistence record. Do not expose HMAC values in API DTOs.
type Event struct {
	ID                      int64
	OrganizationID          int64
	Sequence                int64
	ActorID                 *int64
	Action                  string
	ObjectType              string
	ObjectID                string
	Result                  string
	IPSummary               string
	UserAgentSummary        string
	DiffSummary             string
	PreviousHash            string
	EventHMAC               string `gorm:"column:event_hmac" json:"-"`
	CanonicalizationVersion string
	KeyVersion              string
	CreatedAt               time.Time
}

func (Event) TableName() string { return "integrity_audit_logs" }

// Canonical uses a fixed struct field order and integer UTC microseconds, which
// round-trip exactly through both SQLite and PostgreSQL timestamp columns.
// The previous hash is appended after canonical JSON, per ADR-0006.
func Canonical(event Event) ([]byte, error) {
	if event.ID <= 0 || event.OrganizationID <= 0 || event.Sequence <= 0 ||
		(event.ActorID != nil && *event.ActorID <= 0) || !codePattern.MatchString(event.Action) ||
		!codePattern.MatchString(event.ObjectType) || !codePattern.MatchString(event.Result) ||
		!safeSummary(event.ObjectID, 128) || !safeSummary(event.IPSummary, 128) ||
		!safeSummary(event.UserAgentSummary, 128) || !safeSummary(event.DiffSummary, 1024) ||
		event.CanonicalizationVersion != CanonicalizationVersion || !codePattern.MatchString(event.KeyVersion) ||
		event.CreatedAt.IsZero() || !event.CreatedAt.Equal(event.CreatedAt.Truncate(time.Microsecond)) || (event.PreviousHash != "" && !validHash(event.PreviousHash)) {
		return nil, ErrIntegrity
	}
	canonical := struct {
		Version        string `json:"version"`
		KeyVersion     string `json:"key_version"`
		ID             int64  `json:"id"`
		OrganizationID int64  `json:"organization_id"`
		Sequence       int64  `json:"sequence"`
		ActorID        *int64 `json:"actor_id"`
		Action         string `json:"action"`
		ObjectType     string `json:"object_type"`
		ObjectID       string `json:"object_id"`
		Result         string `json:"result"`
		IPSummary      string `json:"ip_summary"`
		UserAgent      string `json:"user_agent_summary"`
		DiffSummary    string `json:"diff_summary"`
		CreatedAtUS    int64  `json:"created_at_us"`
	}{event.CanonicalizationVersion, event.KeyVersion, event.ID, event.OrganizationID, event.Sequence,
		event.ActorID, event.Action, event.ObjectType, event.ObjectID, event.Result, event.IPSummary,
		event.UserAgentSummary, event.DiffSummary, event.CreatedAt.UTC().UnixMicro()}
	data, err := json.Marshal(canonical)
	if err != nil {
		return nil, ErrIntegrity
	}
	return append(data, []byte(event.PreviousHash)...), nil
}

func Seal(event Event, signer MAC) (Event, error) {
	if signer == nil {
		return Event{}, ErrUnavailable
	}
	event.CanonicalizationVersion = CanonicalizationVersion
	event.KeyVersion = signer.ActiveVersion()
	event.CreatedAt = event.CreatedAt.UTC().Truncate(time.Microsecond)
	data, err := Canonical(event)
	if err != nil {
		return Event{}, err
	}
	sum, err := signer.AuditMAC(event.KeyVersion, data)
	if err != nil || len(sum) != 32 {
		return Event{}, ErrUnavailable
	}
	event.EventHMAC = hex.EncodeToString(sum)
	return event, nil
}

func Verify(event Event, signer MAC) error {
	if signer == nil {
		return ErrUnavailable
	}
	data, err := Canonical(event)
	if err != nil || !validHash(event.EventHMAC) {
		return ErrIntegrity
	}
	expected, err := signer.AuditMAC(event.KeyVersion, data)
	if err != nil || len(expected) != 32 {
		return ErrUnavailable
	}
	actual, err := hex.DecodeString(event.EventHMAC)
	if err != nil || !hmac.Equal(expected, actual) {
		return ErrIntegrity
	}
	return nil
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}
