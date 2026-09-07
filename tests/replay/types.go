// Package replay is DEVELOPMENT-only offline test infrastructure. Production
// packages must not import it. A development signature proves neither official
// model provenance, independent QA acceptance nor authority to publish a result.
package replay

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
)

const (
	SchemaVersion      = "mii.replay-capture.v1"
	Implementation     = "mii.replay.development.v1"
	PredictionSchema   = "mii.replay-prediction.v1"
	MaxCaptureBytes    = 24 << 20
	MaxManifestBytes   = 2 << 20
	MaxBodyBytes       = 1 << 20
	MaxBodyBatchBytes  = 8 << 20
	MaxWireBatchBytes  = 4 << 20
	MaxPredictionBytes = 4 << 20
	MaxSamples         = 150
)

var (
	ErrConfiguration = errors.New("MI_REPLAY_CONFIGURATION_INVALID")
	ErrIntegrity     = errors.New("MI_REPLAY_CAPTURE_INTEGRITY")
	ErrLimit         = errors.New("MI_REPLAY_RESOURCE_LIMIT")
	ErrUnsupported   = errors.New("MI_REPLAY_CAPTURE_UNSUPPORTED")
	ErrCanceled      = errors.New("MI_REPLAY_CANCELED")
	ErrSensitive     = errors.New("MI_REPLAY_SERIALIZATION_FORBIDDEN")
)

// CaptureDraft is S2, intended only for the separate development controller.
// Its fields are NOT evidence of provenance. SealDevelopment is an explicit
// serialization path, not a release approval or a production source capability.
// The controller must wait for committed analysis and final settlement before
// constructing Commitment and sealing; the offline process cannot inspect DBs.
type CaptureDraft struct {
	SchemaVersion     string          `json:"schema_version"`
	Implementation    string          `json:"implementation"`
	CaseID            string          `json:"case_id"`
	KeyID             string          `json:"key_id"`
	OrganizationID    int64           `json:"organization_id,string"`
	RunID             int64           `json:"run_id,string"`
	Manifest          []byte          `json:"manifest"`
	ManifestHash      string          `json:"manifest_hash"`
	ExecutionClosedAt time.Time       `json:"execution_closed_at"`
	Commitment        Commitment      `json:"commitment"`
	Samples           []SampleCapture `json:"samples"`
}

type Commitment struct {
	RunStatus          string    `json:"run_status"`
	RunVersion         int64     `json:"run_version"`
	AnalysisRevision   int       `json:"analysis_revision"`
	PublicationHash    string    `json:"publication_hash"`
	FinishedAt         time.Time `json:"finished_at"`
	SettledRequests    int       `json:"settled_requests"`
	ReservedTokens     int64     `json:"reserved_tokens"`
	ReservedCostMicros int64     `json:"reserved_cost_micros"`
}

type SampleCapture struct {
	ID               int64            `json:"id,string"`
	ProbeInstanceID  int64            `json:"probe_instance_id,string"`
	Ordinal          int              `json:"ordinal"`
	ExecutionOrdinal int              `json:"execution_ordinal"`
	PairID           string           `json:"pair_id"`
	AttemptCount     int              `json:"attempt_count"`
	FinalAttemptID   int64            `json:"final_attempt_id,string"`
	Validity         string           `json:"validity"`
	CompletedAt      time.Time        `json:"completed_at"`
	Attempts         []AttemptCapture `json:"attempts"`
}

type AttemptCapture struct {
	ID          int64           `json:"id,string"`
	JobID       int64           `json:"job_id,string"`
	Number      int             `json:"number"`
	Status      string          `json:"status"`
	Validity    string          `json:"validity"`
	ErrorCode   string          `json:"error_code"`
	StartedAt   time.Time       `json:"started_at"`
	FinishedAt  time.Time       `json:"finished_at"`
	WirePayload []byte          `json:"wire_payload"`
	RequestHash string          `json:"request_hash"`
	Response    ResponseCapture `json:"response"`
}

// ResponseCapture contains actual finite entity bytes, not a normalized answer
// or local tokenizer count. Header duplicates remain observable to the parser.
type ResponseCapture struct {
	HTTPStatus   int            `json:"http_status"`
	Headers      []Header       `json:"headers"`
	Body         []byte         `json:"body"`
	BodyHash     string         `json:"body_hash"`
	End          string         `json:"end"`
	ProtocolHash string         `json:"protocol_hash"`
	Timing       ObservedTiming `json:"timing"`
}

type Header struct {
	Name   string   `json:"name"`
	Values []string `json:"values"`
}

type ObservedTiming struct {
	DurationMillis   int64         `json:"duration_ms"`
	FirstByteMillis  int64         `json:"first_byte_ms"`
	FirstTokenMillis *int64        `json:"first_token_ms"`
	Events           []EventTiming `json:"events"`
}

type EventTiming struct {
	Sequence       int   `json:"sequence"`
	ArrivalMillis  int64 `json:"arrival_ms"`
	IntervalMillis int64 `json:"interval_ms"`
}

// Config is trusted local composition, never decoded from the capture. The
// pinned key is a DEVELOPMENT capture key. The Manifest verifier must use only
// synthetic development key material; do not export a production master key.
type Config struct {
	CaptureKeyID     string
	CapturePublicKey ed25519.PublicKey
	Verifier         *generator.Generator
	Runtime          *bundle.Runtime
}

type Prediction struct {
	SchemaVersion         string            `json:"schema_version"`
	Implementation        string            `json:"implementation"`
	CaseID                string            `json:"case_id"`
	CaptureHash           string            `json:"capture_hash"`
	CaptureKeyFingerprint string            `json:"capture_key_fingerprint"`
	ManifestHash          string            `json:"manifest_hash"`
	SourcePublicationHash string            `json:"source_publication_hash"`
	SourceRuleVersion     string            `json:"source_rule_version"`
	Runtime               bundle.RuntimeRef `json:"runtime"`
	Provenance            string            `json:"provenance"`
	TimingSource          string            `json:"timing_source"`
	Limitations           []string          `json:"limitations"`
	Analysis              analyzer.Document `json:"analysis"`
}

func (CaptureDraft) String() string               { return "[protected development capture]" }
func (d CaptureDraft) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }
func (CaptureDraft) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (d CaptureDraft) LogValue() slog.Value       { return slog.StringValue(d.String()) }

func (SampleCapture) String() string                 { return "[protected development sample]" }
func (s SampleCapture) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, s.String()) }
func (SampleCapture) MarshalJSON() ([]byte, error)   { return nil, ErrSensitive }
func (s SampleCapture) LogValue() slog.Value         { return slog.StringValue(s.String()) }
func (AttemptCapture) String() string                { return "[protected development attempt]" }
func (a AttemptCapture) Format(w fmt.State, _ rune)  { _, _ = io.WriteString(w, a.String()) }
func (AttemptCapture) MarshalJSON() ([]byte, error)  { return nil, ErrSensitive }
func (a AttemptCapture) LogValue() slog.Value        { return slog.StringValue(a.String()) }
func (ResponseCapture) String() string               { return "[protected development response]" }
func (r ResponseCapture) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, r.String()) }
func (ResponseCapture) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (r ResponseCapture) LogValue() slog.Value       { return slog.StringValue(r.String()) }
func (Header) String() string                        { return "[protected development headers]" }
func (h Header) Format(w fmt.State, _ rune)          { _, _ = io.WriteString(w, h.String()) }
func (Header) MarshalJSON() ([]byte, error)          { return nil, ErrSensitive }
func (h Header) LogValue() slog.Value                { return slog.StringValue(h.String()) }
func (Config) String() string                        { return "[protected development replay config]" }
func (c Config) Format(w fmt.State, _ rune)          { _, _ = io.WriteString(w, c.String()) }
func (Config) MarshalJSON() ([]byte, error)          { return nil, ErrSensitive }
func (c Config) LogValue() slog.Value                { return slog.StringValue(c.String()) }
func (Engine) String() string                        { return "[protected development replay engine]" }
func (e Engine) Format(w fmt.State, _ rune)          { _, _ = io.WriteString(w, e.String()) }
func (Engine) MarshalJSON() ([]byte, error)          { return nil, ErrSensitive }
func (e Engine) LogValue() slog.Value                { return slog.StringValue(e.String()) }
func (verifiedCapture) String() string               { return "[protected verified development capture]" }
func (v verifiedCapture) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, v.String()) }
func (verifiedCapture) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v verifiedCapture) LogValue() slog.Value       { return slog.StringValue(v.String()) }
