// Package evidencedisplay prepares bounded, credential-redacted display copies.
// It neither authenticates database identities nor authorizes HTTP disclosure.
package evidencedisplay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

const (
	PolicyVersion      = "display-redaction-v1"
	MaxTextBytes       = 1 << 20
	MaxPayloadBytes    = 4 << 20
	MaxDictionaryBytes = 2 << 20
	MaxEvents          = 256
)

var (
	ErrInvalid   = errors.New("MI_DISPLAY_INVALID")
	ErrLimit     = errors.New("MI_DISPLAY_LIMIT")
	ErrPolicy    = errors.New("MI_DISPLAY_REDACTION_POLICY")
	ErrCancelled = errors.New("MI_DISPLAY_CANCELLED")
	ErrSensitive = errors.New("MI_DISPLAY_SERIALIZATION_FORBIDDEN")
	ErrConsumer  = errors.New("MI_DISPLAY_CONSUMER_FAILED")
)

// Source is an internal assembly input. A matching wire hash proves consistency,
// not authenticity of caller-supplied database facts. The Worker must supply its
// frozen request and actual parsed response inside Credentials.Use.
type Source struct {
	Request  domain.NormalizedRequest
	Snapshot domain.RequestSnapshot
	Response domain.NormalizedResponse
}

func (Source) String() string               { return "[protected display source]" }
func (v Source) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (Source) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v Source) LogValue() slog.Value       { return slog.StringValue(v.String()) }

type document struct {
	Version         int          `json:"version"`
	Policy          string       `json:"policy"`
	SourceHash      string       `json:"source_hash"`
	RequestHash     string       `json:"request_hash"`
	TemplateHash    string       `json:"template_hash"`
	RequestJSON     string       `json:"request_json"`
	RequestChanged  bool         `json:"request_changed"`
	Response        responseView `json:"response"`
	MetadataOmitted bool         `json:"metadata_omitted"`
}

type responseView struct {
	Content             string                      `json:"content"`
	ModelReported       string                      `json:"model_reported"`
	HTTPStatus          int                         `json:"http_status"`
	FinishReason        string                      `json:"finish_reason"`
	ParseStatus         string                      `json:"parse_status"`
	PromptTokens        *int64                      `json:"prompt_tokens"`
	CompletionTokens    *int64                      `json:"completion_tokens"`
	TotalTokens         *int64                      `json:"total_tokens"`
	ReasoningTokens     *int64                      `json:"reasoning_tokens"`
	DurationMS          int64                       `json:"duration_ms"`
	FirstTokenMS        *int64                      `json:"first_token_ms"`
	StreamTerminated    bool                        `json:"stream_terminated"`
	Events              []domain.StreamEventSummary `json:"events"`
	EventSummaryPartial bool                        `json:"event_summary_partial"`
}

type protectedPayload struct {
	mu                      sync.RWMutex
	data                    []byte
	sourceHash, requestHash string
}

// Prepared has no public raw getter or ordinary JSON representation. Only
// Prepare constructs one. Decoding authenticated bytes produces a different
// type, so a decoded/forged document cannot be converted into a sealable input.
type Prepared struct{ prepared *protectedPayload }
type Opened struct{ opened *protectedPayload }

func (Prepared) String() string               { return "[prepared display evidence]" }
func (v Prepared) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (Prepared) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v Prepared) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (Opened) String() string                 { return "[authenticated display evidence]" }
func (v Opened) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, v.String()) }
func (Opened) MarshalJSON() ([]byte, error)   { return nil, ErrSensitive }
func (v Opened) LogValue() slog.Value         { return slog.StringValue(v.String()) }

func (p *Prepared) Hashes() (source, request string) {
	if p == nil || p.prepared == nil {
		return "", ""
	}
	p.prepared.mu.RLock()
	defer p.prepared.mu.RUnlock()
	if len(p.prepared.data) == 0 {
		return "", ""
	}
	return p.prepared.sourceHash, p.prepared.requestHash
}

func closePayload(p *protectedPayload) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	clear(p.data)
	p.data = nil
}
func (p *Prepared) Close() {
	if p != nil {
		closePayload(p.prepared)
	}
}
func (p *Opened) Close() {
	if p != nil {
		closePayload(p.opened)
	}
}

func withCanonical(ctx context.Context, p *protectedPayload, fn func([]byte) error) (result error) {
	defer func() {
		if recover() != nil {
			result = ErrConsumer
		}
	}()
	if ctx == nil || p == nil || fn == nil {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	p.mu.RLock()
	if len(p.data) == 0 || len(p.data) > MaxPayloadBytes {
		p.mu.RUnlock()
		return ErrInvalid
	}
	borrowed := bytes.Clone(p.data)
	p.mu.RUnlock()
	defer clear(borrowed)
	if err := fn(borrowed); err != nil {
		return ErrConsumer
	}
	if ctx.Err() != nil {
		return ErrCancelled
	}
	return nil
}

// WithCanonicalForSeal is an explicit trusted codec boundary, not MarshalJSON.
// Its callback must be bounded, never retain/log borrowed bytes, and never do
// network I/O. Copies made by trusted callbacks cannot be forcibly zeroized.
func (p *Prepared) WithCanonicalForSeal(ctx context.Context, fn func([]byte) error) error {
	if p == nil {
		return ErrInvalid
	}
	return withCanonical(ctx, p.prepared, fn)
}

// WithCanonicalForDisplay is for the future service only AFTER its independent
// authority/retention/audit checks. Possessing this value grants no HTTP access.
func (p *Opened) WithCanonicalForDisplay(ctx context.Context, fn func([]byte) error) error {
	if p == nil {
		return ErrInvalid
	}
	return withCanonical(ctx, p.opened, fn)
}

// DecodeAuthenticatedCanonical must only be called after the display-purpose
// AEAD check. It authenticates nothing itself and cannot produce a Prepared.
// Exact re-encoding rejects unknown/duplicate fields and noncanonical Unicode.
func DecodeAuthenticatedCanonical(data []byte, sourceHash, requestHash string) (*Opened, error) {
	if len(data) == 0 || len(data) > MaxPayloadBytes || !validHash(sourceHash) || !validHash(requestHash) {
		return nil, ErrInvalid
	}
	var v document
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&v) != nil || v.Version != 1 || v.Policy != PolicyVersion || v.SourceHash != sourceHash || v.RequestHash != requestHash || !v.MetadataOmitted || len(v.RequestJSON) > MaxTextBytes || !json.Valid([]byte(v.RequestJSON)) || digest([]byte(v.RequestJSON)) != v.TemplateHash || v.RequestChanged != (v.RequestHash != v.TemplateHash) || !validView(v.Response) {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(v)
	if err != nil || !bytes.Equal(encoded, data) {
		clear(encoded)
		return nil, ErrInvalid
	}
	return &Opened{opened: &protectedPayload{data: encoded, sourceHash: sourceHash, requestHash: requestHash}}, nil
}
