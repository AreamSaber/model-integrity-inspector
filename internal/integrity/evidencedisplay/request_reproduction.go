package evidencedisplay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

const RequestReproductionPolicyVersion = "request-redaction-v1"

// RequestReproductionSource is assembled inside the real Credentials.Use
// callback from the frozen request and signed manifest. It has no response,
// endpoint or transport-header metadata. Matching hashes prove consistency,
// not the caller's authority or authenticity of an arbitrary supplied manifest.
type RequestReproductionSource struct {
	Request      domain.NormalizedRequest
	Snapshot     domain.RequestSnapshot
	ManifestHash string
}

func (RequestReproductionSource) String() string               { return "[protected request reproduction source]" }
func (v RequestReproductionSource) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (RequestReproductionSource) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v RequestReproductionSource) LogValue() slog.Value       { return slog.StringValue(v.String()) }

type requestReproductionDocument struct {
	Version        int    `json:"version"`
	Policy         string `json:"policy"`
	RequestHash    string `json:"request_hash"`
	TemplateHash   string `json:"template_hash"`
	RequestJSON    string `json:"request_json"`
	RequestChanged bool   `json:"request_changed"`
}

// Distinct private fields prevent conversion from authenticated opened data to
// a sealable input, or conversion from either response-display wrapper.
type PreparedRequestReproduction struct{ preparedRequest *protectedPayload }
type OpenedRequestReproduction struct{ openedRequest *protectedPayload }

func (PreparedRequestReproduction) String() string { return "[prepared request reproduction]" }
func (v PreparedRequestReproduction) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, v.String())
}
func (PreparedRequestReproduction) MarshalJSON() ([]byte, error) { return nil, ErrSensitive }
func (v PreparedRequestReproduction) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (OpenedRequestReproduction) String() string                 { return "[authenticated request reproduction]" }
func (v OpenedRequestReproduction) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, v.String()) }
func (OpenedRequestReproduction) MarshalJSON() ([]byte, error)   { return nil, ErrSensitive }
func (v OpenedRequestReproduction) LogValue() slog.Value         { return slog.StringValue(v.String()) }

// BindingHashes exposes only binding digests. The manifest is not part of the
// template bytes: the request-purpose AEAD must bind it independently as AAD.
func (p *PreparedRequestReproduction) BindingHashes() (manifest, request string) {
	if p == nil || p.preparedRequest == nil {
		return "", ""
	}
	p.preparedRequest.mu.RLock()
	defer p.preparedRequest.mu.RUnlock()
	if len(p.preparedRequest.data) == 0 {
		return "", ""
	}
	return p.preparedRequest.sourceHash, p.preparedRequest.requestHash
}

func (p *PreparedRequestReproduction) Close() {
	if p != nil {
		closePayload(p.preparedRequest)
	}
}
func (p *OpenedRequestReproduction) Close() {
	if p != nil {
		closePayload(p.openedRequest)
	}
}

// WithCanonicalForSeal borrows a cleared-on-return copy for the trusted codec.
// Callbacks must be bounded and must not retain/log bytes or perform network I/O.
// Context cancellation cannot forcibly interrupt arbitrary callback code, and
// copies/Go strings made by trusted callbacks cannot be forcibly zeroized.
func (p *PreparedRequestReproduction) WithCanonicalForSeal(ctx context.Context, fn func([]byte) error) error {
	if p == nil {
		return ErrInvalid
	}
	return withCanonical(ctx, p.preparedRequest, fn)
}

// WithCanonicalForReproduction is pure data, never a shell command or an HTTP
// grant. The future service separately checks current authority, request S2
// retention and audit; possession of an Opened value authorizes no disclosure.
func (p *OpenedRequestReproduction) WithCanonicalForReproduction(ctx context.Context, fn func([]byte) error) error {
	if p == nil {
		return ErrInvalid
	}
	return withCanonical(ctx, p.openedRequest, fn)
}

// PrepareRequestReproduction needs the actual credential and every transport
// header value, even for ordinary header names. It uses the same finite
// redaction policy and deterministic adapter verification as response display;
// it neither changes the request nor invents a response when none exists.
func PrepareRequestReproduction(ctx context.Context, source RequestReproductionSource, key []byte, headers map[string][]byte) (*PreparedRequestReproduction, error) {
	ctx, cancel, err := prepareContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if !validHash(source.ManifestHash) {
		return nil, ErrInvalid
	}
	if err := validateRequestSource(source.Request, source.Snapshot); err != nil {
		return nil, err
	}
	replacer, _, err := dictionary(ctx, key, headers)
	if err != nil {
		return nil, err
	}
	requestJSON, err := requestForDisplay(ctx, source.Request, source.Snapshot, replacer)
	if err != nil {
		return nil, err
	}
	if quotedBytes(requestJSON)+1024 > MaxPayloadBytes {
		return nil, ErrLimit
	}
	templateHash := digest([]byte(requestJSON))
	doc := requestReproductionDocument{Version: 1, Policy: RequestReproductionPolicyVersion, RequestHash: source.Snapshot.RequestHash, TemplateHash: templateHash, RequestJSON: requestJSON, RequestChanged: templateHash != source.Snapshot.RequestHash}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(encoded) > MaxPayloadBytes {
		clear(encoded)
		return nil, ErrLimit
	}
	// Do not alter schema/numeric values when a known credential collides with
	// them. The whole value fails closed instead of omitting that credential.
	check := &boundedText{ctx: ctx, limit: MaxPayloadBytes}
	if _, err := replacer.WriteString(check, string(encoded)); err != nil {
		clear(encoded)
		return nil, err
	}
	if check.value.String() != string(encoded) {
		clear(encoded)
		return nil, ErrPolicy
	}
	if ctx.Err() != nil {
		clear(encoded)
		return nil, ErrCancelled
	}
	return &PreparedRequestReproduction{preparedRequest: &protectedPayload{data: encoded, sourceHash: source.ManifestHash, requestHash: source.Snapshot.RequestHash}}, nil
}

// DecodeAuthenticatedRequestReproduction is only a strict codec, to be called
// after request-purpose AEAD verification with the expected manifest in AAD.
// It cannot construct a Prepared or independently authenticate caller input.
func DecodeAuthenticatedRequestReproduction(data []byte, manifestHash, requestHash string) (*OpenedRequestReproduction, error) {
	if len(data) == 0 || len(data) > MaxPayloadBytes || !validHash(manifestHash) || !validHash(requestHash) {
		return nil, ErrInvalid
	}
	var doc requestReproductionDocument
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&doc) != nil || doc.Version != 1 || doc.Policy != RequestReproductionPolicyVersion || doc.RequestHash != requestHash || !validHash(doc.TemplateHash) || digest([]byte(doc.RequestJSON)) != doc.TemplateHash || doc.RequestChanged != (doc.RequestHash != doc.TemplateHash) || !validReproductionRequest(doc.RequestJSON) {
		return nil, ErrInvalid
	}
	encoded, err := json.Marshal(doc)
	if err != nil || !bytes.Equal(encoded, data) {
		clear(encoded)
		return nil, ErrInvalid
	}
	return &OpenedRequestReproduction{openedRequest: &protectedPayload{data: encoded, sourceHash: manifestHash, requestHash: requestHash}}, nil
}
