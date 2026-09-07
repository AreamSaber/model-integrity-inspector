package replay

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// Only private wire types may be serialized. They explicitly replace each
// protected nested container; ordinary public DTO marshaling always fails.
// No opaque verifiedCapture can be created by a JSON caller.
type captureData struct {
	SchemaVersion     string       `json:"schema_version"`
	Implementation    string       `json:"implementation"`
	CaseID            string       `json:"case_id"`
	KeyID             string       `json:"key_id"`
	OrganizationID    int64        `json:"organization_id,string"`
	RunID             int64        `json:"run_id,string"`
	Manifest          []byte       `json:"manifest"`
	ManifestHash      string       `json:"manifest_hash"`
	ExecutionClosedAt time.Time    `json:"execution_closed_at"`
	Commitment        Commitment   `json:"commitment"`
	Samples           []sampleData `json:"samples"`
}
type sampleData struct {
	ID               int64         `json:"id,string"`
	ProbeInstanceID  int64         `json:"probe_instance_id,string"`
	Ordinal          int           `json:"ordinal"`
	ExecutionOrdinal int           `json:"execution_ordinal"`
	PairID           string        `json:"pair_id"`
	AttemptCount     int           `json:"attempt_count"`
	FinalAttemptID   int64         `json:"final_attempt_id,string"`
	Validity         string        `json:"validity"`
	CompletedAt      time.Time     `json:"completed_at"`
	Attempts         []attemptData `json:"attempts"`
}
type attemptData struct {
	ID          int64        `json:"id,string"`
	JobID       int64        `json:"job_id,string"`
	Number      int          `json:"number"`
	Status      string       `json:"status"`
	Validity    string       `json:"validity"`
	ErrorCode   string       `json:"error_code"`
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at"`
	WirePayload []byte       `json:"wire_payload"`
	RequestHash string       `json:"request_hash"`
	Response    responseData `json:"response"`
}
type responseData struct {
	HTTPStatus   int            `json:"http_status"`
	Headers      []headerData   `json:"headers"`
	Body         []byte         `json:"body"`
	BodyHash     string         `json:"body_hash"`
	End          string         `json:"end"`
	ProtocolHash string         `json:"protocol_hash"`
	Timing       ObservedTiming `json:"timing"`
}
type headerData Header

func responseWire(r ResponseCapture) responseData {
	h := make([]headerData, len(r.Headers))
	for i, value := range r.Headers {
		h[i] = headerData(value)
	}
	return responseData{r.HTTPStatus, h, r.Body, r.BodyHash, r.End, r.ProtocolHash, r.Timing}
}
func draftData(d CaptureDraft) captureData {
	w := captureData{d.SchemaVersion, d.Implementation, d.CaseID, d.KeyID, d.OrganizationID, d.RunID, d.Manifest, d.ManifestHash, d.ExecutionClosedAt, d.Commitment, make([]sampleData, len(d.Samples))}
	for i, s := range d.Samples {
		w.Samples[i] = sampleData{s.ID, s.ProbeInstanceID, s.Ordinal, s.ExecutionOrdinal, s.PairID, s.AttemptCount, s.FinalAttemptID, s.Validity, s.CompletedAt, make([]attemptData, len(s.Attempts))}
		for j, a := range s.Attempts {
			w.Samples[i].Attempts[j] = attemptData{a.ID, a.JobID, a.Number, a.Status, a.Validity, a.ErrorCode, a.StartedAt, a.FinishedAt, a.WirePayload, a.RequestHash, responseWire(a.Response)}
		}
	}
	return w
}

type envelope struct {
	Capture   captureData `json:"capture"`
	SHA256    string      `json:"sha256"`
	Signature []byte      `json:"signature"`
}
type verifiedCapture struct {
	data captureData
	hash string
	plan domain.ExecutionPlan
}

var opaqueID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var hashID = regexp.MustCompile(`^[0-9a-f]{64}$`)
var keyID = regexp.MustCompile(`^dev-[a-z0-9][a-z0-9.-]{0,47}$`)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SealDevelopment serializes an explicit S2 draft. It authenticates only this
// development controller's statement; it cannot attest QA, labels or an actual
// database commit. The real capture fixture checks commit before calling it.
func SealDevelopment(draft CaptureDraft, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrConfiguration
	}
	data := draftData(draft)
	if err := bounded(data); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(data)
	if err != nil || len(raw) > MaxCaptureBytes {
		return nil, ErrLimit
	}
	defer clear(raw)
	out, err := json.Marshal(envelope{data, digest(raw), ed25519.Sign(key, signMessage(raw))})
	if err != nil || len(out) > MaxCaptureBytes {
		clear(out)
		return nil, ErrLimit
	}
	return out, nil
}

func signMessage(data []byte) []byte {
	// Hash framing is purpose- and schema-separated from Manifest/QA signatures.
	return []byte(Implementation + "\x00" + SchemaVersion + "\x00" + digest(data))
}

func (e *Engine) verify(ctx context.Context, reader io.Reader) (*verifiedCapture, error) {
	if ctx == nil || reader == nil || e == nil {
		return nil, ErrConfiguration
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxCaptureBytes+1))
	if err != nil {
		return nil, ErrIntegrity
	}
	defer clear(raw)
	if len(raw) > MaxCaptureBytes {
		return nil, ErrLimit
	}
	if !utf8.Valid(raw) {
		return nil, ErrIntegrity
	}
	var value envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return nil, ErrIntegrity
	}
	canonical, err := json.Marshal(value)
	defer clear(canonical)
	// Exact canonical equality rejects duplicates, case aliases, omitted fields,
	// alternate encodings and trailing JSON/whitespace without ignoring any key.
	if err != nil || !bytes.Equal(canonical, raw) || len(value.Signature) != ed25519.SignatureSize || value.Capture.KeyID != e.keyID {
		return nil, ErrIntegrity
	}
	if err := bounded(value.Capture); err != nil {
		return nil, err
	}
	unsigned, err := json.Marshal(value.Capture)
	defer clear(unsigned)
	if err != nil || digest(unsigned) != value.SHA256 || !ed25519.Verify(e.publicKey, signMessage(unsigned), value.Signature) {
		return nil, ErrIntegrity
	}
	plan, err := e.verifier.ExecutionPlan(value.Capture.Manifest, value.Capture.ManifestHash, value.Capture.OrganizationID)
	if err != nil || len(plan.Probes) != len(value.Capture.Samples) {
		return nil, ErrIntegrity
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	if err := bindPlan(value.Capture, plan); err != nil {
		return nil, err
	}
	return &verifiedCapture{value.Capture, digest(raw), plan}, nil
}

func validTime(value time.Time) bool {
	_, offset := value.Zone()
	return !value.IsZero() && offset == 0 && value.Year() >= 2000 && value.Year() <= 2100
}

func bounded(d captureData) error {
	if d.SchemaVersion != SchemaVersion || d.Implementation != Implementation {
		return ErrUnsupported
	}
	if !opaqueID.MatchString(d.CaseID) || !keyID.MatchString(d.KeyID) || d.OrganizationID <= 0 || d.RunID <= 0 || !hashID.MatchString(d.ManifestHash) || !validTime(d.ExecutionClosedAt) {
		return ErrIntegrity
	}
	if len(d.Manifest) < 1 || len(d.Manifest) > MaxManifestBytes || len(d.Samples) < 1 || len(d.Samples) > MaxSamples {
		return ErrLimit
	}
	if !utf8.Valid(d.Manifest) || digest(d.Manifest) != d.ManifestHash {
		return ErrIntegrity
	}
	c := d.Commitment
	if !slices.Contains([]string{"COMPLETED", "PARTIAL", "REVIEW_REQUIRED"}, c.RunStatus) || c.RunVersion < 1 || c.AnalysisRevision != 1 || !hashID.MatchString(c.PublicationHash) || !validTime(c.FinishedAt) || c.FinishedAt.Before(d.ExecutionClosedAt) || c.SettledRequests != len(d.Samples) || c.ReservedTokens != 0 || c.ReservedCostMicros != 0 {
		return ErrIntegrity
	}
	samples, probes, attempts, jobs, requests := map[int64]bool{}, map[int64]bool{}, map[int64]bool{}, map[int64]bool{}, map[string]bool{}
	var bodyBytes, wireBytes int
	for i, s := range d.Samples {
		if s.ID <= 0 || s.ProbeInstanceID <= 0 || samples[s.ID] || probes[s.ProbeInstanceID] || s.Ordinal != i || s.ExecutionOrdinal != i || !validTime(s.CompletedAt) || s.CompletedAt.After(d.ExecutionClosedAt) || s.FinalAttemptID <= 0 || (s.Validity != "VALID" && s.Validity != "VALID_WITH_WARNING") || len(s.PairID) > 128 {
			return ErrIntegrity
		}
		if s.AttemptCount != 1 || len(s.Attempts) != 1 {
			return ErrUnsupported
		}
		samples[s.ID], probes[s.ProbeInstanceID] = true, true
		a := s.Attempts[0]
		if a.ID <= 0 || a.ID != s.FinalAttemptID || a.JobID <= 0 || attempts[a.ID] || jobs[a.JobID] || requests[a.RequestHash] || a.Number != 1 || a.Status != "COMPLETED" || a.Validity != s.Validity || a.ErrorCode != "" || !hashID.MatchString(a.RequestHash) || !validTime(a.StartedAt) || !validTime(a.FinishedAt) || a.FinishedAt.Before(a.StartedAt) || a.FinishedAt.After(s.CompletedAt) {
			return ErrIntegrity
		}
		if a.FinishedAt.Sub(a.StartedAt) > 180*time.Second {
			return ErrUnsupported
		}
		attempts[a.ID], jobs[a.JobID], requests[a.RequestHash] = true, true, true
		if len(a.WirePayload) < 1 || len(a.WirePayload) > openaichat.MaxRequestBytes || len(a.Response.Body) < 1 || len(a.Response.Body) > MaxBodyBytes {
			return ErrLimit
		}
		wireBytes += len(a.WirePayload)
		bodyBytes += len(a.Response.Body)
		if wireBytes > MaxWireBatchBytes || bodyBytes > MaxBodyBatchBytes {
			return ErrLimit
		}
		if digest(a.WirePayload) != a.RequestHash || digest(a.Response.Body) != a.Response.BodyHash || !hashID.MatchString(a.Response.ProtocolHash) || !utf8.Valid(a.WirePayload) {
			return ErrIntegrity
		}
		if a.Response.HTTPStatus != 200 || (a.Response.End != "done" && a.Response.End != "eof") {
			return ErrUnsupported
		}
		if err := validHeaders(a.Response.Headers); err != nil {
			return err
		}
		if err := validTiming(a.Response.Timing, a.FinishedAt.Sub(a.StartedAt)); err != nil {
			return err
		}
	}
	return nil
}

func validHeaders(headers []headerData) error {
	if len(headers) < 1 || len(headers) > 5 {
		return ErrLimit
	}
	seen := map[string]bool{}
	total := 0
	for _, h := range headers {
		if !slices.Contains([]string{"Content-Type", "Retry-After", "X-Request-Id", "Request-Id", "Openai-Processing-Ms"}, h.Name) || seen[h.Name] {
			return ErrIntegrity
		}
		seen[h.Name] = true
		if len(h.Values) < 1 || len(h.Values) > 4 {
			return ErrLimit
		}
		for _, value := range h.Values {
			if len(value) > 512 {
				return ErrLimit
			}
			if !utf8.ValidString(value) || strings.ContainsAny(value, "\r\n\x00") {
				return ErrIntegrity
			}
			total += len(value)
		}
	}
	if total > 12<<10 || !seen["Content-Type"] {
		return ErrIntegrity
	}
	return nil
}

func validTiming(t ObservedTiming, attemptDuration time.Duration) error {
	if t.DurationMillis < 0 || t.DurationMillis > 180_000 || t.DurationMillis > attemptDuration.Milliseconds()+1 || t.FirstByteMillis < 0 || t.FirstByteMillis > t.DurationMillis || len(t.Events) > 16 || (t.FirstTokenMillis != nil && (*t.FirstTokenMillis < t.FirstByteMillis || *t.FirstTokenMillis > t.DurationMillis)) {
		return ErrIntegrity
	}
	for i, event := range t.Events {
		if event.Sequence < 1 || event.ArrivalMillis < t.FirstByteMillis || event.ArrivalMillis > t.DurationMillis || event.IntervalMillis < 0 || event.IntervalMillis > event.ArrivalMillis {
			return ErrIntegrity
		}
		if i > 0 {
			previous := t.Events[i-1]
			if event.Sequence <= previous.Sequence || event.ArrivalMillis < previous.ArrivalMillis || event.IntervalMillis > event.ArrivalMillis-previous.ArrivalMillis || (event.Sequence == previous.Sequence+1 && event.IntervalMillis != event.ArrivalMillis-previous.ArrivalMillis) {
				return ErrIntegrity
			}
		}
	}
	return nil
}

func bindPlan(d captureData, p domain.ExecutionPlan) error {
	// The current real Worker can only have executed this builtin pair. A
	// candidate is a separate evaluation Runtime, never a rewritten source Run.
	if p.Versions.Rule != bundle.BuiltinVersion || p.Versions.Scoring != bundle.BuiltinVersion {
		return ErrUnsupported
	}
	if len(p.Probes) != len(d.Samples) || p.Budget.TimeoutSeconds < 1 {
		return ErrIntegrity
	}
	for i, s := range d.Samples {
		if len(p.Probes[i].Samples) != 1 || s.PairID != p.Probes[i].Samples[0].PairID || d.ExecutionClosedAt.Sub(s.Attempts[0].StartedAt) > time.Duration(p.Budget.TimeoutSeconds)*time.Second {
			return ErrIntegrity
		}
	}
	return nil
}
