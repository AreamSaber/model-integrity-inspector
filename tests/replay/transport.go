package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sync/atomic"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

// recordedDoer is not a network transport. There is deliberately no client,
// proxy, dialer, resolver, default-transport fallback or request authentication.
type recordedDoer struct {
	wire     []byte
	response responseData
	calls    int
	failed   bool
}

func (d *recordedDoer) Do(r *http.Request) (*http.Response, error) {
	d.calls++
	if d.calls != 1 || r == nil || r.Method != http.MethodPost || r.URL.String() != "https://replay.invalid/v1/chat/completions" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" || r.Body == nil {
		d.failed = true
		return nil, ErrIntegrity
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, openaichat.MaxRequestBytes+1))
	defer clear(data)
	if err != nil || !bytes.Equal(data, d.wire) {
		d.failed = true
		return nil, ErrIntegrity
	}
	headers := make(http.Header, len(d.response.Headers))
	for _, h := range d.response.Headers {
		headers[h.Name] = slices.Clone(h.Values)
	}
	return &http.Response{StatusCode: d.response.HTTPStatus, Header: headers, Body: &lineBody{data: d.response.Body}}, nil
}

// Deliver at most one physical line per Read. This retains real parser logic
// but prevents prefetch beyond terminal [DONE] from disguising trailing data.
// RawResponseBytes/hash must still equal the entire signed entity byte object.
type lineBody struct {
	data   []byte
	offset int
	closed atomic.Bool
}

func (b *lineBody) Read(dst []byte) (int, error) {
	if b.closed.Load() || b.offset == len(b.data) {
		return 0, io.EOF
	}
	if len(dst) == 0 {
		return 0, nil
	}
	end := b.offset
	for end < len(b.data) {
		ch := b.data[end]
		end++
		if ch == '\n' {
			break
		}
		if ch == '\r' {
			if end < len(b.data) && b.data[end] == '\n' {
				end++
			}
			break
		}
	}
	n := copy(dst, b.data[b.offset:end])
	b.offset += n
	return n, nil
}
func (b *lineBody) Close() error { b.closed.Store(true); return nil }

// ObserveResponse is an explicit DEVELOPMENT-controller projection. Call it
// only inside the real exact-AAD evidence callback. A hash of caller JSON does
// not independently authenticate an upstream or a settled database record.
func ObserveResponse(r domain.NormalizedResponse) (string, ObservedTiming, error) {
	timing := ObservedTiming{DurationMillis: r.DurationMs, FirstByteMillis: r.FirstByteMs, Events: []EventTiming{}}
	if r.FirstTokenMs != nil {
		value := *r.FirstTokenMs
		timing.FirstTokenMillis = &value
	}
	for _, event := range r.Events {
		timing.Events = append(timing.Events, EventTiming{event.Sequence, event.ArrivalMs, event.IntervalMs})
	}
	if err := validTiming(timing, 180*time.Second); err != nil {
		return "", ObservedTiming{}, err
	}
	hash, err := protocolHash(r)
	return hash, timing, err
}

func protocolHash(r domain.NormalizedResponse) (string, error) {
	// The output contains only a digest, never Content. Copy before removing
	// capture timing and the Worker's locally appended tokenizer warning.
	r.DurationMs, r.FirstByteMs, r.FirstTokenMs = 0, 0, nil
	r.Events = slices.Clone(r.Events)
	for i := range r.Events {
		r.Events[i].ArrivalMs, r.Events[i].IntervalMs = 0, 0
	}
	r.ParseWarnings = slices.DeleteFunc(slices.Clone(r.ParseWarnings), func(s string) bool { return s == "LOCAL_TOKENIZER_APPROXIMATE" })
	if len(r.ParseWarnings) == 0 {
		r.ParseWarnings = nil
	}
	encoded, err := json.Marshal(r)
	defer clear(encoded)
	if err != nil || len(encoded) > MaxBodyBytes {
		return "", ErrLimit
	}
	return digest(encoded), nil
}

func (e *Engine) parse(ctx context.Context, sample domain.SamplePlan, parameter string, capture attemptData) (domain.NormalizedResponse, domain.RequestSnapshot, error) {
	doer := &recordedDoer{wire: capture.WirePayload, response: capture.Response}
	// Temporary parser clocks are deterministic. The signed capture-observed
	// measurements are attached ONLY after the entire protocol projection agrees.
	clock := func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	a, err := openaichat.New(openaichat.Config{Endpoint: "https://replay.invalid/v1", MaxOutputParameter: parameter, Doer: doer, Now: clock, MaxResponseBytes: MaxBodyBytes, MaxEventBytes: MaxBodyBytes, RequestTimeout: 30 * time.Second, FirstEventTimeout: 30 * time.Second, StreamIdleTimeout: 30 * time.Second})
	if err != nil {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrConfiguration
	}
	r, snapshot, err := a.Call(ctx, sample.Request, nil, nil)
	if ctx.Err() != nil {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrCanceled
	}
	if doer.failed || snapshot.RequestHash != capture.RequestHash || !bytes.Equal(snapshot.Payload, capture.WirePayload) {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrIntegrity
	}
	if err != nil || doer.calls != 1 || r.HTTPStatus != 200 || r.Refusal || (r.ParseStatus != "valid" && r.ParseStatus != "partial") {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrUnsupported
	}
	end := "eof"
	if r.StreamTerminated {
		end = "done"
	}
	if end != capture.Response.End || r.ResponseHash != capture.Response.BodyHash || r.RawResponseBytes != int64(len(capture.Response.Body)) {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrIntegrity
	}
	hash, err := protocolHash(r)
	if err != nil {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, err
	}
	if hash != capture.Response.ProtocolHash {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrIntegrity
	}
	// Recompute the existing Worker's local-only warning, never read an input
	// quality/count. Builder.Build independently counts the parsed Content again.
	local, err := e.tokens.CountOutput(r.Content, tokenizer.Selection{ReportedModel: r.ModelReported, RequestedModel: sample.Request.Model})
	if err != nil {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrLimit
	}
	if local.Quality == tokenizer.Heuristic || local.Quality == tokenizer.Unavailable {
		r.ParseWarnings = append(r.ParseWarnings, "LOCAL_TOKENIZER_APPROXIMATE")
	}
	validity := "VALID"
	if r.ParseStatus == "partial" || len(r.ParseWarnings) > 0 {
		validity = "VALID_WITH_WARNING"
	}
	if validity != capture.Validity {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrIntegrity
	}
	t := capture.Response.Timing
	if len(t.Events) != len(r.Events) {
		return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrIntegrity
	}
	for i, event := range t.Events {
		if event.Sequence != r.Events[i].Sequence {
			return domain.NormalizedResponse{}, domain.RequestSnapshot{}, ErrIntegrity
		}
		r.Events[i].ArrivalMs, r.Events[i].IntervalMs = event.ArrivalMillis, event.IntervalMillis
	}
	r.DurationMs, r.FirstByteMs, r.FirstTokenMs = t.DurationMillis, t.FirstByteMillis, t.FirstTokenMillis
	return r, snapshot, nil
}
