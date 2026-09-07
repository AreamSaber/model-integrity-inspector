package evidencedisplay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type noNetwork struct{}

func (noNetwork) Do(*http.Request) (*http.Response, error) { return nil, ErrInvalid }

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < 'a' || r > 'f') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// quotedBytes computes encoding/json's UTF-8 string size before allocation,
// including HTML escaping and U+2028/U+2029. Call only after UTF-8 validation.
func quotedBytes(value string) int {
	n := 2
	for _, r := range value {
		switch {
		case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t' || r == '\b' || r == '\f':
			n += 2
		case r < 32 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
			n += 6
		default:
			n += utf8.RuneLen(r)
		}
	}
	return n
}

func validCount(v *int64) bool { return v == nil || *v >= 0 && *v <= 1<<53-1 }
func validEvents(events []domain.StreamEventSummary, duration int64) bool {
	if len(events) > MaxEvents {
		return false
	}
	previous, arrival := 0, int64(0)
	for _, event := range events {
		if event.Sequence <= previous || event.Bytes < 0 || event.Bytes > MaxTextBytes || event.ArrivalMs < arrival || event.ArrivalMs > duration || event.IntervalMs < 0 || event.IntervalMs > duration {
			return false
		}
		switch event.Type {
		case "done", "error", "malformed", "usage", "empty_delta", "role", "content_delta", "finish":
		default:
			return false
		}
		previous, arrival = event.Sequence, event.ArrivalMs
	}
	return true
}
func validView(v responseView) bool {
	if len(v.Content) > MaxTextBytes || !utf8.ValidString(v.Content) || len(v.ModelReported) > 2048 || !utf8.ValidString(v.ModelReported) || v.HTTPStatus != 0 && (v.HTTPStatus < 100 || v.HTTPStatus > 599) || v.DurationMS < 0 || v.DurationMS > 86400000 || v.FirstTokenMS != nil && (*v.FirstTokenMS < 0 || *v.FirstTokenMS > v.DurationMS) {
		return false
	}
	for _, count := range []*int64{v.PromptTokens, v.CompletionTokens, v.TotalTokens, v.ReasoningTokens} {
		if !validCount(count) {
			return false
		}
	}
	switch v.FinishReason {
	case "", "stop", "length", "content_filter", "tool_calls", "function_call", "unknown":
	default:
		return false
	}
	switch v.ParseStatus {
	case "valid", "invalid", "partial", "unobserved":
	default:
		return false
	}
	return validEvents(v.Events, v.DurationMS)
}

func validateSource(source Source) error {
	if len(source.Snapshot.Payload) == 0 || len(source.Snapshot.Payload) > MaxTextBytes || source.Snapshot.PayloadBytes != len(source.Snapshot.Payload) || !validHash(source.Snapshot.RequestHash) || digest(source.Snapshot.Payload) != source.Snapshot.RequestHash {
		return ErrInvalid
	}
	if len(source.Request.Messages) > 256 || len(source.Request.Stop) > 4 || len(source.Request.ExtraAllowedParams) > 2 {
		return ErrLimit
	}
	for name, value := range source.Request.ExtraAllowedParams {
		if name != "frequency_penalty" && name != "presence_penalty" {
			return ErrInvalid
		}
		// The adapter accepts json.Number as well as native numbers. Bound its
		// lexeme before strconv can allocate an error containing a huge input.
		if number, ok := value.(json.Number); ok && len(number) > 64 {
			return ErrLimit
		}
	}
	if len(source.Request.Model) > 128 {
		return ErrLimit
	}
	requestBound := 2048 + quotedBytes(source.Request.Model)
	for _, message := range source.Request.Messages {
		if len(message.Role) > 16 || len(message.Content) > MaxTextBytes || !utf8.ValidString(message.Content) {
			return ErrLimit
		}
		requestBound += quotedBytes(message.Content) + quotedBytes(message.Role) + 32
		if requestBound > MaxTextBytes {
			return ErrLimit
		}
	}
	for _, stop := range source.Request.Stop {
		if len(stop) > 256 || !utf8.ValidString(stop) {
			return ErrLimit
		}
		requestBound += quotedBytes(stop) + 2
	}
	if requestBound > MaxTextBytes {
		return ErrLimit
	}
	r := source.Response
	if len(r.Content) > MaxTextBytes || !utf8.ValidString(r.Content) || len(r.ModelReported) > 128 || len(r.ProviderRequestID) > 128 || len(r.ContentType) > 512 || len(r.FinishReason) > 128 || len(r.ParseStatus) > 32 || len(r.EndCause) > 128 || len(r.HeaderSummary) > 32 || len(r.ParseWarnings) > 64 || len(r.Events) > MaxEvents || r.ResponseHash != "" && !validHash(r.ResponseHash) {
		return ErrLimit
	}
	text := []string{r.ModelReported, r.ProviderRequestID, r.ContentType, r.FinishReason, r.ParseStatus, r.EndCause}
	for name, value := range r.HeaderSummary {
		if len(name) > 128 || len(value) > 512 {
			return ErrLimit
		}
		text = append(text, name, value)
	}
	for _, value := range r.ParseWarnings {
		if len(value) > 128 {
			return ErrLimit
		}
		text = append(text, value)
	}
	size := quotedBytes(r.Content) + 16384 + len(r.Events)*256
	for _, value := range text {
		if !utf8.ValidString(value) {
			return ErrInvalid
		}
		size += quotedBytes(value)
	}
	if size > MaxPayloadBytes {
		return ErrLimit
	}
	return nil
}

func requestForDisplay(ctx context.Context, source Source, replacer *strings.Replacer) (string, error) {
	// Reuse the public deterministic wire builder with a permanently non-network
	// Doer and fixed non-routable name; never use the historical/live endpoint.
	adapter, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", MaxOutputParameter: source.Snapshot.MaxOutputParameter, Doer: noNetwork{}})
	if err != nil {
		return "", ErrInvalid
	}
	request, snapshot, err := adapter.BuildRequest(ctx, source.Request)
	if err != nil {
		return "", ErrInvalid
	}
	defer func() { _ = request.Body.Close(); clear(snapshot.Payload) }()
	if snapshot.RequestHash != source.Snapshot.RequestHash || !bytes.Equal(snapshot.Payload, source.Snapshot.Payload) || snapshot.Model != source.Snapshot.Model || snapshot.Stream != source.Snapshot.Stream || snapshot.MaxOutputTokens != source.Snapshot.MaxOutputTokens || snapshot.MaxOutputParameter != source.Snapshot.MaxOutputParameter {
		return "", ErrInvalid
	}
	// The original canonical request was verified above. Preserve numeric wire
	// values (including full int64 seeds) as RawMessage; only text is rewritten.
	var fields map[string]json.RawMessage
	if json.Unmarshal(snapshot.Payload, &fields) != nil {
		return "", ErrInvalid
	}
	model, err := redactText(ctx, replacer, source.Request.Model)
	if err != nil {
		return "", err
	}
	fields["model"], err = json.Marshal(model)
	if err != nil {
		return "", ErrInvalid
	}
	messages := make([]domain.NormalizedMessage, len(source.Request.Messages))
	messageBound := 2
	for i, message := range source.Request.Messages {
		value, e := redactText(ctx, replacer, message.Content)
		if e != nil {
			return "", e
		}
		messages[i] = domain.NormalizedMessage{Role: message.Role, Content: value}
		messageBound += quotedBytes(message.Role) + quotedBytes(value) + 24
		if messageBound > MaxTextBytes {
			return "", ErrLimit
		}
	}
	fields["messages"], err = json.Marshal(messages)
	if err != nil {
		return "", ErrInvalid
	}
	if len(source.Request.Stop) > 0 {
		stops := make([]string, len(source.Request.Stop))
		for i, value := range source.Request.Stop {
			stops[i], err = redactText(ctx, replacer, value)
			if err != nil {
				return "", err
			}
		}
		fields["stop"], err = json.Marshal(stops)
		if err != nil {
			return "", ErrInvalid
		}
	}
	bound := 2
	for name, value := range fields {
		bound += quotedBytes(name) + len(value) + 2
		if bound > MaxTextBytes {
			return "", ErrLimit
		}
	}
	encoded, err := json.Marshal(fields)
	if err != nil || len(encoded) > MaxTextBytes {
		clear(encoded)
		return "", ErrLimit
	}
	defer clear(encoded)
	return string(encoded), nil
}

// Prepare must be called in the real Worker's Credentials.Use callback. It
// creates a separate copy; no source field, request hash or analysis is changed.
func Prepare(ctx context.Context, source Source, key []byte, headers map[string][]byte) (*Prepared, error) {
	ctx, cancel, err := prepareContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if err := validateSource(source); err != nil {
		return nil, err
	}
	replacer, _, err := dictionary(ctx, key, headers)
	if err != nil {
		return nil, err
	}
	requestJSON, err := requestForDisplay(ctx, source, replacer)
	if err != nil {
		return nil, err
	}
	content, err := redactText(ctx, replacer, source.Response.Content)
	if err != nil {
		return nil, err
	}
	model, err := redactText(ctx, replacer, source.Response.ModelReported)
	if err != nil {
		return nil, err
	}
	view := responseView{Content: content, ModelReported: model, HTTPStatus: source.Response.HTTPStatus, FinishReason: source.Response.FinishReason, ParseStatus: source.Response.ParseStatus, PromptTokens: source.Response.PromptTokens, CompletionTokens: source.Response.CompletionTokens, TotalTokens: source.Response.TotalTokens, ReasoningTokens: source.Response.ReasoningTokens, DurationMS: source.Response.DurationMs, FirstTokenMS: source.Response.FirstTokenMs, StreamTerminated: source.Response.StreamTerminated, Events: source.Response.Events}
	if view.ParseStatus == "" {
		view.ParseStatus = "unobserved"
	}
	switch view.FinishReason {
	case "", "stop", "length", "content_filter", "tool_calls", "function_call", "unknown":
	default:
		view.FinishReason = "unknown"
	}
	if !validView(view) {
		return nil, ErrInvalid
	}
	previous := 0
	for _, event := range view.Events {
		if event.Sequence != previous+1 {
			view.EventSummaryPartial = true
		}
		previous = event.Sequence
	}
	if source.Response.StreamChunkCount > len(view.Events) {
		view.EventSummaryPartial = true
	}
	// This is a distinct source digest, not the AES analysis-payload ContentHash
	// or raw HTTP ResponseHash. It binds the checked wire hash and normalized
	// response before any display changes under an explicit domain separator.
	original, err := json.Marshal(source.Response)
	if err != nil {
		return nil, ErrInvalid
	}
	defer clear(original)
	if len(original) > MaxPayloadBytes {
		return nil, ErrLimit
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte("mii/display-source/v1\x00" + source.Snapshot.RequestHash + "\x00"))
	_, _ = hash.Write(original)
	sourceHash := hex.EncodeToString(hash.Sum(nil))
	templateHash := digest([]byte(requestJSON))
	doc := document{Version: 1, Policy: PolicyVersion, SourceHash: sourceHash, RequestHash: source.Snapshot.RequestHash, TemplateHash: templateHash, RequestJSON: requestJSON, RequestChanged: templateHash != source.Snapshot.RequestHash, Response: view, MetadataOmitted: true}
	if quotedBytes(requestJSON)+quotedBytes(content)+quotedBytes(model)+16384+len(view.Events)*256 > MaxPayloadBytes {
		return nil, ErrLimit
	}
	encoded, err := json.Marshal(doc)
	if err != nil {
		return nil, ErrInvalid
	}
	if len(encoded) > MaxPayloadBytes {
		clear(encoded)
		return nil, ErrLimit
	}
	// Fixed schema strings and numeric fields are not rewritten. If a known
	// credential coincides with them, reject the whole display rather than skip
	// that credential or corrupt the protocol/numeric data.
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
	return &Prepared{prepared: &protectedPayload{data: encoded, sourceHash: sourceHash, requestHash: source.Snapshot.RequestHash}}, nil
}
