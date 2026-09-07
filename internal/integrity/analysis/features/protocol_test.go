package features

import (
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func TestProtocolObservationsDoNotConfuseUnobservedMissingAndNormal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*domain.NormalizedResponse)
		want   ProtocolObservations
	}{
		{"normal-length", func(r *domain.NormalizedResponse) { r.FinishReason = "length" }, ProtocolObservations{"normal", "normal", "normal", "normal", "normal"}},
		{"never-observed", func(r *domain.NormalizedResponse) { *r = domain.NormalizedResponse{} }, ProtocolObservations{"unobserved", "unobserved", "unobserved", "unobserved", "unobserved"}},
		{"auth-failure", func(r *domain.NormalizedResponse) { r.HTTPStatus = 401; r.ParseStatus = "invalid" }, ProtocolObservations{"unobserved", "anomalous", "unobserved", "unobserved", "unobserved"}},
		{"wrong-content-type", func(r *domain.NormalizedResponse) { r.ContentType = "text/html" }, ProtocolObservations{"unobserved", "anomalous", "unobserved", "unobserved", "unobserved"}},
		{"malformed", func(r *domain.NormalizedResponse) { r.ParseStatus = "invalid" }, ProtocolObservations{"unobserved", "normal", "unobserved", "unobserved", "unobserved"}},
		{"missing-usage", func(r *domain.NormalizedResponse) { r.TotalTokens = nil }, ProtocolObservations{"missing", "normal", "normal", "normal", "normal"}},
		{"invalid-total", func(r *domain.NormalizedResponse) { n := int64(4); r.TotalTokens = &n }, ProtocolObservations{"invalid", "normal", "normal", "normal", "normal"}},
		{"negative-usage", func(r *domain.NormalizedResponse) { n := int64(-1); r.CompletionTokens = &n }, ProtocolObservations{"invalid", "normal", "normal", "normal", "normal"}},
		{"model-missing", func(r *domain.NormalizedResponse) { r.ModelReported = "" }, ProtocolObservations{"normal", "normal", "missing", "normal", "normal"}},
		{"model-differs", func(r *domain.NormalizedResponse) { r.ModelReported = "untrusted-model-echo" }, ProtocolObservations{"normal", "normal", "anomalous", "normal", "normal"}},
		{"finish-missing", func(r *domain.NormalizedResponse) { r.FinishReason = "" }, ProtocolObservations{"normal", "normal", "normal", "missing", "normal"}},
		{"finish-unknown", func(r *domain.NormalizedResponse) { r.FinishReason = "untrusted-finish" }, ProtocolObservations{"normal", "normal", "normal", "invalid", "normal"}},
		{"inconsistent-metadata", func(r *domain.NormalizedResponse) {
			r.ParseWarnings = []string{"USAGE_CHANGED_WITHIN_STREAM", "MODEL_CHANGED_WITHIN_STREAM", "FINISH_REASON_CONFLICT"}
		}, ProtocolObservations{"invalid", "normal", "anomalous", "invalid", "normal"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			one, two := int64(1), int64(2)
			r := domain.NormalizedResponse{HTTPStatus: 200, ContentType: "application/json", ParseStatus: "valid", ChoiceCount: 1, PromptTokens: &one, CompletionTokens: &one, TotalTokens: &two, ModelReported: "model", FinishReason: "stop", EndCause: "complete"}
			tc.mutate(&r)
			if got := protocolObservations(r, false, "model"); *got != tc.want {
				t.Fatalf("observations=%+v want=%+v", *got, tc.want)
			}
		})
	}
	r := domain.NormalizedResponse{HTTPStatus: 200, ContentType: "text/event-stream", ParseStatus: "partial", ChoiceCount: 1, FinishReason: "stop", EndCause: "eof"}
	if got := protocolObservations(r, true, "model"); got.Termination != "anomalous" || got.Usage != "missing" {
		t.Fatal("partial stream marked complete")
	}
}
