package capturefixture

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/tests/replay"
)

// This scan knows only this controller's synthetic credentials, not a general
// promise to identify arbitrary unknown secrets or arbitrary encoding layers.
func captureContainsSecret(draft replay.CaptureDraft, secrets ...string) bool {
	values := []string{string(draft.Manifest), draft.CaseID, draft.KeyID}
	for _, sample := range draft.Samples {
		values = append(values, sample.PairID)
		for _, attempt := range sample.Attempts {
			values = append(values, string(attempt.WirePayload), string(attempt.Response.Body))
			for _, header := range attempt.Response.Headers {
				values = append(values, header.Name)
				values = append(values, header.Values...)
			}
		}
	}
	for _, secret := range secrets {
		if secret == "" {
			return true
		}
		for _, value := range values {
			if strings.Contains(value, secret) {
				return true
			}
		}
	}
	return false
}

func TestCaptureSecretScanIncludesDecodedByteFields(t *testing.T) {
	const canary = "synthetic-private-capture-canary"
	for _, field := range []string{"manifest", "wire_payload", "body"} {
		t.Run(field, func(t *testing.T) {
			// encoding/json writes []byte as base64; an outer string scan misses
			// the secret, while the decoded typed scan must reject every field.
			payload := map[string]any{"samples": []any{map[string]any{"attempts": []any{map[string]any{"response": map[string]any{}}}}}}
			attempt := payload["samples"].([]any)[0].(map[string]any)["attempts"].([]any)[0].(map[string]any)
			switch field {
			case "manifest":
				payload[field] = []byte(canary)
			case "wire_payload":
				attempt[field] = []byte(canary)
			case "body":
				attempt["response"].(map[string]any)[field] = []byte(canary)
			}
			encoded, err := json.Marshal(payload)
			if err != nil || bytes.Contains(encoded, []byte(canary)) {
				t.Fatal("fixture failed to encode sensitive byte field")
			}
			var draft replay.CaptureDraft
			if json.Unmarshal(encoded, &draft) != nil || !captureContainsSecret(draft, canary) {
				t.Fatal("decoded capture secret escaped the controller scan")
			}
		})
	}
	clean := replay.CaptureDraft{Manifest: []byte("synthetic-public-content")}
	if captureContainsSecret(clean, canary) || !captureContainsSecret(clean, "") {
		t.Fatal("controller secret scan baseline or missing-key guard failed")
	}
	clean.Samples = []replay.SampleCapture{{Attempts: []replay.AttemptCapture{{Response: replay.ResponseCapture{Headers: []replay.Header{{Name: "X-Request-Id", Values: []string{canary}}}}}}}}
	if !captureContainsSecret(clean, canary) {
		t.Fatal("capture response header was not scanned")
	}
}
