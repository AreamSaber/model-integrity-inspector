package replay

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestAllSensitiveContainersRejectDirectSerializationAndDiagnostics(t *testing.T) {
	f := newFixture(t, "gpt-4o", false)
	s := f.draft.Samples[0]
	s.Attempts[0].WirePayload = []byte("synthetic-wire-secret-canary")
	s.Attempts[0].Response.Body = []byte("synthetic-body-secret-canary")
	s.Attempts[0].Response.Headers[0].Values = []string{"synthetic-header-secret-canary"}
	config := Config{CaptureKeyID: "dev-secret-canary", CapturePublicKey: f.engine.publicKey, Verifier: f.generator, Runtime: f.engine.runtime}
	values := []any{f.draft, &f.draft, s, &s, s.Attempts[0], &s.Attempts[0], s.Attempts[0].Response, &s.Attempts[0].Response, s.Attempts[0].Response.Headers[0], &s.Attempts[0].Response.Headers[0], config, &config, f.engine, *f.engine, &verifiedCapture{data: draftData(f.draft)}, verifiedCapture{data: draftData(f.draft)}}
	for i, value := range values {
		t.Run(fmt.Sprintf("container-%d", i), func(t *testing.T) {
			for _, pattern := range []string{"%v", "%+v", "%#v", "%s"} {
				message := fmt.Sprintf(pattern, value)
				if strings.Contains(message, "canary") || !strings.Contains(message, "protected") {
					t.Fatal("direct diagnostic exposed sensitive container")
				}
			}
			if _, err := json.Marshal(value); !errors.Is(err, ErrSensitive) {
				t.Fatal("direct JSON serialization accepted")
			}
			var text, jsonLog bytes.Buffer
			for _, handler := range []slog.Handler{slog.NewTextHandler(&text, nil), slog.NewJSONHandler(&jsonLog, nil)} {
				logger := slog.New(handler)
				logger.Info("test", "direct", value)
				logger.LogAttrs(t.Context(), slog.LevelInfo, "test", slog.Any("nested", value))
			}
			for _, log := range []string{text.String(), jsonLog.String()} {
				if strings.Contains(log, "canary") || !strings.Contains(log, "protected") {
					t.Fatal("direct/Any slog exposed sensitive container")
				}
			}
		})
	}
}
