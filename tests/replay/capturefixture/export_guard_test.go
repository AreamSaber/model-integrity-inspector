package capturefixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"unicode/utf8"

	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

func TestExportGuardDecodedKeysAndDocuments(t *testing.T) {
	signer, err := localfile.NewManifestSigner()
	if err != nil {
		t.Fatal("test signer unavailable")
	}
	defer signer.Destroy()
	key, err := localfile.EncodeDevelopmentManifestKey(signer)
	if err != nil {
		t.Fatal("test key export unavailable")
	}
	defer clear(key)
	var decodedKey struct {
		Key []byte `json:"key"`
	}
	if json.Unmarshal(key, &decodedKey) != nil {
		t.Fatal("test key decode unavailable")
	}
	defer clear(decodedKey.Key)
	const forbidden = "synthetic-application-master-canary"
	clean := []byte(`{"capture":{"manifest":"cHVibGljLW1hbmlmZXN0"}}`)
	if !safeExportDocuments(clean, key, []byte("public"), []byte("rule"), []string{forbidden}) {
		t.Fatal("independent synthetic key was not allowed in its dedicated private file")
	}
	for _, field := range []string{"manifest", "wire_payload", "body", "header"} {
		for _, canary := range append([]string{forbidden}, secretCanaries(decodedKey.Key)...) {
			// Headers are JSON strings, not byte arrays. encoding/json replaces
			// invalid UTF-8; raw random bytes cannot round-trip in that field.
			// All ASCII hex/base64 key representations still exercise headers.
			if field == "header" && !utf8.ValidString(canary) {
				continue
			}
			payload := map[string]any{"manifest": []byte("public-manifest"), "samples": []any{map[string]any{"attempts": []any{map[string]any{"response": map[string]any{}}}}}}
			attempt := payload["samples"].([]any)[0].(map[string]any)["attempts"].([]any)[0].(map[string]any)
			switch field {
			case "manifest":
				payload[field] = []byte(canary)
			case "wire_payload":
				attempt[field] = []byte(canary)
			case "body":
				attempt["response"].(map[string]any)[field] = []byte(canary)
			case "header":
				attempt["response"].(map[string]any)["headers"] = []any{map[string]any{"name": "X-Request-Id", "values": []string{canary}}}
			}
			encoded, err := json.Marshal(map[string]any{"capture": payload})
			if err != nil || safeExportDocuments(encoded, key, []byte("public"), []byte("rule"), []string{forbidden}) {
				t.Fatal("decoded capture allowed synthetic key or application secret")
			}
		}
	}
	for _, missing := range [][]string{nil, {""}} {
		if safeExportDocuments(clean, key, []byte("public"), []byte("rule"), missing) {
			t.Fatal("missing canary accepted")
		}
	}
	if safeExportDocuments(clean, []byte(`{}`), []byte("public"), []byte("rule"), []string{forbidden}) || safeExportDocuments([]byte("broken"), key, []byte("public"), []byte("rule"), []string{forbidden}) || safeExportDocuments(clean, key, []byte(forbidden), []byte("rule"), []string{forbidden}) || safeExportDocuments(clean, key, []byte("public"), []byte(forbidden), []string{forbidden}) {
		t.Fatal("invalid or secret-bearing export document accepted")
	}
	if safeExportDocuments(clean, key, decodedKey.Key, []byte("rule"), []string{forbidden}) || safeExportDocuments(clean, key, []byte("public"), decodedKey.Key, []string{forbidden}) {
		t.Fatal("independent Manifest key escaped its dedicated file")
	}
}

func TestExporterDiagnosticsAndProcessEnvironment(t *testing.T) {
	const canary = "synthetic-private-exporter-canary"
	exporter := settledExporter{forbidden: []string{canary}}
	for _, text := range []string{fmt.Sprintf("%+v", exporter), fmt.Sprintf("%#v", exporter), fmt.Sprintf("%v", &exporter)} {
		if strings.Contains(text, canary) || !strings.Contains(text, "REDACTED") {
			t.Fatal("exporter formatting leaked")
		}
	}
	var output bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&output, nil))
	logger.Info("export-test", "direct", exporter, slog.Any("any", exporter))
	if strings.Contains(output.String(), canary) || !strings.Contains(output.String(), "REDACTED") {
		t.Fatal("exporter logging leaked")
	}
	if raw, err := json.Marshal(exporter); err == nil || len(raw) != 0 {
		t.Fatal("exporter directly serialized")
	}
	t.Setenv("MII_TEST_POSTGRES_DSN", canary)
	t.Setenv("GITHUB_TOKEN", canary)
	if strings.Contains(strings.Join(captureCLIEnvironment(), "\n"), canary) {
		t.Fatal("standalone CLI inherited a control credential")
	}
}
