package capturefixture

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/analyzer"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/tests/replay"
	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

// This capability exists ONLY in this test binary. Construction and invocation
// stay next to the real Worker control flow; no production import or API accepts
// a caller-declared settled flag, source, application master, or destination.
type settledExporter struct {
	store     *repository.Store
	tenant    *repository.Tenant
	signer    *localfile.ManifestSigner
	key       ed25519.PrivateKey
	forbidden []string
}

func (settledExporter) String() string               { return "[REDACTED development capture exporter]" }
func (e settledExporter) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, e.String()) }
func (e settledExporter) LogValue() slog.Value       { return slog.StringValue(e.String()) }
func (settledExporter) MarshalJSON() ([]byte, error) { return nil, errCapture }

// write does not export anything until actual publication AND final settlement
// have been read back, audit verified, and all decoded payloads scanned. The four
// files are individually private/atomic/no-replace; this is NOT a bundle-wide
// atomic transaction. Capture is committed last, after its trust inputs.
func (e settledExporter) write(ctx context.Context, dir string, draft replay.CaptureDraft) ([]byte, analyzer.Document, error) {
	encoded, original, err := sealSettled(ctx, e.tenant, draft, e.key)
	if err != nil {
		return nil, analyzer.Document{}, errCapture
	}
	retained := false
	defer func() {
		if !retained {
			clear(encoded)
		}
	}()
	if e.store.VerifyAllAudit(ctx, true) != nil {
		return nil, analyzer.Document{}, errCapture
	}
	manifestKey, err := localfile.EncodeDevelopmentManifestKey(e.signer)
	if err != nil {
		return nil, analyzer.Document{}, errCapture
	}
	defer clear(manifestKey)
	publicKey, err := localfile.EncodeDevelopmentCapturePublicKey(draft.KeyID, e.key.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, analyzer.Document{}, errCapture
	}
	installed, err := bundle.Builtin()
	if err != nil {
		return nil, analyzer.Document{}, errCapture
	}
	rule := installed.RuleBytes()
	if !safeExportDocuments(encoded, manifestKey, publicKey, rule, e.forbidden) || ctx.Err() != nil {
		return nil, analyzer.Document{}, errCapture
	}
	for _, item := range []struct {
		name  string
		bytes []byte
		limit int
	}{
		{"capture-public-key.json", publicKey, localfile.MaxTrustBytes},
		{"manifest-key.json", manifestKey, localfile.MaxTrustBytes},
		{"rule.json", rule, 1 << 20},
		{"capture.json", encoded, replay.MaxCaptureBytes},
	} {
		if localfile.WriteNew(ctx, filepath.Join(dir, item.name), item.bytes, item.limit) != nil {
			return nil, analyzer.Document{}, errCapture
		}
	}
	retained = true
	return encoded, original, nil
}

// Key-shaped canaries cover raw and common hex/base64 representations. These
// finite tests do not claim general DLP or detection of arbitrary encodings.
func secretCanaries(secret []byte) []string {
	return []string{string(secret), hex.EncodeToString(secret), base64.StdEncoding.EncodeToString(secret), base64.RawStdEncoding.EncodeToString(secret), base64.URLEncoding.EncodeToString(secret), base64.RawURLEncoding.EncodeToString(secret)}
}

func safeExportDocuments(encoded, manifestKey, publicKey, rule []byte, forbidden []string) bool {
	if len(forbidden) == 0 {
		return false
	}
	var envelope struct {
		Capture replay.CaptureDraft `json:"capture"`
	}
	var keyDocument struct {
		Key []byte `json:"key"`
	}
	defer func() { clear(keyDocument.Key) }()
	if json.Unmarshal(encoded, &envelope) != nil || json.Unmarshal(manifestKey, &keyDocument) != nil || len(keyDocument.Key) != 32 {
		return false
	}
	// The synthetic Manifest key is intentionally present ONLY in its explicit
	// private key file, never in captured Manifest/request/response/header bytes.
	captureForbidden := append(append([]string{}, forbidden...), secretCanaries(keyDocument.Key)...)
	if captureContainsSecret(envelope.Capture, captureForbidden...) {
		return false
	}
	for _, canary := range captureForbidden {
		for _, data := range [][]byte{encoded, publicKey, rule} {
			if bytes.Contains(data, []byte(canary)) {
				return false
			}
		}
	}
	for _, canary := range forbidden {
		if canary == "" {
			return false
		}
		for _, data := range [][]byte{encoded, manifestKey, publicKey, rule} {
			if bytes.Contains(data, []byte(canary)) {
				return false
			}
		}
	}
	return true
}

func capturePrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if protectCaptureDirectory(dir) != nil {
		t.Fatal("private capture directory unavailable")
	}
	return dir
}

func assertNoExport(t *testing.T, dir string) {
	t.Helper()
	items, err := os.ReadDir(dir)
	if err != nil || len(items) != 0 {
		t.Fatal("rejected capture left exported files")
	}
}

func assertRejectedExports(t *testing.T, ctx context.Context, dir string, exporter settledExporter, draft replay.CaptureDraft) {
	t.Helper()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, err := exporter.write(canceled, dir, draft); err == nil {
		t.Fatal("canceled export accepted")
	}
	assertNoExport(t, dir)
	// A canary in real decoded body bytes must block export even when the outer
	// envelope base64 conceals it. Source and publication are otherwise genuine.
	blocked := exporter
	blocked.forbidden = append(append([]string{}, exporter.forbidden...), string(draft.Samples[0].Attempts[0].Response.Body))
	if _, _, err := blocked.write(ctx, dir, draft); err == nil {
		t.Fatal("decoded canary exported")
	}
	assertNoExport(t, dir)
}

func assertActualCLIExport(t *testing.T, dir string, expectedPrediction, expectedAnalysis []byte) {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("Go toolchain unavailable for actual CLI build")
	}
	binDir := capturePrivateDir(t)
	binary := filepath.Join(binDir, "replay")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	buildCtx, cancelBuild := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancelBuild()
	// #nosec G204 -- fixed Go toolchain with fixed package and private test output;
	// no shell or capture-controlled build arguments.
	build := exec.CommandContext(buildCtx, goBinary, "build", "-buildvcs=false", "-o", binary, "../cmd/replay")
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOPROXY=off", "GOSUMDB=off")
	if err := build.Run(); err != nil {
		t.Fatal("actual offline CLI build failed")
	}
	output := filepath.Join(dir, "prediction.json")
	args := []string{"--capture", filepath.Join(dir, "capture.json"), "--rule", filepath.Join(dir, "rule.json"), "--rule-sha256", bundle.BuiltinHash, "--capture-public-key-file", filepath.Join(dir, "capture-public-key.json"), "--manifest-key-file", filepath.Join(dir, "manifest-key.json"), "--output", output, "--timeout", "30s"}
	cliCtx, cancelCLI := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancelCLI()
	// #nosec G204 -- freshly test-built executable and fixed argument vector.
	command := exec.CommandContext(cliCtx, binary, args...)
	command.Env = captureCLIEnvironment()
	var logs bytes.Buffer
	command.Stdout, command.Stderr = &logs, &logs
	if err := command.Run(); err != nil || logs.String() != "MI_REPLAY_OK_DEVELOPMENT_ONLY\n" {
		// Never print process output, file paths, capture content or trust keys.
		t.Fatal("actual exported capture CLI failed")
	}
	actual, err := localfile.Read(t.Context(), output, replay.MaxPredictionBytes)
	if err != nil || !bytes.Equal(actual, expectedPrediction) {
		t.Fatal("actual CLI prediction differs from settled capture replay")
	}
	var prediction replay.Prediction
	if json.Unmarshal(actual, &prediction) != nil {
		t.Fatal("actual CLI prediction invalid")
	}
	analysis, err := json.Marshal(prediction.Analysis)
	if err != nil || !bytes.Equal(analysis, expectedAnalysis) {
		t.Fatal("actual CLI differs from immutable database publication")
	}
	if !prediction.Analysis.Scores.Development || prediction.Analysis.Scores.Calibrated {
		t.Fatal("actual CLI obtained a release qualification")
	}
	// A second actual process must not overwrite or truncate its existing output.
	// #nosec G204 -- same test-built executable; paths are controller-owned.
	second := exec.CommandContext(cliCtx, binary, args...)
	second.Env = captureCLIEnvironment()
	logs.Reset()
	second.Stdout, second.Stderr = &logs, &logs
	if second.Run() == nil || logs.String() != localfile.ErrExists.Error()+"\n" {
		t.Fatal("actual CLI did not reject the existing prediction with its exact closed error")
	}
	preserved, err := localfile.Read(t.Context(), output, replay.MaxPredictionBytes)
	if err != nil || !bytes.Equal(preserved, actual) {
		t.Fatal("existing prediction changed")
	}
	assertActualCLIWrongSigner(t, cliCtx, binary, dir, args)
}

// Do not propagate database credentials, application configuration, GitHub
// credentials or caller Go settings into the standalone detector process.
func captureCLIEnvironment() []string {
	env := []string{"LANG=C", "LC_ALL=C"}
	if runtime.GOOS == "windows" {
		for _, name := range []string{"SystemRoot", "WINDIR"} {
			if value := os.Getenv(name); value != "" {
				env = append(env, name+"="+value)
			}
		}
	}
	return env
}

func assertActualCLIWrongSigner(t *testing.T, ctx context.Context, binary, dir string, args []string) {
	t.Helper()
	other, err := localfile.NewManifestSigner()
	if err != nil {
		t.Fatal("wrong-signer test unavailable")
	}
	defer other.Destroy()
	data, err := localfile.EncodeDevelopmentManifestKey(other)
	if err != nil {
		t.Fatal("wrong-signer document unavailable")
	}
	defer clear(data)
	path := filepath.Join(dir, "wrong-manifest-key.json")
	if localfile.WriteNew(ctx, path, data, localfile.MaxTrustBytes) != nil {
		t.Fatal("wrong-signer input unavailable")
	}
	output := filepath.Join(dir, "wrong-signer-prediction.json")
	changed := append([]string{}, args...)
	for i := 0; i < len(changed)-1; i += 2 {
		switch changed[i] {
		case "--manifest-key-file":
			changed[i+1] = path
		case "--output":
			changed[i+1] = output
		}
	}
	// #nosec G204 -- same test-built executable; no shell or input-derived paths.
	command := exec.CommandContext(ctx, binary, changed...)
	command.Env = captureCLIEnvironment()
	var logs bytes.Buffer
	command.Stdout, command.Stderr = &logs, &logs
	if command.Run() == nil || logs.String() != replay.ErrIntegrity.Error()+"\n" {
		t.Fatal("actual capture accepted replacement Manifest key or unsafe diagnostics")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("replacement Manifest key created a prediction")
	}
}
