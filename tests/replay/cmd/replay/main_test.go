//go:build windows || linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/tests/replay"
	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

func cliPrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := protectCLITestDirectory(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeFixture(t *testing.T, dir string, f cliFixture) []string {
	t.Helper()
	for name, data := range map[string][]byte{"capture.json": f.capture, "rule.json": f.rule, "public.json": f.public, "manifest-key.json": f.manifestKey} {
		if err := localfile.WriteNew(t.Context(), filepath.Join(dir, name), data, replay.MaxCaptureBytes); err != nil {
			t.Fatal(err)
		}
	}
	return []string{"--capture", filepath.Join(dir, "capture.json"), "--rule", filepath.Join(dir, "rule.json"), "--rule-sha256", bundle.BuiltinHash, "--capture-public-key-file", filepath.Join(dir, "public.json"), "--manifest-key-file", filepath.Join(dir, "manifest-key.json"), "--output", filepath.Join(dir, "prediction.json"), "--timeout", "30s"}
}

func withArg(args []string, name, value string) []string {
	out := append([]string(nil), args...)
	for i := 0; i < len(out)-1; i += 2 {
		if out[i] == name {
			out[i+1] = value
			return out
		}
	}
	return append(out, name, value)
}

func builtCLI(t *testing.T) string {
	t.Helper()
	name := "replay"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("built CLI tests require the frozen Go toolchain on PATH")
	}
	path := filepath.Join(cliPrivateDir(t), name)
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	// #nosec G204 -- fixed frozen Go executable and test-owned absolute output;
	// no user input is interpreted as a command or build argument.
	cmd := exec.CommandContext(ctx, goPath, "build", "-buildvcs=false", "-o", path, ".")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CLI build failed: %v\n%s", err, output)
	}
	return path
}

func invokeCLI(t *testing.T, binary string, args []string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	// #nosec G204 -- executable freshly built above; argument-vector invocation,
	// never a shell and never a capture-controlled executable or argument.
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(output)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("CLI process failed to finish: %v", err)
	}
	return exit.ExitCode(), string(output)
}

func TestBuiltCLI(t *testing.T) {
	binary := builtCLI(t)
	f := syntheticFixture(t)
	dir := cliPrivateDir(t)
	args := writeFixture(t, dir, f)
	t.Run("successful-S1-and-repeatable", func(t *testing.T) {
		code, message := invokeCLI(t, binary, args)
		if code != 0 || message != "MI_REPLAY_OK_DEVELOPMENT_ONLY\n" {
			t.Fatalf("success code=%d message=%q", code, message)
		}
		data, err := localfile.Read(t.Context(), filepath.Join(dir, "prediction.json"), replay.MaxPredictionBytes)
		if err != nil {
			t.Fatal(err)
		}
		var prediction replay.Prediction
		if json.Unmarshal(data, &prediction) != nil || prediction.Provenance != "development_controller_statement" || !prediction.Analysis.Scores.Development || prediction.Analysis.Scores.Calibrated {
			t.Fatal("invalid development prediction")
		}
		for _, nonce := range f.nonces {
			if bytes.Contains(data, []byte(nonce)) {
				t.Fatal("nonce leaked into S1")
			}
		}
		second := withArg(args, "--output", filepath.Join(dir, "repeat.json"))
		if code, message := invokeCLI(t, binary, second); code != 0 {
			t.Fatalf("repeat: %d %q", code, message)
		}
		again, err := localfile.Read(t.Context(), filepath.Join(dir, "repeat.json"), replay.MaxPredictionBytes)
		if err != nil || !bytes.Equal(data, again) {
			t.Fatalf("non-deterministic output: %v", err)
		}
	})
	t.Run("existing-output-unchanged", func(t *testing.T) {
		path := filepath.Join(dir, "existing.json")
		if err := localfile.WriteNew(t.Context(), path, []byte("sentinel"), 100); err != nil {
			t.Fatal(err)
		}
		code, message := invokeCLI(t, binary, withArg(args, "--output", path))
		if code == 0 || message != localfile.ErrExists.Error()+"\n" {
			t.Fatalf("exists: %d %q", code, message)
		}
		data, err := localfile.Read(t.Context(), path, 100)
		if err != nil || string(data) != "sentinel" {
			t.Fatal("existing output changed")
		}
	})
	t.Run("supported-candidate-is-not-builtin-or-release", func(t *testing.T) {
		artifact, err := bundle.DevelopmentArtifact("1.0.0-dev.2")
		if err != nil {
			t.Fatal(err)
		}
		artifact.Manifest.Scoring.NoBaselineFactor = 0.4
		raw, hash, err := artifact.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "candidate.json")
		if err := localfile.WriteNew(t.Context(), path, raw, bundle.MaxArtifactBytes); err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(dir, "candidate-prediction.json")
		changed := withArg(withArg(withArg(args, "--rule", path), "--rule-sha256", hash), "--output", output)
		if code, message := invokeCLI(t, binary, changed); code != 0 {
			t.Fatalf("candidate: %d %q", code, message)
		}
		data, err := localfile.Read(t.Context(), output, replay.MaxPredictionBytes)
		if err != nil {
			t.Fatal(err)
		}
		var p replay.Prediction
		if json.Unmarshal(data, &p) != nil || p.Runtime.SHA256 != hash || p.Runtime.Version != "1.0.0-dev.2" || !p.Analysis.Scores.Development || p.Analysis.Scores.Calibrated {
			t.Fatal("candidate identity or development boundary lost")
		}
	})
	cases := []struct {
		name, flag string
		data       []byte
		value      string
	}{
		{"corrupt-capture", "--capture", append(bytes.Clone(f.capture), 'x'), ""},
		{"duplicate-field", "--capture", bytes.Replace(f.capture, []byte(`"capture":`), []byte(`"capture":{},"capture":`), 1), ""},
		{"raw-master-rejected", "--manifest-key-file", bytes.Repeat([]byte("x"), 32), ""},
		{"unknown-public-field", "--capture-public-key-file", bytes.Replace(f.public, []byte(`"purpose":`), []byte(`"trusted":true,"purpose":`), 1), ""},
		{"oversized-rule", "--rule", bytes.Repeat([]byte("x"), bundle.MaxArtifactBytes+1), ""},
		{"oversized-trust", "--manifest-key-file", bytes.Repeat([]byte("x"), localfile.MaxTrustBytes+1), ""},
		{"wrong-rule-hash", "--rule-sha256", nil, strings.Repeat("0", 64)},
		{"input-directory", "--capture", nil, dir},
		{"relative-path", "--capture", nil, "capture.json"},
		{"url-path", "--capture", nil, "https://never-dial.invalid/sensitive"},
		{"too-short-timeout", "--timeout", nil, "1ms"},
		{"too-long-timeout", "--timeout", nil, "121s"},
	}
	other := syntheticFixture(t)
	cases = append(cases, struct {
		name, flag string
		data       []byte
		value      string
	}{"changed-capture-key", "--capture-public-key-file", other.public, ""}, struct {
		name, flag string
		data       []byte
		value      string
	}{"changed-manifest-key", "--manifest-key-file", other.manifestKey, ""})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			value := tc.value
			if tc.data != nil {
				value = filepath.Join(dir, tc.name+".json")
				if err := localfile.WriteNew(t.Context(), value, tc.data, replay.MaxCaptureBytes); err != nil {
					t.Fatal(err)
				}
			}
			output := filepath.Join(dir, tc.name+"-output.json")
			changed := withArg(withArg(args, tc.flag, value), "--output", output)
			code, message := invokeCLI(t, binary, changed)
			if code == 0 || !strings.HasPrefix(message, "MI_REPLAY_") || strings.Count(message, "\n") != 1 || strings.Contains(message, dir) || strings.Contains(message, "sensitive") {
				t.Fatalf("unsafe failure: %d %q", code, message)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("failure created output")
			}
		})
	}
	t.Run("caller-cancellation-during-process-startup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		output := filepath.Join(dir, "canceled-process.json")
		// #nosec G204 -- same test-built executable; no shell. This specifically
		// checks external caller cancellation, not graceful OS signal delivery.
		cmd := exec.CommandContext(ctx, binary, withArg(args, "--output", output)...)
		var diagnostics bytes.Buffer
		cmd.Stdout = &diagnostics
		cmd.Stderr = &diagnostics
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cancel()
		if err := cmd.Wait(); err == nil {
			t.Fatal("canceled process unexpectedly succeeded")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("startup cancellation created output")
		}
	})
}

func TestCLICanceledContextAndStrictArguments(t *testing.T) {
	f := syntheticFixture(t)
	args := writeFixture(t, cliPrivateDir(t), f)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out, errOut bytes.Buffer
	if code := run(ctx, args, &out, &errOut); code != 130 || out.Len() != 0 || errOut.String() != replay.ErrCanceled.Error()+"\n" {
		t.Fatalf("cancellation: %d %q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run(t.Context(), args, &out, &errOut); code != 0 || out.String() != "MI_REPLAY_OK_DEVELOPMENT_ONLY\n" || errOut.Len() != 0 {
		t.Fatalf("internal execution: %d %q", code, errOut.String())
	}
	for _, bad := range [][]string{nil, {"--help"}, {"--unknown", "secret-path"}, append(append([]string{}, args...), "--timeout", "1s"), append(append([]string{}, args...), "trailing-secret")} {
		out.Reset()
		errOut.Reset()
		if code := run(t.Context(), bad, &out, &errOut); code != 2 || out.Len() != 0 || errOut.String() != errArguments.Error()+"\n" {
			t.Fatal("argument errors leaked or accepted")
		}
	}
	if safeError(errors.New("sensitive-source-body")) != "MI_REPLAY_FAILED" {
		t.Fatal("unknown error leaked")
	}
}
