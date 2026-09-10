package bundle

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/tokenrisk"
)

func installedScoringFixture(t *testing.T) (*Artifacts, *InstalledScoringArtifact) {
	t.Helper()
	installed, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	a, err := installed.InstalledScoringArtifact(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return installed, a
}

func TestInstalledScoringPreservesOriginalReferenceAndReconstructsActualAnalysis(t *testing.T) {
	installed, a := installedScoringFixture(t)
	ref, data := a.Ref(), a.Bytes()
	// Independent outer field order/limits, enclosing the separately frozen
	// ORIGINAL rule bytes. No production carrier encoder supplies this oracle.
	want := append([]byte(`{"schema_version":"mii.scoring-installed.v1","implementation":"mii.analyzer.development.v1","version":"1.0.0-dev.1","reference_rule_sha256":"fda4b1aaf5290b762c4fb687a9164298e4dcc1f14f7273c870f938ea23bc8d88","reference_rule":`), installed.RuleBytes()...)
	want = append(want, []byte(`,"limits":{"ScoringSamples":512,"Hypotheses":256,"TokenSamples":512,"TokenObservations":4096,"TokenSeries":64,"FeatureResponseBytes":1048576,"FeatureBatchBytes":8388608}}`)...)
	if !bytes.Equal(want, data) || ref.Bytes != int64(len(want)) || ref.SHA256 != digest(want) || ref.ReferenceRuleSHA256 != BuiltinHash || ref.ScoringSHA256 != scoring.RulesHash() || ref.TokenRulesSHA256 != tokenrisk.RulesHash() {
		t.Fatal("installed data differs from independent limits/original rule bytes")
	}
	if ref.Bytes != 2928 || ref.SHA256 != "c1d2977d3cb0256e2b94c5ab77ba4ba95aa4364289b5389643405594036954ba" {
		t.Fatal("new installed scoring format changed its pinned identity")
	}
	var wire installedScoringWire
	if json.Unmarshal(data, &wire) != nil || !bytes.Equal(wire.ReferenceRule, installed.RuleBytes()) {
		t.Fatal("original parameters or their version bindings were rewritten")
	}
	verified, err := VerifyInstalledScoringArtifact(t.Context(), data, ref)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := verified.NewReferenceRuntime(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewResolver()
	if err != nil {
		t.Fatal(err)
	}
	original, err := resolver.Resolve(installed.RuleBytes(), BuiltinHash)
	if err != nil || restored.Ref() != original.Ref() || restored == original || restored.engine == original.engine {
		t.Fatal("reference runtime lost identity or reused a default engine", err)
	}
	batch := runtimeBatch(t, false)
	before, err := original.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	after, err := restored.Analyze(batch)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := json.Marshal(before)
	two, _ := json.Marshal(after)
	if !bytes.Equal(one, two) || after.Scores.Calibrated || !after.Scores.Development || after.Scores.EvidenceGrade == "A" || after.Scores.EvidenceGrade == "B" {
		t.Fatal("restored archived reference altered analysis or granted trust")
	}
	t.Logf("carrier_bytes=%d carrier_sha256=%s", ref.Bytes, ref.SHA256)
}

func TestInstalledScoringDoesNotFlattenTenantRuleVersions(t *testing.T) {
	_, installed := installedScoringFixture(t)
	batch := runtimeBatch(t, false)
	var hashes [2]string
	for i, factor := range []float64{.4, .7} {
		// Distinct tenant resolvers may retain the same version with different
		// exact parameters. Neither is represented by the global reference.
		r, err := NewResolver()
		if err != nil {
			t.Fatal(err)
		}
		a := candidate(t, "1.0.0-dev.42")
		a.Manifest.Scoring.NoBaselineFactor = factor
		data, hash := canonicalCandidate(t, a)
		selected, err := r.Resolve(data, hash)
		if err != nil {
			t.Fatal(err)
		}
		got, err := selected.Analyze(batch)
		if err != nil || got.Scores.Confidence.BaselineFactor != factor || got.Scores.RulesHash == installed.Ref().ScoringSHA256 {
			t.Fatal("tenant parameters replaced by the installed reference", err)
		}
		hashes[i] = got.Scores.RulesHash
		counterfeit := &Artifacts{rule: data}
		if carrier, err := counterfeit.InstalledScoringArtifact(t.Context()); !errors.Is(err, ErrIntegrity) || carrier != nil {
			t.Fatal("tenant candidate mislabeled as installed builtin")
		}
	}
	if hashes[0] == hashes[1] {
		t.Fatal("tenant-specific same-version parameters collapsed")
	}
}

func TestInstalledScoringOwnsResourcesAndNeverSubstitutesDefaults(t *testing.T) {
	installed, a := installedScoringFixture(t)
	data := a.Bytes()
	verified, err := VerifyInstalledScoringArtifact(t.Context(), data, a.Ref())
	if err != nil {
		t.Fatal(err)
	}
	data[0] ^= 1
	copy := verified.Bytes()
	copy[len(copy)-1] ^= 1
	installed.rule[0] ^= 1
	if !bytes.Equal(a.Bytes(), verified.Bytes()) {
		t.Fatal("carrier retained borrowed source/output memory")
	}
	if _, err := verified.NewReferenceRuntime(t.Context()); err != nil {
		t.Fatal("valid archived resources depended on damaged current source", err)
	}
	if out, err := installed.InstalledScoringArtifact(t.Context()); !errors.Is(err, ErrIntegrity) || out != nil {
		t.Fatal("damaged installed source silently replaced with defaults")
	}
	verified.data[0] ^= 1
	if out, err := verified.NewReferenceRuntime(t.Context()); !errors.Is(err, ErrIntegrity) || out != nil {
		t.Fatal("damaged private archive silently replaced with defaults")
	}
}

func TestInstalledScoringRejectsRehashedWireAndIdentityMutations(t *testing.T) {
	_, a := installedScoringFixture(t)
	for name, change := range map[string]func([]byte) []byte{
		"unknown": func(b []byte) []byte { return append([]byte(`{"unknown":0,`), b[1:]...) },
		"case": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"implementation":`), []byte(`"Implementation":`), 1)
		},
		"duplicate": func(b []byte) []byte { return append([]byte(`{"version":"1.0.0-dev.1",`), b[1:]...) },
		"version": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"version":"1.0.0-dev.1"`), []byte(`"version":"unknown"`), 1)
		},
		"limit": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"Hypotheses":256`), []byte(`"Hypotheses":257`), 1)
		},
		"reference": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"NoBaselineFactor":0.8`), []byte(`"NoBaselineFactor":0.4`), 1)
		},
		"reference_null": func(b []byte) []byte {
			var w installedScoringWire
			_ = json.Unmarshal(b, &w)
			w.ReferenceRule = nil
			out, _ := json.Marshal(w)
			return out
		},
		"newline":   func(b []byte) []byte { return append(b, '\n') },
		"extra":     func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"too_large": func([]byte) []byte { return bytes.Repeat([]byte{' '}, MaxInstalledScoringBytes+1) },
	} {
		t.Run(name, func(t *testing.T) {
			data := change(a.Bytes())
			if bytes.Equal(data, a.Bytes()) {
				t.Fatal("test mutation did not change bytes")
			}
			expected := a.Ref()
			expected.Bytes, expected.SHA256 = int64(len(data)), digest(data)
			if got, err := VerifyInstalledScoringArtifact(t.Context(), data, expected); !errors.Is(err, ErrIntegrity) || got != nil {
				t.Fatal("self-rehashed unsupported archive accepted", err)
			}
		})
	}
	for i := range 8 {
		r := a.Ref()
		fields := []*string{&r.SchemaVersion, &r.Implementation, &r.Version, &r.ReferenceRuleSHA256, &r.ScoringSHA256, &r.TokenRulesSHA256, &r.SHA256}
		if i < len(fields) {
			*fields[i] += "x"
		} else {
			r.Bytes++
		}
		if got, err := VerifyInstalledScoringArtifact(t.Context(), a.Bytes(), r); !errors.Is(err, ErrIntegrity) || got != nil {
			t.Fatal("external expected identity ignored", i, err)
		}
	}
}

func TestInstalledScoringClosedContextsPrivacyAndConcurrentRestore(t *testing.T) {
	installed, a := installedScoringFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if got, err := installed.InstalledScoringArtifact(ctx); err == nil || got != nil {
			t.Fatal("invalid export context accepted")
		}
		if got, err := VerifyInstalledScoringArtifact(ctx, a.Bytes(), a.Ref()); err == nil || got != nil {
			t.Fatal("invalid verify context accepted")
		}
		if got, err := a.NewReferenceRuntime(ctx); err == nil || got != nil {
			t.Fatal("invalid restore context accepted")
		}
	}
	for _, value := range []any{a, a.Ref()} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			out := fmt.Sprintf(format, value)
			if strings.Contains(out, BuiltinHash) || strings.Contains(out, InstalledScoringSchema) {
				t.Fatal("implicit formatting exposed carrier identity")
			}
		}
		if out, err := json.Marshal(value); err == nil || len(out) != 0 {
			t.Fatal("implicit JSON allowed")
		}
		if _, err := value.(interface{ MarshalYAML() (any, error) }).MarshalYAML(); err == nil {
			t.Fatal("implicit YAML allowed")
		}
		var out bytes.Buffer
		slog.New(slog.NewJSONHandler(&out, nil)).Info("test", "carrier", value)
		if strings.Contains(out.String(), BuiltinHash) {
			t.Fatal("slog exposed carrier identity")
		}
	}
	var group sync.WaitGroup
	results := make(chan *Runtime, 4)
	for range 4 {
		group.Go(func() {
			r, err := a.NewReferenceRuntime(t.Context())
			if err != nil {
				t.Error(err)
			}
			results <- r
		})
	}
	group.Wait()
	close(results)
	seen := map[*Runtime]bool{}
	for r := range results {
		if r == nil || seen[r] {
			t.Fatal("restored runtimes are shared/partial")
		}
		seen[r] = true
	}
}

func TestInstalledScoringNilAndEmptyInputsNeverProduceCandidates(t *testing.T) {
	var source *Artifacts
	if got, err := source.InstalledScoringArtifact(t.Context()); got != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatal("nil installed source accepted")
	}
	var a *InstalledScoringArtifact
	if a.Bytes() != nil || a.Ref() != (InstalledScoringRef{}) {
		t.Fatal("nil carrier returned resources")
	}
	if got, err := a.NewReferenceRuntime(t.Context()); got != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatal("nil carrier restored defaults")
	}
	if got, err := VerifyInstalledScoringArtifact(t.Context(), nil, InstalledScoringRef{}); got != nil || !errors.Is(err, ErrIntegrity) {
		t.Fatal("empty carrier verified")
	}
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte{'x'}, MaxInstalledScoringBytes+1)} {
		if got, err := (&Artifacts{rule: raw}).InstalledScoringArtifact(t.Context()); got != nil || !errors.Is(err, ErrIntegrity) {
			t.Fatal("empty/oversized installed data replaced with defaults")
		}
	}
}

// Cancel a REAL cancelable context on a later boundary check, after initial
// admission. This makes the construction/post-verification paths deterministic
// without timers, production hooks, or returning an inconsistent fake Err.
type scoringCancelAfterContext struct {
	context.Context
	cancel        context.CancelFunc
	checks, after int
}

func (c *scoringCancelAfterContext) Err() error {
	c.checks++
	if c.checks == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestInstalledScoringCancellationAfterAdmissionReturnsNoCandidate(t *testing.T) {
	installed, a := installedScoringFixture(t)
	for _, operation := range []string{"export", "verify", "restore"} {
		last := 5
		if operation == "export" {
			last = 3
		}
		for after := 2; after <= last; after++ {
			t.Run(fmt.Sprintf("%s_checkpoint_%d", operation, after), func(t *testing.T) {
				base, cancel := context.WithCancel(t.Context())
				defer cancel()
				ctx := &scoringCancelAfterContext{Context: base, cancel: cancel, after: after}
				var err error
				var returned bool
				switch operation {
				case "export":
					var got *InstalledScoringArtifact
					got, err = installed.InstalledScoringArtifact(ctx)
					returned = got != nil
				case "verify":
					var got *InstalledScoringArtifact
					got, err = VerifyInstalledScoringArtifact(ctx, a.Bytes(), a.Ref())
					returned = got != nil
				case "restore":
					var got *Runtime
					got, err = a.NewReferenceRuntime(ctx)
					returned = got != nil
				}
				if ctx.checks < after || !errors.Is(base.Err(), context.Canceled) || !errors.Is(err, context.Canceled) || returned {
					t.Fatal("late cancellation did not close constructed output", ctx.checks, err)
				}
			})
		}
	}
}

func FuzzInstalledScoringCarrier(f *testing.F) {
	source, err := Builtin()
	if err != nil {
		f.Fatal(err)
	}
	a, err := source.InstalledScoringArtifact(f.Context())
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range [][]byte{nil, a.Bytes(), []byte(`{}`), []byte(`{"reference_rule":null}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		expected := a.Ref()
		expected.Bytes, expected.SHA256 = int64(len(data)), digest(data)
		got, err := VerifyInstalledScoringArtifact(t.Context(), data, expected)
		if err != nil {
			if got != nil {
				t.Fatal("invalid bytes returned partial carrier")
			}
			return
		}
		if got.Ref() != a.Ref() || !bytes.Equal(got.Bytes(), a.Bytes()) {
			t.Fatal("self-rehashed input admitted unknown installed resources")
		}
		if runtime, err := got.NewReferenceRuntime(t.Context()); err != nil || runtime == nil {
			t.Fatal("verified reference could not reconstruct", err)
		}
	})
}
