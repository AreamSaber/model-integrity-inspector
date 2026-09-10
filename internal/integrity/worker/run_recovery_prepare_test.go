package worker

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type runRecoveryTestSource func(func(repository.ExecutionReconciliationData) error) error

func (s runRecoveryTestSource) Use(fn func(repository.ExecutionReconciliationData) error) error {
	return s(fn)
}

func runRecoveryTestData(f runDerivedFixture) repository.ExecutionReconciliationData {
	return repository.ExecutionReconciliationData{
		Job:  repository.Job{ID: f.attempt.JobID, OrganizationID: f.sample.OrganizationID, Type: string(repository.JobSampleExecute), ObjectID: f.sample.ID, AttemptCount: f.attempt.LeaseGeneration, Status: "pending"},
		Run:  repository.RunRecord{ID: f.sample.RunID, OrganizationID: f.sample.OrganizationID, AnalysisSourceVersion: domain.AnalysisSourceDerivedV1, ManifestHash: f.plan.ManifestHash},
		Plan: f.plan, Sample: f.sample, Attempt: &f.attempt,
	}
}

func TestRunRecoveryPrepareActualMACAndBodylessIdentity(t *testing.T) {
	f := newRunDerivedFixture(t)
	prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, f.config.DerivedSealer)
	if err != nil {
		t.Fatal(err)
	}
	data := runRecoveryTestData(f)
	before := data
	result, err := prepare(t.Context(), runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error { return fn(data) }))
	if err != nil || result == nil || len(result.Items) != 1 || !reflect.DeepEqual(before, data) {
		t.Fatal("real bodyless preparation failed or changed original source", err)
	}
	candidate := result.Items[0]
	if candidate.Status != "UNCERTAIN" || candidate.Validity != "INVALID_RETRYABLE" || candidate.ErrorCode != "MI_UNCERTAIN_ATTEMPT" || candidate.Record.KeyVersion != "PREPARE.v1" || result.Scope.RequestHash != f.attempt.RequestHash || result.Scope.ManifestHash != f.plan.ManifestHash || bytes.Contains(candidate.Record.Payload, []byte(f.response.Content)) {
		t.Fatal("recovery rewrote identity, source or unavailable outcome")
	}
	if result := verifyRunDerivedCandidate(t, f, candidate, nil); result.Included != 0 {
		t.Fatal("unavailable recovery was promoted to measured success")
	}
}

func TestRunRecoveryPrepareSourceFailuresAreClosed(t *testing.T) {
	for _, mode := range []string{"empty", "twice", "swallowed-invalid", "cancel-after-callback", "late-error", "unknown-version"} {
		t.Run(mode, func(t *testing.T) {
			f := newRunDerivedFixture(t)
			prepare, err := NewRunRecoveryPreparer(f.config.DerivedBuilder, f.config.DerivedSealer)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			data := runRecoveryTestData(f)
			calls := 0
			source := runRecoveryTestSource(func(fn func(repository.ExecutionReconciliationData) error) error {
				if mode == "empty" {
					return nil
				}
				if mode == "swallowed-invalid" {
					data.Attempt.RequestHash = "invalid"
				}
				if mode == "unknown-version" {
					data.Run.AnalysisSourceVersion = "unknown-v99"
				}
				calls++
				if err := fn(data); err != nil && mode != "swallowed-invalid" {
					return err
				}
				if mode == "twice" {
					calls++
					_ = fn(data)
				}
				if mode == "cancel-after-callback" {
					cancel()
				}
				if mode == "late-error" {
					return errors.New("private-canary-source-failure")
				}
				return nil
			})
			result, err := prepare(ctx, source)
			if err == nil || result != nil || strings.Contains(err.Error(), "private-canary") {
				t.Fatal("source failure or scope violation released a candidate/sensitive error")
			}
			if mode == "cancel-after-callback" && !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation was detached")
			}
			if mode != "empty" && calls == 0 {
				t.Fatal("fixture did not reach real preparation")
			}
		})
	}
}
