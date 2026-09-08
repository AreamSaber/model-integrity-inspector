package identity

import (
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestSystemStatusRuntimeBoundariesAndDetachedProjection(t *testing.T) {
	service, _ := newTestService(t)
	runtime := SystemRuntime{Role: "server", Build: buildinfo.Current(), Versions: domain.BundleVersions{Rule: "1.0.0-dev.1", Template: "1.0.0-dev.1", Scoring: "1.0.0-dev.1", Tokenizer: "1.0.0"}, StartupVerifiedAt: time.Now().UTC()}
	for _, mutate := range []func(*SystemRuntime){
		func(r *SystemRuntime) { r.Role = "operator" }, func(r *SystemRuntime) { r.Role = "all" }, func(r *SystemRuntime) { r.StartupVerifiedAt = time.Time{} }, func(r *SystemRuntime) { r.Build.Version = "secret\ncanary" }, func(r *SystemRuntime) { r.Build.Commit = "private-path" }, func(r *SystemRuntime) { r.Build.BuiltAt = "unexpected" }, func(r *SystemRuntime) { r.Versions.Rule = "" },
	} {
		copy := runtime
		mutate(&copy)
		if _, err := NewSystemStatusService(service, copy); err == nil {
			t.Fatal("invalid runtime metadata accepted")
		}
	}
	s, err := NewSystemStatusService(service, runtime)
	if err != nil {
		t.Fatal(err)
	}
	count := int64(0)
	r := repository.SystemStatusRecord{ObservedAt: time.Now().UTC(), Driver: "sqlite", Schema: repository.SystemStatusSchema{State: "compatible", Expected: 15, Applied: 15}, Jobs: repository.SystemStatusJobs{State: "observed", Total: &count}, Audit: repository.SystemStatusAudit{State: "verified"}, ConfiguredRetentionDays: 0}
	first := s.project(r, 1, 2)
	if first.Retention.ConfiguredDays != 0 || first.Retention.WritePolicyDays != 30 || first.Retention.State != "unavailable" || first.Build.Commit != nil || first.Build.BuiltAt != nil || first.RemoteWorkers.State != "unavailable" || first.LocalWorker.State != "not_applicable" {
		t.Fatal("unknown/startup state misrepresented")
	}
	*first.Key.CheckedAt = time.Time{}
	if s.project(r, 1, 2).Key.CheckedAt.IsZero() {
		t.Fatal("caller mutated startup snapshot")
	}
	r.Jobs = repository.SystemStatusJobs{State: "limit_exceeded"}
	r.Audit = repository.SystemStatusAudit{State: "invalid"}
	out := s.project(r, 1, 2)
	if out.Jobs.State != "unavailable" || out.Jobs.Total != nil || out.Audit.State != "error" || out.ObservedState != "degraded" {
		t.Fatal("failed/unknown observation treated as healthy zero")
	}
}
