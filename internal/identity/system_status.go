package identity

import (
	"context"
	"regexp"
	"strconv"
	"time"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

// SystemRuntime is trusted application composition, never a decoded request.
// Startup observations are not claims about current disk/key availability.
type SystemRuntime struct {
	Role              string
	Build             buildinfo.Info
	Versions          domain.BundleVersions
	StartupVerifiedAt time.Time
	LocalWorkerReady  func() bool
}
type SystemStatusService struct {
	identity *Service
	runtime  SystemRuntime
}

type SystemCheck struct {
	State     string     `json:"state"`
	Source    string     `json:"source"`
	CheckedAt *time.Time `json:"checked_at"`
	Reason    string     `json:"reason"`
}
type SystemBuild struct {
	Version   string     `json:"version"`
	Commit    *string    `json:"commit"`
	BuiltAt   *time.Time `json:"built_at"`
	Rule      string     `json:"rule_bundle"`
	Template  string     `json:"template_bundle"`
	Scoring   string     `json:"scoring"`
	Tokenizer string     `json:"tokenizer_bundle"`
}
type SystemSchema struct {
	SystemCheck
	Expected int `json:"expected_migrations"`
	Applied  int `json:"observed_migrations"`
}
type SystemJobs struct {
	SystemCheck
	Limit          int    `json:"row_limit"`
	Total          *int64 `json:"total_active_jobs"`
	PendingReady   *int64 `json:"pending_ready"`
	PendingDelayed *int64 `json:"pending_delayed"`
	RunningLeased  *int64 `json:"running_leased"`
	RunningExpired *int64 `json:"running_expired"`
}
type SystemAudit struct {
	SystemCheck
	VerifiedCount *int64     `json:"verified_tail_events"`
	LastEventAt   *time.Time `json:"last_event_at"`
}
type SystemRetention struct {
	SystemCheck
	ConfiguredDays  int `json:"configured_body_days"`
	WritePolicyDays int `json:"current_write_policy_days"`
}
type SystemStatus struct {
	OrganizationID string          `json:"organization_id"`
	UserID         string          `json:"user_id"`
	ObservedAt     time.Time       `json:"observed_at"`
	ObservedState  string          `json:"observed_state"`
	Coverage       string          `json:"coverage"`
	Role           string          `json:"process_role"`
	Driver         string          `json:"database_driver"`
	Build          SystemBuild     `json:"build"`
	Database       SystemCheck     `json:"database"`
	Schema         SystemSchema    `json:"schema"`
	LocalWorker    SystemCheck     `json:"local_worker"`
	RemoteWorkers  SystemCheck     `json:"remote_workers"`
	Jobs           SystemJobs      `json:"organization_jobs"`
	Audit          SystemAudit     `json:"organization_audit"`
	Key            SystemCheck     `json:"master_key"`
	Reports        SystemCheck     `json:"report_storage"`
	Retention      SystemRetention `json:"retention_policy"`
	Quotas         SystemCheck     `json:"organization_periodic_quotas"`
	Cleanup        SystemCheck     `json:"retention_cleanup"`
	Backup         SystemCheck     `json:"backup_restore"`
}

var systemVersionLabel = regexp.MustCompile(`^v?[0-9][0-9A-Za-z.+-]{0,127}$`)
var systemCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func NewSystemStatusService(service *Service, runtime SystemRuntime) (*SystemStatusService, error) {
	if service == nil || service.store == nil || runtime.Role != "all" && runtime.Role != "server" || runtime.StartupVerifiedAt.IsZero() || runtime.StartupVerifiedAt.Year() < 2000 || runtime.StartupVerifiedAt.Year() > 2100 || runtime.Role == "all" && runtime.LocalWorkerReady == nil {
		return nil, ErrUnavailable
	}
	for _, version := range []string{runtime.Build.Version, runtime.Versions.Rule, runtime.Versions.Template, runtime.Versions.Scoring, runtime.Versions.Tokenizer} {
		if !systemVersionLabel.MatchString(version) {
			return nil, ErrUnavailable
		}
	}
	if runtime.Build.Commit != "unknown" && !systemCommit.MatchString(runtime.Build.Commit) {
		return nil, ErrUnavailable
	}
	if runtime.Build.BuiltAt != "unknown" {
		if value, err := time.Parse(time.RFC3339, runtime.Build.BuiltAt); err != nil || value.Year() < 2000 || value.Year() > 2100 {
			return nil, ErrUnavailable
		}
	}
	runtime.StartupVerifiedAt = runtime.StartupVerifiedAt.UTC()
	return &SystemStatusService{service, runtime}, nil
}

// Authorize is a cheap admission preflight, not an alternative to the later
// transaction-bound user/session/member/grant checks.
func (s *SystemStatusService) Authorize(ctx context.Context, token string, org int64) error {
	if s == nil || org <= 0 {
		return ErrPermission
	}
	// Preflight only the system role. The narrow repository snapshot below
	// checks the explicit organization and two grants without loading all grant
	// strings or treating system status as a cross-tenant wildcard.
	_, auth, err := s.identity.managementAuthority(ctx, token, 0, "system.read", "")
	if err != nil {
		return err
	}
	return managementServiceError(s.identity.store.CheckSystemStatusAuthority(ctx, auth, org))
}

func (s *SystemStatusService) Read(ctx context.Context, token string, org int64) (SystemStatus, error) {
	if s == nil || org <= 0 {
		return SystemStatus{}, ErrPermission
	}
	_, auth, err := s.identity.managementAuthority(ctx, token, 0, "system.read", "")
	if err != nil {
		return SystemStatus{}, err
	}
	r, err := s.identity.store.ReadSystemStatus(ctx, auth, org)
	if err != nil {
		return SystemStatus{}, managementServiceError(err)
	}
	out := s.project(r, auth.UserID, org)
	if err := s.identity.store.CheckSystemStatusAuthority(ctx, auth, org); err != nil {
		return SystemStatus{}, managementServiceError(err)
	}
	if ctx.Err() != nil {
		return SystemStatus{}, ErrUnavailable
	}
	return out, nil
}

func (s *SystemStatusService) project(r repository.SystemStatusRecord, user, org int64) SystemStatus {
	now := r.ObservedAt
	startup := s.runtime.StartupVerifiedAt
	check := func(state, source, reason string) SystemCheck { return SystemCheck{state, source, &now, reason} }
	unavailable := func(reason string) SystemCheck { return SystemCheck{"unavailable", "not_observed", nil, reason} }
	v := s.runtime.Versions
	out := SystemStatus{OrganizationID: strconv.FormatInt(org, 10), UserID: strconv.FormatInt(user, 10), ObservedAt: now, ObservedState: "ok", Coverage: "partial", Role: s.runtime.Role, Driver: r.Driver,
		Build:         SystemBuild{Version: s.runtime.Build.Version, Rule: v.Rule, Template: v.Template, Scoring: v.Scoring, Tokenizer: v.Tokenizer},
		Database:      check("ok", "authorized_database_snapshot", "read_connection_only"),
		Schema:        SystemSchema{check("ok", "authorized_database_snapshot", "migration_history_matches"), r.Schema.Expected, r.Schema.Applied},
		Jobs:          SystemJobs{check("ok", "selected_organization", "active_jobs_not_runs_or_samples"), repository.SystemStatusMaxJobs, r.Jobs.Total, r.Jobs.PendingReady, r.Jobs.PendingDelayed, r.Jobs.RunningLeased, r.Jobs.RunningExpired},
		Audit:         SystemAudit{check("ok", "selected_organization", "tail_only_not_full_chain"), r.Audit.VerifiedCount, r.Audit.LastEventAt},
		RemoteWorkers: unavailable("remote_consumer_registry_unavailable"),
		Key:           SystemCheck{"startup_verified", "local_process_startup", &startup, "current_key_file_and_all_credentials_not_probed"},
		Reports:       SystemCheck{"startup_verified", "local_process_startup", &startup, "current_capacity_writeability_and_all_artifacts_not_probed"},
		Retention:     SystemRetention{unavailable("organization_setting_not_bound_to_write_policy"), r.ConfiguredRetentionDays, 30},
		Quotas:        unavailable("organization_periodic_quotas_not_implemented"), Cleanup: unavailable("retention_handler_not_registered"), Backup: unavailable("backup_restore_receipts_unavailable")}
	if s.runtime.Build.Commit != "unknown" {
		value := s.runtime.Build.Commit
		out.Build.Commit = &value
	}
	if s.runtime.Build.BuiltAt != "unknown" {
		value, _ := time.Parse(time.RFC3339, s.runtime.Build.BuiltAt)
		value = value.UTC()
		out.Build.BuiltAt = &value
	}
	if s.runtime.Role == "server" {
		out.LocalWorker = check("not_applicable", "local_process", "server_role_has_no_local_worker")
	} else if s.runtime.LocalWorkerReady() {
		out.LocalWorker = check("ok", "local_process", "local_runner_reports_ready")
	} else {
		out.LocalWorker = check("error", "local_process", "local_runner_not_ready")
		out.ObservedState = "degraded"
	}
	localObservedAt := time.Now().UTC()
	out.LocalWorker.CheckedAt = &localObservedAt
	if r.Schema.State != "compatible" {
		out.Schema.State = "error"
		out.Schema.Reason = "migration_history_mismatch"
		out.ObservedState = "degraded"
	}
	if r.Jobs.State == "limit_exceeded" {
		out.Jobs.SystemCheck = unavailable("active_job_limit_exceeded")
	} else if r.Jobs.State != "observed" {
		out.Jobs.State = "error"
		out.Jobs.Reason = "active_job_records_invalid"
		out.ObservedState = "degraded"
	}
	if r.Audit.State == "unavailable" {
		out.Audit.SystemCheck = unavailable("audit_signer_unavailable")
	} else if r.Audit.State != "verified" {
		out.Audit.State = "error"
		out.Audit.Reason = "audit_tail_invalid"
		out.ObservedState = "degraded"
	}
	return out
}
