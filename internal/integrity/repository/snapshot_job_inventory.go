package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strings"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
)

const snapshotJobOrganizationPage = 100

var (
	errSnapshotJobSource = errors.New("SNAPSHOT_JOB_SOURCE_INVALID")
	errSnapshotJobLimit  = errors.New("SNAPSHOT_JOB_ORGANIZATION_LIMIT")
	errSnapshotJobBusy   = errors.New("SNAPSHOT_JOB_NOT_DRAINED")
)

type snapshotJobClassification uint8

const (
	snapshotJobUnverified snapshotJobClassification = iota
	snapshotJobVerifiedCurrent
	snapshotJobLegacyIncomplete
)

type snapshotJobOrganization struct {
	organizationID                      int64
	pending, running, completed, failed int64
	cancelled, dispatched, uncertain    int64
	completedAttempts, plannedAttempts  int64
	legacyJobs, legacyAttempts          int64
}

func (snapshotJobOrganization) String() string               { return "[private snapshot job organization]" }
func (v snapshotJobOrganization) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v snapshotJobOrganization) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotJobOrganization) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotJobOrganization) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// This owned candidate is a COMPLETE observation, not a publish/activation
// receipt or executable Job capability. legacyIncomplete preserves migration
// history without pretending missing execution identities were authenticated.
// A later coordinator must retain those original rows and explicitly handle
// isolated legacy recovery; it must not silently discard the legacy counts.
type snapshotJobInventory struct {
	organizations  []snapshotJobOrganization
	classification snapshotJobClassification
}

func (snapshotJobInventory) String() string               { return "[private snapshot job inventory]" }
func (v snapshotJobInventory) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, v.String()) }
func (v snapshotJobInventory) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (snapshotJobInventory) MarshalJSON() ([]byte, error) { return nil, ErrConfiguration }
func (snapshotJobInventory) MarshalYAML() (any, error)    { return nil, ErrConfiguration }

// Only the supplied actual transaction is used. The trusted caller must first
// check SQLite's native physical RO flag on its continuously owned connection;
// query_only is supplemental, not proof of that flag. PG must be genuinely RO
// and RR/serializable. No transaction, claim, reconciliation, lock, or write is
// started here. A deadline bounds SQL work; arbitrary Job/Attempt population
// caps are NOT imposed. Only scalar checks and <=100 grouped org rows enter Go.
func (s *Store) snapshotJobInventory(ctx context.Context, tx *gorm.DB) (snapshotJobInventory, error) {
	return s.snapshotJobInventoryLimited(ctx, tx, backupmanifest.MaxOrganizations)
}

func (s *Store) snapshotJobInventoryLimited(ctx context.Context, tx *gorm.DB, limit int) (snapshotJobInventory, error) {
	if ctx == nil || s == nil || tx == nil || tx.Config == nil || tx.Error != nil || tx.Statement == nil ||
		tx.Dialector == nil || tx.Name() != s.driver || limit < 1 || limit > backupmanifest.MaxOrganizations {
		return snapshotJobInventory{}, ErrConfiguration
	}
	if ctx.Err() != nil {
		return snapshotJobInventory{}, ErrUnavailable
	}
	if _, bounded := ctx.Deadline(); !bounded {
		return snapshotJobInventory{}, ErrConfiguration
	}
	if actual, ok := tx.Statement.ConnPool.(*sql.Tx); !ok || actual == nil {
		return snapshotJobInventory{}, ErrConfiguration
	}
	read := tx.Session(&gorm.Session{NewDB: true, Context: ctx})
	if err := auditSnapshotTransaction(read, s.driver); err != nil {
		return snapshotJobInventory{}, err
	}
	// Check invalid IDs before a positive cursor can omit them. CASE's ELSE
	// rejects SQL UNKNOWN/NULL as well as false; SQLite storage classes are
	// checked before database/sql may coerce an ID/counter to an integer.
	checks := snapshotJobSourceChecks(read)
	for _, check := range checks {
		var invalid bool
		if err := read.Raw(check).Scan(&invalid).Error; err != nil {
			return snapshotJobInventory{}, ErrUnavailable
		}
		if ctx.Err() != nil {
			return snapshotJobInventory{}, ErrUnavailable
		}
		if invalid {
			return snapshotJobInventory{}, errSnapshotJobSource
		}
	}
	result := snapshotJobInventory{organizations: make([]snapshotJobOrganization, 0, min(limit, snapshotJobOrganizationPage)), classification: snapshotJobVerifiedCurrent}
	var after int64
	for {
		if ctx.Err() != nil {
			return snapshotJobInventory{}, ErrUnavailable
		}
		var ids []int64
		if err := read.Table("organizations").Where("id>?", after).Order("id").Limit(snapshotJobOrganizationPage).Pluck("id", &ids).Error; err != nil {
			return snapshotJobInventory{}, ErrUnavailable
		}
		if len(ids) > limit-len(result.organizations) {
			return snapshotJobInventory{}, errSnapshotJobLimit
		}
		if len(ids) == 0 {
			break
		}
		jobs, attempts, err := snapshotJobCounts(read, ids)
		if err != nil {
			return snapshotJobInventory{}, err
		}
		for _, id := range ids {
			if id <= after {
				return snapshotJobInventory{}, errSnapshotJobSource
			}
			j, a := jobs[id], attempts[id]
			if !snapshotJobValidCounts(j) || !snapshotJobValidCounts(a) {
				return snapshotJobInventory{}, errSnapshotJobSource
			}
			// Lease expiry and terminal Job state do not prove a dispatched
			// external request has stopped. Never normalize these to success.
			if j.Running != 0 || a.Dispatched != 0 {
				return snapshotJobInventory{}, errSnapshotJobBusy
			}
			row := snapshotJobOrganization{id, j.Pending, j.Running, j.Completed, j.Failed, j.Cancelled, a.Dispatched, a.Uncertain, a.Completed, a.Planned, j.Legacy, a.Legacy}
			if row.legacyJobs != 0 || row.legacyAttempts != 0 {
				result.classification = snapshotJobLegacyIncomplete
			}
			result.organizations = append(result.organizations, row)
			after = id
		}
		if len(ids) < snapshotJobOrganizationPage {
			break
		}
	}
	if ctx.Err() != nil {
		return snapshotJobInventory{}, ErrUnavailable
	}
	if len(result.organizations) == 0 {
		return snapshotJobInventory{}, errSnapshotJobSource
	}
	return result, nil
}

// No unbounded string/body/key, lease owner or timestamp crosses the SQL
// boundary. Aggregate sums use BIGINT on both dialects, including PostgreSQL's
// empty-group semantics. Each query groups only the fixed current org page.
type snapshotJobCountRow struct {
	OrganizationID                                 int64
	Pending, Running, Completed, Failed, Cancelled int64
	Dispatched, Uncertain, Planned, Legacy, Total  int64
}

func snapshotJobCounts(tx *gorm.DB, ids []int64) (map[int64]snapshotJobCountRow, map[int64]snapshotJobCountRow, error) {
	jobs := make(map[int64]snapshotJobCountRow, len(ids))
	attempts := make(map[int64]snapshotJobCountRow, len(ids))
	for _, query := range []struct {
		table, alias, legacy string
		fields               []string
		output               map[int64]snapshotJobCountRow
	}{
		{"integrity_jobs", "j", snapshotJobLegacySQL(), []string{"pending", "running", "completed", "failed", "cancelled"}, jobs},
		{"integrity_sample_attempts", "a", snapshotAttemptLegacySQL(), []string{"DISPATCHED", "UNCERTAIN", "COMPLETED", "PLANNED"}, attempts},
	} {
		columns := query.alias + ".organization_id,COUNT(*) AS total"
		for _, state := range query.fields {
			columns += ",SUM(CAST(CASE WHEN " + query.alias + ".status='" + state + "' THEN 1 ELSE 0 END AS BIGINT)) AS " + strings.ToLower(state)
		}
		columns += ",SUM(CAST(CASE WHEN " + query.legacy + " THEN 1 ELSE 0 END AS BIGINT)) AS legacy"
		var rows []snapshotJobCountRow
		if err := tx.Table(query.table+" "+query.alias).Select(columns).Where(query.alias+".organization_id IN ?", ids).
			Group(query.alias + ".organization_id").Order(query.alias + ".organization_id").Limit(snapshotJobOrganizationPage + 1).Scan(&rows).Error; err != nil {
			return nil, nil, ErrUnavailable
		}
		if len(rows) > len(ids) {
			return nil, nil, errSnapshotJobSource
		}
		for _, row := range rows {
			belongs := false
			for _, id := range ids {
				belongs = belongs || row.OrganizationID == id
			}
			if !belongs {
				return nil, nil, errSnapshotJobSource
			}
			if _, duplicate := query.output[row.OrganizationID]; duplicate {
				return nil, nil, errSnapshotJobSource
			}
			query.output[row.OrganizationID] = row
		}
	}
	return jobs, attempts, nil
}

func snapshotJobValidCounts(row snapshotJobCountRow) bool {
	var sum int64
	for _, n := range []int64{row.Pending, row.Running, row.Completed, row.Failed, row.Cancelled, row.Dispatched, row.Uncertain, row.Planned} {
		if n < 0 || sum > math.MaxInt64-n {
			return false
		}
		sum += n
	}
	return sum == row.Total && row.Legacy >= 0 && row.Legacy <= row.Total
}

// Names below are fixed source literals, never caller or database identifiers.
func snapshotJobInteger(tx *gorm.DB, name string, minimum int) string {
	condition := fmt.Sprintf("%s IS NOT NULL AND %s>=%d", name, name, minimum)
	if tx.Name() == "sqlite" {
		condition = "typeof(" + name + ")='integer' AND " + condition
	}
	return "(" + condition + ")"
}

func snapshotJobInvalidRows(table, condition string) string {
	return "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE CASE WHEN " + condition + " THEN 0 ELSE 1 END=1)"
}

func snapshotJobSourceChecks(tx *gorm.DB) []string {
	positive := func(name string) string { return snapshotJobInteger(tx, name, 1) }
	nonnegative := func(name string) string { return snapshotJobInteger(tx, name, 0) }
	job := positive("j.id") + " AND " + positive("j.organization_id") + " AND " + positive("j.object_id") + " AND " + nonnegative("j.attempt_count") + " AND " + positive("j.max_attempts") + `
 AND j.attempt_count<=j.max_attempts AND j.status IN ('pending','running','completed','failed','cancelled')
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=j.organization_id)
 AND (` + snapshotJobObjectSQL() + `)
 AND (NOT (` + snapshotJobLegacySQL() + `) OR j.status IN ('completed','failed','cancelled'))`
	attempt := positive("a.id") + " AND " + positive("a.organization_id") + " AND " + positive("a.logical_sample_id") + " AND " + positive("a.attempt_no") + " AND " + nonnegative("a.lease_generation") + `
 AND a.status IN ('PLANNED','DISPATCHED','COMPLETED','UNCERTAIN')
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=a.organization_id)
 AND EXISTS(SELECT 1 FROM integrity_logical_samples s JOIN integrity_runs r ON r.organization_id=s.organization_id AND r.id=s.run_id
 WHERE s.organization_id=a.organization_id AND s.id=a.logical_sample_id AND ` + positive("s.run_id") + ` AND
 (a.run_id IS NULL OR (` + positive("a.run_id") + ` AND a.run_id=s.run_id))
 AND (a.job_id IS NULL OR (` + positive("a.job_id") + ` AND EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.organization_id=a.organization_id AND j.id=a.job_id AND j.type='integrity.sample.execute' AND j.object_id=a.logical_sample_id AND a.lease_generation<=j.attempt_count)))
 AND ((` + snapshotAttemptLegacySQL() + `) AND r.analysis_source_version='legacy_response_v1' AND a.derived_receipt='legacy_not_recorded'
 OR NOT (` + snapshotAttemptLegacySQL() + `) AND a.attempt_no<=s.attempt_count))
 AND (a.job_id IS NOT NULL OR a.lease_generation=0)`
	return []string{
		snapshotJobInvalidRows("organizations o", positive("o.id")+" AND o.status IN ('active','disabled')"),
		// A duplicate at the 100th ID is invisible to the next positive keyset
		// page. Prove uniqueness in SQL before that cursor can omit a row.
		"SELECT EXISTS(SELECT 1 FROM organizations GROUP BY id HAVING COUNT(*)<>1)",
		"SELECT EXISTS(SELECT 1 FROM integrity_jobs GROUP BY id HAVING COUNT(*)<>1)",
		"SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts GROUP BY id HAVING COUNT(*)<>1)",
		"SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts GROUP BY organization_id,logical_sample_id,attempt_no HAVING COUNT(*)<>1)",
		snapshotJobInvalidRows("integrity_jobs j", job),
		snapshotJobInvalidRows("integrity_sample_attempts a", attempt),
		// A provided current pointer may differ from a historical attempt's
		// Job after retry. It must still bind this exact sample/type/org.
		snapshotJobInvalidRows("integrity_logical_samples s", positive("s.id")+" AND "+positive("s.organization_id")+" AND "+positive("s.run_id")+" AND "+nonnegative("s.attempt_count")+`
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=s.organization_id)
 AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=s.organization_id AND r.id=s.run_id)
 AND EXISTS(SELECT 1 FROM integrity_probe_instances p WHERE p.organization_id=s.organization_id AND p.run_id=s.run_id AND p.id=s.probe_instance_id)
 AND (s.job_id IS NULL OR (`+positive("s.job_id")+` AND EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.organization_id=s.organization_id AND j.id=s.job_id AND j.type='integrity.sample.execute' AND j.object_id=s.id)))
 AND (s.final_attempt_id IS NULL OR (`+positive("s.final_attempt_id")+` AND EXISTS(SELECT 1 FROM integrity_sample_attempts a WHERE a.organization_id=s.organization_id AND a.logical_sample_id=s.id AND a.id=s.final_attempt_id)))`),
		snapshotJobInvalidRows("integrity_runs r", positive("r.id")+" AND "+positive("r.organization_id")+`
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=r.organization_id)
 AND EXISTS(SELECT 1 FROM integrity_targets t WHERE t.organization_id=r.organization_id AND t.id=r.target_id)
 AND (r.plan_job_id IS NULL OR (`+positive("r.plan_job_id")+` AND EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.organization_id=r.organization_id AND j.id=r.plan_job_id AND j.type='integrity.run.plan' AND j.object_id=r.id)))`),
		snapshotJobInvalidRows("integrity_target_prechecks p", positive("p.id")+" AND "+positive("p.organization_id")+" AND "+positive("p.target_id")+`
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=p.organization_id)
 AND EXISTS(SELECT 1 FROM integrity_targets t WHERE t.organization_id=p.organization_id AND t.id=p.target_id)
 AND (p.job_id IS NULL OR (`+positive("p.job_id")+` AND EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.organization_id=p.organization_id AND j.id=p.job_id AND j.type='integrity.target.precheck' AND j.object_id=p.id)))`),
		snapshotJobInvalidRows("integrity_reports p", positive("p.id")+" AND "+positive("p.organization_id")+" AND "+positive("p.run_id")+`
 AND EXISTS(SELECT 1 FROM organizations o WHERE o.id=p.organization_id)
 AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=p.organization_id AND r.id=p.run_id)
 AND EXISTS(SELECT 1 FROM integrity_run_results v WHERE v.organization_id=p.organization_id AND v.run_id=p.run_id AND v.analysis_revision=p.analysis_revision)
 AND (p.job_id IS NULL OR (`+positive("p.job_id")+` AND EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.organization_id=p.organization_id AND j.id=p.job_id AND j.type='integrity.report.generate' AND j.object_id=p.id)))`),
	}
}

func snapshotAttemptLegacySQL() string {
	return "(a.run_id IS NULL OR a.job_id IS NULL OR a.lease_generation=0 OR a.status='PLANNED')"
}

func snapshotJobLegacySQL() string {
	return `(j.type='integrity.run.plan' AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=j.organization_id AND r.id=j.object_id AND r.plan_job_id IS NULL))
 OR (j.type='integrity.sample.execute' AND EXISTS(SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id=j.organization_id AND s.id=j.object_id AND s.job_id IS NULL))
 OR (j.type='integrity.report.generate' AND EXISTS(SELECT 1 FROM integrity_reports r WHERE r.organization_id=j.organization_id AND r.id=j.object_id AND r.job_id IS NULL))
 OR (j.type='integrity.target.precheck' AND EXISTS(SELECT 1 FROM integrity_target_prechecks p WHERE p.organization_id=j.organization_id AND p.id=j.object_id AND p.job_id IS NULL))`
}

func snapshotJobObjectSQL() string {
	return `(j.type='integrity.run.plan' AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=j.organization_id AND r.id=j.object_id AND (r.plan_job_id IS NULL OR r.plan_job_id=j.id)))
 OR (j.type='integrity.run.analyze' AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=j.organization_id AND r.id=j.object_id))
 OR (j.type='integrity.sample.execute' AND EXISTS(SELECT 1 FROM integrity_logical_samples s JOIN integrity_runs r ON r.organization_id=s.organization_id AND r.id=s.run_id WHERE s.organization_id=j.organization_id AND s.id=j.object_id AND (j.status IN ('completed','failed','cancelled') OR s.job_id=j.id)))
 OR (j.type='integrity.report.generate' AND EXISTS(SELECT 1 FROM integrity_reports p JOIN integrity_runs r ON r.organization_id=p.organization_id AND r.id=p.run_id JOIN integrity_run_results v ON v.organization_id=p.organization_id AND v.run_id=p.run_id AND v.analysis_revision=p.analysis_revision WHERE p.organization_id=j.organization_id AND p.id=j.object_id AND (p.job_id IS NULL OR p.job_id=j.id)))
 OR (j.type='integrity.target.precheck' AND EXISTS(SELECT 1 FROM integrity_target_prechecks p JOIN integrity_targets t ON t.organization_id=p.organization_id AND t.id=p.target_id WHERE p.organization_id=j.organization_id AND p.id=j.object_id AND (p.job_id IS NULL OR p.job_id=j.id)))
 OR (j.type='integrity.notification.send' AND EXISTS(SELECT 1 FROM integrity_outbox o WHERE o.organization_id=j.organization_id AND o.id=j.object_id))
 OR (j.type='integrity.retention.delete' AND ((j.object_id=j.organization_id AND substr(j.idempotency_key,1,19)<>'response-retention:') OR (j.object_id<>j.organization_id AND EXISTS(SELECT 1 FROM integrity_response_retention_batches b JOIN integrity_runs r ON r.organization_id=b.organization_id AND r.id=b.run_id AND r.created_by=b.created_by WHERE b.organization_id=j.organization_id AND b.id=j.object_id AND b.job_id=j.id AND b.created_by>0 AND b.run_id>0 AND j.idempotency_key='response-retention:' || CAST(b.id AS TEXT) AND ((b.state='planned' AND j.status IN ('pending','running','failed','cancelled')) OR (b.state='completed' AND j.status='completed' AND b.completed_at IS NOT NULL AND b.policy_version>0 AND b.observed_at_micros>0 AND length(b.receipt_hash)=64))))))`
}
