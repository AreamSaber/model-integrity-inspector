package repository

import (
	"strconv"
	"strings"

	"gorm.io/gorm"
)

// All SQL fragments below have fixed code-owned identifiers; caller values are
// bound separately. SQL predicates reject invalid storage classes/byte lengths
// before any textual value is allocated by database/sql.
func backupDrainText(db *gorm.DB, field string, maximum int, nullable bool) string {
	var valid string
	if db.Name() == "sqlite" {
		valid = "typeof(" + field + ")='text' AND length(CAST(" + field + " AS BLOB))<=" + strconv.Itoa(maximum)
	} else {
		valid = "octet_length(CAST(" + field + " AS TEXT))<=" + strconv.Itoa(maximum)
	}
	if nullable {
		return "(" + field + " IS NULL OR (" + valid + "))"
	}
	return "(" + field + " IS NOT NULL AND " + valid + ")"
}

func backupDrainInteger(db *gorm.DB, field string, minimum int64) string {
	valid := field + ">=" + strconv.FormatInt(minimum, 10)
	if db.Name() == "sqlite" {
		valid = "typeof(" + field + ")='integer' AND " + valid
	}
	return "(" + valid + ")"
}

const backupDrainDispatched = `EXISTS(SELECT 1 FROM integrity_sample_attempts a WHERE a.job_id=j.id AND a.status='DISPATCHED')`
const backupDrainPrecheckRequested = `j.type='integrity.target.precheck' AND EXISTS(SELECT 1 FROM integrity_target_prechecks p WHERE p.organization_id=j.organization_id AND p.id=j.object_id AND p.request_count>0)`

const backupDrainTerminalProjection = `(j.status IN ('failed','cancelled') AND (
 (j.type='integrity.run.plan' AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=j.organization_id AND r.id=j.object_id AND r.execution_closed_at IS NULL))
 OR (j.type='integrity.sample.execute' AND EXISTS(SELECT 1 FROM integrity_logical_samples s WHERE s.organization_id=j.organization_id AND s.id=j.object_id AND s.completed_at IS NULL))
 OR (j.type='integrity.run.analyze' AND EXISTS(SELECT 1 FROM integrity_runs r WHERE r.organization_id=j.organization_id AND r.id=j.object_id AND r.status='ANALYZING' AND r.execution_closed_at IS NOT NULL))
 OR (j.type='integrity.report.generate' AND EXISTS(SELECT 1 FROM integrity_reports r WHERE r.organization_id=j.organization_id AND r.id=j.object_id AND r.status IN ('queued','generating')))
 OR (j.type='integrity.target.precheck' AND EXISTS(SELECT 1 FROM integrity_target_prechecks p WHERE p.organization_id=j.organization_id AND p.id=j.object_id AND p.status IN ('queued','running')))
))`

func backupDrainCandidateSQL() string {
	return `((j.status='running' AND (j.lease_until IS NULL OR j.lease_until<=?))
 OR (j.status='pending' AND (j.cancel_requested_at IS NOT NULL OR j.attempt_count>=j.max_attempts
 OR (o.status<>'active' AND NOT (` + retentionDisabledJobSQL + `))
 OR ` + backupDrainDispatched + ` OR (` + backupDrainPrecheckRequested + `)
 OR (j.type='integrity.notification.send' AND j.attempt_count>0)))
 OR ` + backupDrainTerminalProjection + `)`
}

func backupDrainJobStructuralSQL(db *gorm.DB) string {
	// Active legacy with a missing nullable current Job pointer is unsupported,
	// not a newly invented foreign identity. Never fill the pointer to pause it.
	objects := "(" + snapshotJobObjectSQL() + ` OR (j.type='integrity.sample.execute' AND EXISTS(SELECT 1 FROM integrity_logical_samples s JOIN integrity_runs r ON r.organization_id=s.organization_id AND r.id=s.run_id WHERE s.organization_id=j.organization_id AND s.id=j.object_id AND s.job_id IS NULL)))`
	checks := []string{backupDrainInteger(db, "j.id", 1), backupDrainInteger(db, "j.organization_id", 1), backupDrainInteger(db, "j.object_id", 1), backupDrainInteger(db, "j.attempt_count", 0), backupDrainInteger(db, "j.max_attempts", 1), "j.attempt_count<=j.max_attempts", "j.status IN ('pending','running','failed','completed','cancelled')", "EXISTS(SELECT 1 FROM organizations o WHERE o.id=j.organization_id AND o.status IN ('active','disabled'))", objects}
	return strings.Join(checks, " AND ")
}

func backupDrainJobValidSQL(db *gorm.DB) string {
	checks := []string{backupDrainJobStructuralSQL(db)}
	if db.Name() == "sqlite" {
		checks = append(checks, "typeof(j.priority)='integer'")
	}
	for _, field := range []struct {
		name     string
		maximum  int
		nullable bool
	}{
		{"type", 64, false}, {"idempotency_key", 128, false}, {"status", 32, false}, {"lease_owner", 128, true}, {"last_error_code", 64, true},
		{"available_at", 128, false}, {"created_at", 128, false}, {"updated_at", 128, false}, {"lease_until", 128, true}, {"cancel_requested_at", 128, true}, {"completed_at", 128, true},
	} {
		checks = append(checks, backupDrainText(db, "j."+field.name, field.maximum, field.nullable))
	}
	return strings.Join(checks, " AND ")
}

// No requirement for a modern Job pointer is imposed on static legal legacy
// rows. Active incomplete legacy is reported separately, never fabricated.
func backupDrainDispatchedInvalidSQL(db *gorm.DB) string {
	valid := backupDrainInteger(db, "a.id", 1) + " AND " + backupDrainInteger(db, "a.organization_id", 1) + " AND " + backupDrainInteger(db, "a.logical_sample_id", 1) + " AND " + backupDrainInteger(db, "a.lease_generation", 0) + ` AND
 EXISTS(SELECT 1 FROM integrity_logical_samples s JOIN integrity_runs r ON r.organization_id=s.organization_id AND r.id=s.run_id
 WHERE s.organization_id=a.organization_id AND s.id=a.logical_sample_id
 AND (a.run_id IS NULL OR a.run_id=s.run_id))
 AND (a.job_id IS NULL OR EXISTS(SELECT 1 FROM integrity_jobs j WHERE j.id=a.job_id AND j.organization_id=a.organization_id
 AND j.type='integrity.sample.execute' AND j.object_id=a.logical_sample_id
 AND a.lease_generation<=j.attempt_count)) AND (a.job_id IS NOT NULL OR a.lease_generation=0)`
	return `SELECT EXISTS(SELECT 1 FROM integrity_sample_attempts a WHERE a.status='DISPATCHED' AND CASE WHEN ` + valid + ` THEN 0 ELSE 1 END=1)`
}

func backupDrainExists(db *gorm.DB, query string, args ...any) (bool, error) {
	var found bool
	if err := db.Raw(query, args...).Scan(&found).Error; err != nil {
		return false, err
	}
	return found, nil
}
