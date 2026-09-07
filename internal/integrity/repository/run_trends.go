package repository

import "gorm.io/gorm"

// AttemptTrendRecord counts dispatch records, including retries, not final
// logical samples. It contains only aggregates of explicit S1 columns.
type AttemptTrendRecord struct {
	Dispatched, LogicalSamples, RetryAttempts int64
	Succeeded, Failed, Uncertain, InFlight    int64
	LatencySamples, LatencyTotalMS            int64
	LatencyMinMS, LatencyMaxMS                *int64
}

type RunTrendRecord struct {
	Run      RunHistoryRecord
	Attempts AttemptTrendRecord
}

type RunTrendPage struct {
	Items   []RunTrendRecord
	HasMore bool
}

// ListRunTrends uses one authorized read snapshot for the bounded run page,
// lookahead and attempt aggregates. It never computes a whole-target total.
// The limit+1 row is only a pagination lookahead and is not aggregated.
func (t *Tenant) ListRunTrends(page ListOptions, filters RunFilters) (RunTrendPage, error) {
	if page.AfterID < 0 || page.Limit < 1 || page.Limit > 100 || filters.TargetID <= 0 || !filters.Valid() {
		return RunTrendPage{}, ErrConfiguration
	}
	out := RunTrendPage{Items: []RunTrendRecord{}}
	err := t.resultReadTransaction(false, func(tx *gorm.DB) error {
		q, err := historyPageQuery(tx, t.orgID, page.AfterID, filters)
		if err != nil {
			return err
		}
		var rows []RunHistoryRecord
		if err := q.Limit(page.Limit + 1).Scan(&rows).Error; err != nil {
			return err
		}
		out.HasMore = len(rows) > page.Limit
		if out.HasMore {
			rows = rows[:page.Limit]
		}
		for _, row := range rows {
			if row.OrganizationID != t.orgID || row.TargetID != filters.TargetID || row.PlannedSamples < 0 || row.PlannedSamples > 1000 || row.RequestCount < 0 || row.RequestCount > 3000 {
				return ErrResultDocument
			}
			attempts, err := readAttemptTrend(tx, t.orgID, row.ID)
			if err != nil {
				return err
			}
			// There is no attempt-retention pruning in this version. A mismatch
			// cannot be silently attributed to cleanup or replaced by a counter.
			if attempts.Dispatched != row.RequestCount || attempts.LogicalSamples > int64(row.PlannedSamples) {
				return ErrResultDocument
			}
			out.Items = append(out.Items, RunTrendRecord{Run: row, Attempts: attempts})
		}
		return nil
	})
	if err != nil {
		return RunTrendPage{}, err
	}
	return out, nil
}

func readAttemptTrend(tx *gorm.DB, orgID, runID int64) (AttemptTrendRecord, error) {
	// The (organization_id,run_id,started_at) index bounds this to one run.
	// LIMIT is inside the aggregate, so a damaged run cannot transfer or
	// aggregate an unbounded number of records. No variable-length response,
	// request, error text or model field is selected into application memory.
	const source = `(SELECT a.logical_sample_id,a.attempt_no,a.status,a.validity,a.http_status,a.error_code,a.duration_ms,a.started_at,a.finished_at,
	CASE WHEN s.id IS NOT NULL THEN 1 ELSE 0 END AS bound_sample
	FROM integrity_sample_attempts a
	LEFT JOIN integrity_logical_samples s ON s.organization_id=a.organization_id AND s.run_id=a.run_id AND s.id=a.logical_sample_id
	WHERE a.organization_id=? AND a.run_id=? LIMIT 3001) a`
	const success = `a.status='COMPLETED' AND a.validity IN ('VALID','VALID_WITH_WARNING') AND a.http_status=200 AND (a.error_code IS NULL OR a.error_code='')`
	const latency = `a.status='COMPLETED' AND a.duration_ms IS NOT NULL AND a.duration_ms BETWEEN 0 AND 86400000`
	const valid = `a.bound_sample=1 AND a.attempt_no BETWEEN 1 AND 3 AND a.started_at IS NOT NULL
	AND (a.duration_ms IS NULL OR a.duration_ms BETWEEN 0 AND 86400000)
	AND (a.http_status IS NULL OR a.http_status BETWEEN 0 AND 599)
	AND ((a.status='DISPATCHED' AND a.validity='PENDING' AND a.finished_at IS NULL AND a.duration_ms IS NULL AND a.http_status IS NULL AND (a.error_code IS NULL OR a.error_code=''))
	OR (a.finished_at IS NOT NULL AND a.finished_at>=a.started_at AND
	((a.status='UNCERTAIN' AND a.validity='INVALID_RETRYABLE' AND a.error_code='MI_UNCERTAIN_ATTEMPT' AND (a.http_status IS NULL OR a.http_status=0))
	OR (a.status='COMPLETED' AND
	((a.validity IN ('VALID','VALID_WITH_WARNING') AND a.http_status=200 AND (a.error_code IS NULL OR a.error_code=''))
	OR (a.validity IN ('INVALID_RETRYABLE','INVALID_PROTOCOL','INVALID_SAFETY_LIMIT','NOT_APPLICABLE') AND a.error_code IN
	('MI_NETWORK_TEMPORARY','MI_CONNECTION_RESET','MI_TIMEOUT','MI_RATE_LIMITED','MI_SERVICE_UNAVAILABLE','MI_AUTH_FAILED','MI_MODEL_NOT_FOUND','MI_PROTOCOL_UNSUPPORTED','MI_CLIENT_SAFETY_LIMIT','MI_EVIDENCE_LIMIT','MI_SAFETY_REFUSAL','MI_EXECUTION_CANCELLED','MI_EXECUTION_TARGET_STALE','MI_EXECUTION_BUDGET_EXCEEDED','MI_EXECUTION_CIRCUIT_OPEN')))))))`
	var row struct {
		AttemptTrendRecord `gorm:"embedded"`
		Invalid            int64
	}
	query := `SELECT COUNT(*) AS dispatched,COUNT(DISTINCT a.logical_sample_id) AS logical_samples,
	COALESCE(SUM(CASE WHEN a.attempt_no>1 THEN 1 ELSE 0 END),0) AS retry_attempts,
	COALESCE(SUM(CASE WHEN ` + success + ` THEN 1 ELSE 0 END),0) AS succeeded,
	COALESCE(SUM(CASE WHEN a.status='COMPLETED' AND a.validity NOT IN ('VALID','VALID_WITH_WARNING') THEN 1 ELSE 0 END),0) AS failed,
	COALESCE(SUM(CASE WHEN a.status='UNCERTAIN' THEN 1 ELSE 0 END),0) AS uncertain,
	COALESCE(SUM(CASE WHEN a.status='DISPATCHED' THEN 1 ELSE 0 END),0) AS in_flight,
	COALESCE(SUM(CASE WHEN ` + latency + ` THEN 1 ELSE 0 END),0) AS latency_samples,
	COALESCE(SUM(CASE WHEN ` + latency + ` THEN a.duration_ms ELSE 0 END),0) AS latency_total_ms,
	MIN(CASE WHEN ` + latency + ` THEN a.duration_ms ELSE NULL END) AS latency_min_ms,
	MAX(CASE WHEN ` + latency + ` THEN a.duration_ms ELSE NULL END) AS latency_max_ms,
	COALESCE(SUM(CASE WHEN ` + valid + ` THEN 0 ELSE 1 END),0) AS invalid FROM ` + source
	if err := tx.Raw(query, orgID, runID).Scan(&row).Error; err != nil {
		return AttemptTrendRecord{}, err
	}
	if row.Invalid != 0 || row.Dispatched > 3000 || row.Dispatched != row.Succeeded+row.Failed+row.Uncertain+row.InFlight || row.Dispatched != row.LogicalSamples+row.RetryAttempts {
		return AttemptTrendRecord{}, ErrResultDocument
	}
	return row.AttemptTrendRecord, nil
}
