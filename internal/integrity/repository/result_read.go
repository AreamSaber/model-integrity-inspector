package repository

import (
	"errors"
	"time"

	"gorm.io/gorm"
)

var ErrResultDocument = errors.New("MI_ANALYSIS_RESULT_INVALID")

type ResultSampleRecord struct {
	ID, OrganizationID, RunID, ProbeInstanceID int64
	Ordinal, AttemptCount                      int
	FinalAttemptID                             *int64
	Validity                                   string
	CompletedAt                                *time.Time
}
type ResultAttemptRecord struct {
	ID, OrganizationID, RunID, LogicalSampleID                         int64
	AttemptNo                                                          int
	Status, Validity                                                   string
	ErrorCode                                                          *string
	HTTPStatus                                                         *int
	PromptTokens, CompletionTokens, TotalTokens, LocalCompletionTokens *int64
	DurationMS                                                         *int64
	StartedAt, FinishedAt                                              *time.Time
}

// PublishedRead is internal storage data. ConclusionJSON/StatisticsJSON are not
// responses: the run service must validate and project their S1 schema.
type PublishedRead struct {
	Run      RunHistoryRecord
	Result   RunResultRecord
	Samples  []ResultSampleRecord
	Findings []FindingRecord
	Attempts []ResultAttemptRecord
}

func (t *Tenant) ReadPublishedResult(runID int64, revision int, evidence bool, sampleID int64) (PublishedRead, error) {
	if runID <= 0 || revision != 1 || sampleID < 0 {
		return PublishedRead{}, ErrNotFound
	}
	out := PublishedRead{Samples: []ResultSampleRecord{}, Findings: []FindingRecord{}, Attempts: []ResultAttemptRecord{}}
	err := t.resultReadTransaction(evidence, func(tx *gorm.DB) error {
		if err := historyQuery(tx, t.orgID).Where("r.id=?", runID).Take(&out.Run).Error; err != nil {
			return err
		}
		// Check size in SQL before transferring/allocating a potentially corrupt
		// document. SQLite length(TEXT) is characters, so count encoded bytes.
		columns := `organization_id,run_id,analysis_revision,prompt_risk,token_risk,response_risk,evidence_risk,overall_risk,confidence,is_published,created_at,` + readBoundedText(tx, "conclusion_json", "conclusion_json", 4194304)
		for _, field := range []struct {
			name  string
			limit int
		}{{"risk_level", 64}, {"evidence_grade", 1}, {"completeness", 16}} {
			columns += "," + readBoundedText(tx, field.name, field.name, field.limit)
		}
		if err := tx.Model(&RunResultRecord{}).Select(columns).Where("organization_id=? AND run_id=? AND analysis_revision=? AND is_published=?", t.orgID, runID, revision, true).Take(&out.Result).Error; err != nil {
			return err
		}
		if out.Result.ConclusionJSON == "" {
			return ErrResultDocument
		}
		if err := tx.Table("integrity_logical_samples").Select("id,organization_id,run_id,probe_instance_id,ordinal,attempt_count,final_attempt_id,completed_at,"+readBoundedText(tx, "validity", "validity", 32)).Where("organization_id=? AND run_id=?", t.orgID, runID).Order("id").Limit(513).Scan(&out.Samples).Error; err != nil {
			return err
		}
		if len(out.Samples) > 512 {
			return ErrResultDocument
		}
		if evidence {
			// Fixed schema supports <=256 findings, each JSON field <=64 KiB.
			columns := "id,organization_id,run_id,analysis_revision,risk_score,confidence,created_at"
			for _, field := range []struct {
				name  string
				limit int
			}{
				{"category", 32}, {"type", 64}, {"severity", 16}, {"evidence_grade", 1}, {"rule_id", 128}, {"rule_version", 128},
				{"statistics_json", 65536}, {"alternative_explanations", 65536}, {"sample_refs", 65536},
			} {
				columns += "," + readBoundedText(tx, field.name, field.name, field.limit)
			}
			if err := tx.Model(&FindingRecord{}).Select(columns).Where("organization_id=? AND run_id=? AND analysis_revision=?", t.orgID, runID, revision).Order("id").Limit(257).Find(&out.Findings).Error; err != nil {
				return err
			}
			if len(out.Findings) > 256 {
				return ErrResultDocument
			}
		}
		if sampleID > 0 {
			if !evidence {
				return ErrManagementPermission
			}
			found := false
			for _, s := range out.Samples {
				if s.ID == sampleID {
					found = true
					break
				}
			}
			if !found {
				return ErrNotFound
			}
			columns := "id,organization_id,run_id,logical_sample_id,attempt_no,http_status,prompt_tokens,completion_tokens,total_tokens,local_completion_tokens,duration_ms,started_at,finished_at"
			for _, field := range []struct {
				name  string
				limit int
			}{{"status", 32}, {"validity", 32}, {"error_code", 128}} {
				columns += "," + readBoundedText(tx, field.name, field.name, field.limit)
			}
			if err := tx.Table("integrity_sample_attempts").Select(columns).Where("organization_id=? AND run_id=? AND logical_sample_id=?", t.orgID, runID, sampleID).Order("attempt_no").Limit(4).Scan(&out.Attempts).Error; err != nil {
				return err
			}
			if len(out.Attempts) > 3 {
				return ErrResultDocument
			}
		}
		return nil
	})
	// managementError deliberately closes unknown errors; retain only this
	// reader's fixed corruption sentinel without leaking database diagnostics.
	if err != nil {
		return PublishedRead{}, err
	}
	return out, nil
}
