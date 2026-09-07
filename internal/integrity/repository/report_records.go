package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

var ErrReportInvalid = errors.New("MI_REPORT_INVALID")
var ErrReportNotReady = errors.New("MI_REPORT_NOT_READY")
var ErrReportLimit = errors.New("MI_REPORT_LIMIT")

const reportSchema = "mii.report.v1"
const reportInputLimit = 4 << 20
const reportFileLimit = 16 << 20

type ReportRecord struct {
	ID, OrganizationID, RunID           int64
	AnalysisRevision, Revision          int
	FormatName                          string `gorm:"column:format"`
	SchemaVersion, Status               string
	ContentHash, StoragePath, ErrorCode *string
	CreatedBy, JobID                    *int64
	CreatedAt                           time.Time
	CompletedAt, FrozenAt               *time.Time
	SourceJSON, SourceHash, FileHash    *string
	FileSize                            *int64
}

func (ReportRecord) TableName() string            { return "integrity_reports" }
func (ReportRecord) String() string               { return "[protected report record]" }
func (r ReportRecord) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (ReportRecord) MarshalJSON() ([]byte, error) { return nil, ErrReportInvalid }
func (r ReportRecord) LogValue() slog.Value       { return slog.StringValue(r.String()) }

type ReportInput struct {
	RunID                  int64
	AnalysisRevision       int
	Format, IdempotencyKey string
}
type reportReceipt struct {
	OrganizationID, CreatedBy   int64
	RequestKeyHash, RequestHash string
	RunID                       int64
	AnalysisRevision            int
	ReportID                    int64
}

func (reportReceipt) TableName() string { return "integrity_report_receipts" }

func reportDigest(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func validReportInput(in ReportInput) bool {
	if in.RunID <= 0 || in.AnalysisRevision != 1 || !slices.Contains([]string{"json", "html"}, in.Format) || len(in.IdempotencyKey) < 16 || len(in.IdempotencyKey) > 128 {
		return false
	}
	for _, r := range in.IdempotencyKey {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)
		if !allowed {
			return false
		}
	}
	return true
}
func reportError(err error) error {
	for _, known := range []error{ErrReportInvalid, ErrReportNotReady, ErrReportLimit, ErrResultDocument, ErrJobLeaseLost, ErrJobInvalid, ErrConsumerLost, ErrTransactionClosed} {
		if errors.Is(err, known) {
			return known
		}
	}
	return managementError(err)
}
func reportMetadataColumns(tx *gorm.DB) string {
	columns := "id,organization_id,run_id,analysis_revision,revision,created_by,job_id,created_at,completed_at,frozen_at,file_size"
	for _, f := range []struct {
		name  string
		limit int
	}{{"format", 8}, {"schema_version", 32}, {"status", 16}, {"content_hash", 71}, {"storage_path", 128}, {"error_code", 64}, {"source_hash", 64}, {"file_hash", 64}} {
		columns += "," + readBoundedText(tx, f.name, f.name, f.limit)
	}
	return columns
}
func validReportRecord(r ReportRecord, org int64) bool {
	if r.ID <= 0 || r.OrganizationID != org || r.RunID <= 0 || r.AnalysisRevision != 1 || r.Revision < 1 || r.Revision > 2147483647 || r.CreatedBy == nil || *r.CreatedBy <= 0 || r.JobID == nil || *r.JobID <= 0 || r.CreatedAt.IsZero() || r.SchemaVersion != reportSchema || !slices.Contains([]string{"json", "html"}, r.FormatName) || !slices.Contains([]string{"queued", "generating", "ready", "failed", "expired"}, r.Status) {
		return false
	}
	if r.SourceHash != nil && !executionHash.MatchString(*r.SourceHash) || r.ErrorCode != nil && *r.ErrorCode != "MI_REPORT_GENERATION_FAILED" {
		return false
	}
	if r.Status == "ready" {
		return r.ContentHash != nil && len(*r.ContentHash) == 71 && strings.HasPrefix(*r.ContentHash, "sha256:") && executionHash.MatchString((*r.ContentHash)[7:]) && r.FileHash != nil && executionHash.MatchString(*r.FileHash) && r.FileSize != nil && *r.FileSize > 0 && *r.FileSize <= reportFileLimit && r.StoragePath != nil && *r.StoragePath == ReportObjectName(org, *r.FileHash, r.FormatName) && r.CompletedAt != nil && r.SourceHash != nil && r.FrozenAt != nil
	}
	return r.ContentHash == nil && r.FileHash == nil && r.FileSize == nil && r.StoragePath == nil
}

// ReportObjectName accepts only closed database-derived identifiers. Storage
// independently validates the entire generated name and never accepts paths.
func ReportObjectName(org int64, fileHash, format string) string {
	if org <= 0 || !executionHash.MatchString(fileHash) || !slices.Contains([]string{"json", "html"}, format) {
		return ""
	}
	return "org-" + strconv.FormatInt(org, 10) + "-" + fileHash + "." + format
}
func reportPermissions(tx *gorm.DB, org, user int64) error {
	var active int64
	if err := tx.Table("users").Where("id=? AND status='active' AND must_change_password=?", user, false).Count(&active).Error; err != nil {
		return err
	}
	if active != 1 {
		return ErrManagementPermission
	}
	// Restrict SQL output to the only accepted permission codes.
	var grants []string
	err := tx.Raw(`SELECT DISTINCT code FROM (
SELECT rp.permission_code AS code FROM role_permissions rp JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id JOIN organizations o ON o.id=om.organization_id WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND rp.permission_code IN ('run.read','evidence.read','report.export')
UNION SELECT mp.permission_code AS code FROM member_permissions mp JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id JOIN organizations o ON o.id=om.organization_id WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active' AND mp.permission_code IN ('run.read','evidence.read','report.export')) report_grants`, org, user, org, user).Scan(&grants).Error
	if err != nil {
		return err
	}
	for _, p := range []string{"run.read", "evidence.read", "report.export"} {
		if !slices.Contains(grants, p) {
			return ErrManagementPermission
		}
	}
	return nil
}

func (t *Tenant) CreateReport(in ReportInput) (ReportRecord, error) {
	if !validReportInput(in) {
		return ReportRecord{}, ErrReportInvalid
	}
	var out ReportRecord
	err := t.reportTransaction(func(tx *TenantTransaction) error {
		actor, err := audit.ActorFromContext(tx.ctx)
		if err != nil {
			return err
		}
		if err := reportPermissions(tx.db, t.orgID, actor.ActorID); err != nil {
			return err
		}
		key := reportDigest([]byte(in.IdempotencyKey))
		body, _ := json.Marshal(struct {
			Run      int64
			Revision int
			Format   string
		}{in.RunID, in.AnalysisRevision, in.Format})
		requestHash := reportDigest(append([]byte("mii.report.request.v1\x00"), body...))
		var receipt reportReceipt
		err = tx.db.Select("organization_id,created_by,run_id,analysis_revision,report_id,"+readBoundedText(tx.db, "request_hash", "request_hash", 64)).Where("organization_id=? AND created_by=? AND request_key_hash=?", t.orgID, actor.ActorID, key).Take(&receipt).Error
		if err == nil {
			if receipt.RequestHash != requestHash || receipt.RunID != in.RunID || receipt.AnalysisRevision != in.AnalysisRevision {
				return ErrConflict
			}
			if err := tx.db.Select(reportMetadataColumns(tx.db)).Where("organization_id=? AND id=?", t.orgID, receipt.ReportID).Take(&out).Error; err != nil {
				return err
			}
			if !validReportRecord(out, t.orgID) {
				return ErrReportInvalid
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var resultCount int64
		if err := tx.db.Table("integrity_run_results").Where("organization_id=? AND run_id=? AND analysis_revision=? AND is_published=?", t.orgID, in.RunID, in.AnalysisRevision, true).Count(&resultCount).Error; err != nil {
			return err
		}
		if resultCount != 1 {
			return ErrNotFound
		}
		var active int64
		if err := tx.db.Model(&ReportRecord{}).Where("organization_id=? AND status IN ('queued','generating')", t.orgID).Count(&active).Error; err != nil {
			return err
		}
		if active >= 20 {
			return ErrReportLimit
		}
		var revision int
		if err := tx.db.Model(&ReportRecord{}).Select("COALESCE(MAX(revision),0)").Where("organization_id=? AND run_id=? AND analysis_revision=? AND format=?", t.orgID, in.RunID, in.AnalysisRevision, in.Format).Scan(&revision).Error; err != nil {
			return err
		}
		if revision >= 100 {
			return ErrReportLimit
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		now, err := queueTime(tx.db, t.store.driver)
		if err != nil {
			return err
		}
		out = ReportRecord{ID: id, OrganizationID: t.orgID, RunID: in.RunID, AnalysisRevision: in.AnalysisRevision, Revision: revision + 1, FormatName: in.Format, SchemaVersion: reportSchema, Status: "queued", CreatedBy: &actor.ActorID, CreatedAt: now}
		if err := tx.db.Create(&out).Error; err != nil {
			return err
		}
		job, err := tx.Enqueue(JobSpec{Type: JobReportGenerate, ObjectID: id, IdempotencyKey: "report:" + strconv.FormatInt(id, 10), MaxAttempts: 3})
		if err != nil {
			return err
		}
		out.JobID = &job.ID
		if err := tx.db.Model(&ReportRecord{}).Where("organization_id=? AND id=?", t.orgID, id).Update("job_id", job.ID).Error; err != nil {
			return err
		}
		receipt = reportReceipt{t.orgID, actor.ActorID, key, requestHash, in.RunID, in.AnalysisRevision, id}
		if err := tx.db.Create(&receipt).Error; err != nil {
			return err
		}
		return t.store.appendAudit(tx.ctx, tx.db, t.orgID, auditObject("report.create", "report", id), nil)
	})
	return out, reportError(err)
}
