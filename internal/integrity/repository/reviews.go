package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"gorm.io/gorm"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// ReviewRecord is human-authored history, never an algorithm score or an
// approval of a software release. Explanation is deliberately excluded from
// default marshaling/logging; only the explicit authorized HTTP DTO exposes it.
type ReviewRecord struct {
	ID, OrganizationID, RunID int64
	AnalysisRevision          int
	Conclusion                string
	Explanation               string `json:"-"`
	CreatedBy                 int64
	CreatedAt                 time.Time
}

func (ReviewRecord) TableName() string { return "integrity_reviews" }

type reviewReceipt struct {
	OrganizationID, CreatedBy   int64
	RequestKeyHash, RequestHash string
	RunID                       int64
	AnalysisRevision            int
	ReviewID                    int64
}

func (reviewReceipt) TableName() string { return "integrity_review_receipts" }

// ReviewInput contains no actor, timestamp, score, approval or report fields.
type ReviewInput struct {
	RunID                                   int64
	AnalysisRevision                        int
	PreviousReviewID                        int64
	Conclusion, Explanation, IdempotencyKey string
}

func ValidReviewText(value string) bool {
	if !utf8.ValidString(value) || len(value) > 4096 || strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) && r != '\n' && r != '\t' || unicode.In(r, unicode.Cf) {
			return false
		}
	}
	return true
}
func validReviewConclusion(value string) bool {
	return slices.Contains([]string{"confirmed", "false_positive", "watch", "not_applicable"}, value)
}
func ValidReviewInput(input ReviewInput) bool {
	if input.RunID <= 0 || input.AnalysisRevision < 1 || input.AnalysisRevision > 2147483647 || input.PreviousReviewID < 0 || !validReviewConclusion(input.Conclusion) || !ValidReviewText(input.Explanation) || len(input.IdempotencyKey) < 16 || len(input.IdempotencyKey) > 128 {
		return false
	}
	for _, r := range input.IdempotencyKey {
		allowed := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r)
		if !allowed {
			return false
		}
	}
	return true
}
func reviewHash(input ReviewInput) string {
	// Fixed struct field order and a separate domain; keys are retry identities,
	// not authentication. The actor/org are additionally bound by the SQL key.
	raw, _ := json.Marshal(struct {
		RunID       int64  `json:"run_id"`
		Revision    int    `json:"analysis_revision"`
		Previous    int64  `json:"previous_review_id"`
		Conclusion  string `json:"conclusion"`
		Explanation string `json:"explanation"`
	}{input.RunID, input.AnalysisRevision, input.PreviousReviewID, input.Conclusion, input.Explanation})
	digest := sha256.Sum256(append([]byte("mii.review.request.v1\x00"), raw...))
	return hex.EncodeToString(digest[:])
}
func reviewColumns(tx *gorm.DB) string {
	return "id,organization_id,run_id,analysis_revision,created_by,created_at," + readBoundedText(tx, "conclusion", "conclusion", 32) + "," + readBoundedText(tx, "explanation", "explanation", 4096)
}
func validReviewRecord(row ReviewRecord, org, run int64, revision int) bool {
	return row.ID > 0 && row.OrganizationID == org && row.RunID == run && row.AnalysisRevision == revision && row.CreatedBy > 0 && !row.CreatedAt.IsZero() && validReviewConclusion(row.Conclusion) && ValidReviewText(row.Explanation)
}
func publishedReviewScope(tx *gorm.DB, org, run int64, revision int) error {
	var count int64
	if err := tx.Table("integrity_run_results").Where("organization_id=? AND run_id=? AND analysis_revision=? AND is_published=?", org, run, revision, true).Count(&count).Error; err != nil {
		return err
	}
	if count != 1 {
		return ErrNotFound
	}
	return nil
}

// AppendReview atomically rechecks the persisted reviewer, optimistic latest
// identity, immutable result revision and audit. It never updates result rows.
func (t *Tenant) AppendReview(input ReviewInput) (ReviewRecord, error) {
	if !ValidReviewInput(input) {
		return ReviewRecord{}, ErrConfiguration
	}
	var out ReviewRecord
	err := t.controlTransaction("review.write", func(tx *gorm.DB) error {
		actor, err := audit.ActorFromContext(t.ctx)
		if err != nil {
			return err
		}
		permissions, err := managementPermissions(tx, t.orgID, actor.ActorID)
		if err != nil {
			return err
		}
		if !slices.Contains(permissions, "run.read") {
			return ErrManagementPermission
		}
		if err := publishedReviewScope(tx, t.orgID, input.RunID, input.AnalysisRevision); err != nil {
			return err
		}
		key := sha256.Sum256([]byte(input.IdempotencyKey))
		receipt := reviewReceipt{}
		err = tx.Select("review_id,run_id,analysis_revision,"+readBoundedText(tx, "request_hash", "request_hash", 64)).Where("organization_id=? AND created_by=? AND request_key_hash=?", t.orgID, actor.ActorID, hex.EncodeToString(key[:])).Take(&receipt).Error
		if err == nil {
			if receipt.RunID != input.RunID || receipt.AnalysisRevision != input.AnalysisRevision || receipt.RequestHash != reviewHash(input) {
				return ErrConflict
			}
			if err := tx.Select(reviewColumns(tx)).Where("organization_id=? AND run_id=? AND analysis_revision=? AND id=?", t.orgID, input.RunID, input.AnalysisRevision, receipt.ReviewID).Take(&out).Error; err != nil {
				return err
			}
			if !validReviewRecord(out, t.orgID, input.RunID, input.AnalysisRevision) {
				return ErrUnavailable
			}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		var latest ReviewRecord
		err = tx.Select("id,created_at").Where("organization_id=? AND run_id=? AND analysis_revision=?", t.orgID, input.RunID, input.AnalysisRevision).Order("created_at DESC,id DESC").Take(&latest).Error
		if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if latest.ID != input.PreviousReviewID {
			return ErrConflict
		}
		id, err := NewID()
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		if !now.After(latest.CreatedAt) {
			now = latest.CreatedAt.Add(time.Microsecond)
		}
		out = ReviewRecord{ID: id, OrganizationID: t.orgID, RunID: input.RunID, AnalysisRevision: input.AnalysisRevision, Conclusion: input.Conclusion, Explanation: input.Explanation, CreatedBy: actor.ActorID, CreatedAt: now}
		if err := tx.Create(&out).Error; err != nil {
			return err
		}
		receipt = reviewReceipt{OrganizationID: t.orgID, CreatedBy: actor.ActorID, RequestKeyHash: hex.EncodeToString(key[:]), RequestHash: reviewHash(input), RunID: input.RunID, AnalysisRevision: input.AnalysisRevision, ReviewID: id}
		if err := tx.Create(&receipt).Error; err != nil {
			return err
		}
		return t.store.appendAudit(t.ctx, tx, t.orgID, AuditCommand{Action: "review.append", ObjectType: "review", ObjectID: strconv.FormatInt(id, 10), Result: input.Conclusion}, nil)
	})
	if err != nil {
		return ReviewRecord{}, err
	}
	return out, nil
}

// ListReviews uses the same read-only snapshot as authorized result reads.
// Immutable cursor anchors survive later appends. No request or response body
// nor mutable username is loaded into human review history.
func (t *Tenant) ListReviews(run int64, revision int, page ListOptions) ([]ReviewRecord, error) {
	if run <= 0 || revision < 1 || revision > 2147483647 || page.AfterID < 0 || page.Limit < 1 || page.Limit > 100 {
		return nil, ErrConfiguration
	}
	rows := []ReviewRecord{}
	err := t.resultReadTransaction(false, func(tx *gorm.DB) error {
		if err := publishedReviewScope(tx, t.orgID, run, revision); err != nil {
			return err
		}
		query := tx.Table("integrity_reviews").Select(reviewColumns(tx)).Where("organization_id=? AND run_id=? AND analysis_revision=?", t.orgID, run, revision)
		if page.AfterID != 0 {
			var anchor ReviewRecord
			if err := tx.Select("id,created_at").Where("organization_id=? AND run_id=? AND analysis_revision=? AND id=?", t.orgID, run, revision, page.AfterID).Take(&anchor).Error; err != nil {
				return err
			}
			query = query.Where("created_at<? OR (created_at=? AND id<?)", anchor.CreatedAt, anchor.CreatedAt, anchor.ID)
		}
		if err := query.Order("created_at DESC,id DESC").Limit(page.Limit).Find(&rows).Error; err != nil {
			return err
		}
		for _, row := range rows {
			if !validReviewRecord(row, t.orgID, run, revision) {
				return ErrUnavailable
			}
		}
		return nil
	})
	if err != nil {
		return nil, managementError(err)
	}
	return rows, nil
}
