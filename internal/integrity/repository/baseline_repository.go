package repository

import (
	"context"
	"crypto/hmac"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func baselineError(err error) error {
	for _, known := range []error{ErrBaselineInvalid, ErrBaselineIntegrity, ErrBaselineState, ErrBaselineSource, ErrBaselineExpired} {
		if errors.Is(err, known) {
			return known
		}
	}
	return managementError(err)
}
func (b *BaselineRepository) tenant(ctx context.Context, orgID int64) (*Tenant, error) {
	if err := b.store.RequireControlAuthority(ctx, orgID); err != nil {
		return nil, err
	}
	return b.store.WithOrganization(ctx, orgID)
}

// Reads authorize and assemble the record in one non-writer-blocking snapshot.
// The concrete callers supply fixed permissions; there is no exported generic
// SQL callback or caller-selected permission capability.
func (b *BaselineRepository) read(t *Tenant, source bool, fn func(*gorm.DB) error) error {
	auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
	read := func(tx *gorm.DB) error {
		var user User
		if err := tx.Select("id,must_change_password,password_changed_at,"+readBoundedText(tx, "status", "status", 16)).Where("id=?", auth.UserID).Take(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		var session Session
		if err := tx.Select("id,created_at,expires_at,revoked_at").Where("id=? AND user_id=?", auth.SessionID, auth.UserID).Take(&session).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrManagementSession
			}
			return err
		}
		if user.Status != "active" || session.RevokedAt != nil || !session.ExpiresAt.After(time.Now()) || session.CreatedAt.Before(user.PasswordChangedAt) {
			return ErrManagementSession
		}
		if user.MustChangePassword {
			return ErrPasswordChangeRequired
		}
		codes, err := baselineReadGrants(tx, t.orgID, auth.UserID)
		if err != nil {
			return err
		}
		if !slices.Contains(codes, "baseline.read") || source && (!slices.Contains(codes, "run.read") || !slices.Contains(codes, "evidence.read")) {
			return ErrManagementPermission
		}
		return fn(tx)
	}
	var err error
	if b.store.driver == "postgres" {
		err = b.store.db.WithContext(t.ctx).Transaction(read, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	} else {
		err = b.store.db.WithContext(t.ctx).Connection(func(conn *gorm.DB) error {
			conn = conn.Session(&gorm.Session{NewDB: true})
			if err := conn.Exec("BEGIN DEFERRED").Error; err != nil {
				return err
			}
			committed := false
			defer func() {
				if !committed {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.ctx), 2*time.Second)
					defer cancel()
					_ = conn.WithContext(cleanup).Exec("ROLLBACK").Error
				}
			}()
			if err := read(conn); err != nil {
				return err
			}
			if err := conn.Exec("COMMIT").Error; err != nil {
				return err
			}
			committed = true
			return nil
		})
	}
	return baselineError(err)
}
func (b *BaselineRepository) write(t *Tenant, permission string, fn func(*gorm.DB) error) error {
	auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
	var operationErr error
	err := b.store.managementTransaction(t.ctx, auth, t.orgID, permission, true, func(tx *gorm.DB, _ User) error { operationErr = fn(tx); return operationErr })
	if operationErr != nil {
		return baselineError(operationErr)
	}
	return baselineError(err)
}

func baselineColumns(tx *gorm.DB) string {
	cols := "id,organization_id,run_id,analysis_revision,reviewed_by,created_at,reviewed_at,expires_at,version,created_by,updated_at,retired_at"
	for _, f := range []struct {
		name  string
		limit int
	}{{"name", 128}, {"model", 128}, {"protocol", 32}, {"status", 16}, {"source", 16}, {"region", 64}, {"source_manifest_hash", 64}, {"source_result_hash", 64}, {"parameters_hash", 64}, {"snapshot_hash", 64}, {"snapshot_json", 200 << 10}, {"applicable_scope_json", 256}, {"approval_key_version", 64}, {"approval_mac", 64}, {"review_explanation", 1024}, {"retirement_reason", 256}} {
		cols += "," + readBoundedText(tx, f.name, f.name, f.limit)
	}
	return cols
}
func baselineCanonical(r BaselineRecord) ([]byte, error) {
	r.ApprovalMAC = nil
	raw, err := json.Marshal(struct {
		Purpose                                  string
		Record                                   BaselineRecord
		Snapshot, KeyVersion, Review, Retirement string
	}{"mii.baseline.record.v1", r, r.SnapshotJSON, valueString(r.ApprovalKeyVersion), r.ReviewExplanation, r.RetirementReason})
	if err != nil || len(raw) > 256<<10 {
		return nil, ErrBaselineIntegrity
	}
	return raw, nil
}
func valueString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func (b *BaselineRepository) seal(r *BaselineRecord) error {
	version := b.signer.ActiveVersion()
	r.ApprovalKeyVersion = &version
	raw, err := baselineCanonical(*r)
	if err != nil {
		return err
	}
	mac, err := b.signer.BaselineMAC(version, raw)
	if err != nil || len(mac) != 32 {
		return ErrBaselineIntegrity
	}
	encoded := hex.EncodeToString(mac)
	r.ApprovalMAC = &encoded
	return nil
}
func (b *BaselineRepository) verify(r BaselineRecord) error {
	if r.ID <= 0 || r.CreatedBy == nil || *r.CreatedBy <= 0 || r.Version < 1 || r.ApprovalKeyVersion == nil || r.ApprovalMAC == nil || len(*r.ApprovalMAC) != 64 || baselineHash([]byte(r.SnapshotJSON)) != r.SnapshotHash || !slices.Contains([]string{"draft", "approved", "retired"}, r.Status) {
		return ErrBaselineIntegrity
	}
	raw, err := baselineCanonical(r)
	if err != nil {
		return err
	}
	provided, err := hex.DecodeString(*r.ApprovalMAC)
	if err != nil {
		return ErrBaselineIntegrity
	}
	expected, err := b.signer.BaselineMAC(*r.ApprovalKeyVersion, raw)
	if err != nil || len(expected) != 32 || !hmac.Equal(expected, provided) {
		return ErrBaselineIntegrity
	}
	return nil
}
func (b *BaselineRepository) load(tx *gorm.DB, orgID, id int64, lock bool) (BaselineRecord, error) {
	var r BaselineRecord
	q := tx.Model(&BaselineRecord{}).Select(baselineColumns(tx)).Where("organization_id=? AND id=?", orgID, id)
	if lock && b.store.driver == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "UPDATE"})
	}
	if err := q.Take(&r).Error; err != nil {
		return r, err
	}
	return r, b.verify(r)
}
func (b *BaselineRepository) Get(ctx context.Context, orgID, id int64) (BaselineRecord, error) {
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return BaselineRecord{}, err
	}
	var out BaselineRecord
	err = b.read(t, false, func(tx *gorm.DB) error { var e error; out, e = b.load(tx, orgID, id, false); return e })
	return out, err
}
func (b *BaselineRepository) List(ctx context.Context, orgID int64, p BaselineList) ([]BaselineRecord, error) {
	if p.AfterID < 0 || p.Limit < 1 || p.Limit > 100 || !validManagementText(p.Query, 128, false) || !slices.Contains([]string{"", "draft", "approved", "expired", "retired"}, p.Status) {
		return nil, ErrBaselineInvalid
	}
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := []BaselineRecord{}
	err = b.read(t, false, func(tx *gorm.DB) error {
		q := tx.Model(&BaselineRecord{}).Select(baselineColumns(tx)).Where("organization_id=? AND id>?", orgID, p.AfterID)
		now := time.Now().UTC()
		if p.Status == "expired" {
			q = q.Where("status<>'retired' AND expires_at<=?", now)
		} else if p.Status != "" {
			q = q.Where("status=?", p.Status)
			if p.Status != "retired" {
				q = q.Where("expires_at>?", now)
			}
		}
		if p.Query != "" {
			q = q.Where("LOWER(name) LIKE ? ESCAPE '!'", managementLike(p.Query))
		}
		if err := q.Order("id").Limit(p.Limit).Find(&out).Error; err != nil {
			return err
		}
		for _, r := range out {
			if err := b.verify(r); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

func (b *BaselineRepository) source(tx *gorm.DB, orgID, runID int64, revision int, lock bool) (*BaselineSource, error) {
	var r RunRecord
	q := tx.Model(&RunRecord{}).Select("id,organization_id,target_id,version,created_at,execution_closed_at,"+readBoundedText(tx, "status", "status", 32)+","+readBoundedText(tx, "manifest_hash", "manifest_hash", 64)+","+readBoundedText(tx, "config_snapshot", "config_snapshot", 8<<20)).Where("organization_id=? AND id=?", orgID, runID)
	if lock && b.store.driver == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "SHARE"})
	}
	if err := q.Take(&r).Error; err != nil {
		return nil, err
	}
	if !slices.Contains([]string{"COMPLETED", "PARTIAL", "REVIEW_REQUIRED"}, r.Status) || r.ExecutionClosedAt == nil {
		return nil, ErrBaselineSource
	}
	var result RunResultRecord
	columns := "organization_id,run_id,analysis_revision,is_published,created_at,prompt_risk,token_risk,response_risk,evidence_risk,overall_risk,confidence," + readBoundedText(tx, "conclusion_json", "conclusion_json", 4<<20)
	for _, field := range []string{"risk_level", "evidence_grade", "completeness"} {
		columns += "," + readBoundedText(tx, field, field, 64)
	}
	q = tx.Model(&RunResultRecord{}).Select(columns).Where("organization_id=? AND run_id=? AND analysis_revision=? AND is_published=?", orgID, runID, revision, true)
	if lock && b.store.driver == "postgres" {
		q = q.Clauses(clause.Locking{Strength: "SHARE"})
	}
	if err := q.Take(&result).Error; err != nil {
		return nil, err
	}
	var frozen executionSnapshot
	if json.Unmarshal([]byte(r.ConfigSnapshot), &frozen) != nil || len(result.ConclusionJSON) < 2 || frozen.Plan.Target.ID != r.TargetID || frozen.Plan.ManifestHash != r.ManifestHash || len(frozen.Plan.Manifest) == 0 {
		return nil, ErrBaselineSource
	}
	published := PublishedRead{Result: result, Samples: []ResultSampleRecord{}}
	if err := historyQuery(tx, orgID).Where("r.id=?", runID).Take(&published.Run).Error; err != nil {
		return nil, err
	}
	if err := tx.Table("integrity_logical_samples").Select("id,organization_id,run_id,probe_instance_id,ordinal,attempt_count,final_attempt_id,completed_at,"+readBoundedText(tx, "validity", "validity", 32)).Where("organization_id=? AND run_id=?", orgID, runID).Order("id").Limit(513).Scan(&published.Samples).Error; err != nil {
		return nil, err
	}
	if len(published.Samples) > 512 {
		return nil, ErrBaselineSource
	}
	bindings, err := json.Marshal(published)
	if err != nil {
		return nil, ErrBaselineSource
	}
	return &BaselineSource{store: b.store, organizationID: orgID, runID: runID, runVersion: r.Version, revision: revision, configHash: baselineHash([]byte(r.ConfigSnapshot)), resultHash: baselineHash([]byte(result.ConclusionJSON)), bindingHash: baselineHash(bindings), plan: frozen.Plan, result: published, createdAt: r.CreatedAt}, nil
}
func (b *BaselineRepository) Source(ctx context.Context, orgID, runID int64, revision int) (*BaselineSource, error) {
	if runID <= 0 || revision != 1 {
		return nil, ErrBaselineSource
	}
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return nil, err
	}
	var out *BaselineSource
	err = b.read(t, true, func(tx *gorm.DB) error { var e error; out, e = b.source(tx, orgID, runID, revision, false); return e })
	return out, err
}
func (b *BaselineRepository) recheckSource(tx *gorm.DB, t *Tenant, s *BaselineSource) error {
	if s == nil || s.store != b.store || s.organizationID != t.orgID {
		return ErrBaselineSource
	}
	current, err := b.source(tx, t.orgID, s.runID, s.revision, true)
	if err != nil {
		return err
	}
	if current.runVersion != s.runVersion || current.configHash != s.configHash || current.resultHash != s.resultHash || current.bindingHash != s.bindingHash {
		return ErrBaselineSource
	}
	return nil
}

func (b *BaselineRepository) Create(ctx context.Context, orgID int64, s *BaselineSource, scope BaselineScope, input BaselineMutation) (BaselineRecord, error) {
	if s == nil || scope.OrganizationID != orgID || scope.RunID != s.runID || scope.AnalysisRevision != s.revision || scope.ManifestHash != s.plan.ManifestHash || scope.ResultHash != s.resultHash || scope.Model != s.plan.Target.Model || scope.Protocol != s.plan.Target.Protocol || !validManagementText(input.Name, 128, true) || !validManagementText(input.Region, 64, false) || !slices.Contains([]string{"official", "historical"}, input.Source) || !input.ExpiresAt.After(time.Now()) || input.ExpiresAt.After(time.Now().Add(365*24*time.Hour)) {
		return BaselineRecord{}, ErrBaselineInvalid
	}
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return BaselineRecord{}, err
	}
	snapshot, err := baselineJSON(scope)
	if err != nil {
		return BaselineRecord{}, err
	}
	id, err := NewID()
	if err != nil {
		return BaselineRecord{}, ErrUnavailable
	}
	actor, _ := audit.ActorFromContext(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	r := BaselineRecord{ID: id, OrganizationID: orgID, RunID: s.runID, AnalysisRevision: s.revision, Name: strings.TrimSpace(input.Name), Model: scope.Model, Protocol: scope.Protocol, Status: "draft", ApplicableScopeJSON: `{"schema_version":"baseline.scope.v1"}`, CreatedAt: now, UpdatedAt: now, ExpiresAt: input.ExpiresAt.UTC().Truncate(time.Microsecond), Version: 1, CreatedBy: &actor.ActorID, Source: input.Source, Region: input.Region, SourceManifestHash: scope.ManifestHash, SourceResultHash: scope.ResultHash, ParametersHash: scope.ParametersHash, SnapshotJSON: snapshot, SnapshotHash: baselineHash([]byte(snapshot))}
	err = b.write(t, "baseline.write", func(tx *gorm.DB) error {
		if err := b.requireSourceGrants(tx, t); err != nil {
			return err
		}
		if err := b.recheckSource(tx, t, s); err != nil {
			return err
		}
		if err := b.seal(&r); err != nil {
			return err
		}
		if err := tx.Create(&r).Error; err != nil {
			return err
		}
		return b.store.appendAudit(ctx, tx, orgID, auditObject("baseline.create", "baseline", id), nil)
	})
	return r, err
}
func (b *BaselineRepository) requireSourceGrants(tx *gorm.DB, t *Tenant) error {
	auth := t.ctx.Value(controlAuthorityKey{}).(controlAuthority).identity
	codes, err := baselineReadGrants(tx, t.orgID, auth.UserID)
	if err != nil {
		return err
	}
	if !slices.Contains(codes, "run.read") || !slices.Contains(codes, "evidence.read") {
		return ErrManagementPermission
	}
	return nil
}

// The reader and source inspector transfer only these closed codes. Unrelated
// or corrupted grant metadata cannot introduce unbounded strings into a read.
func baselineReadGrants(tx *gorm.DB, orgID, userID int64) ([]string, error) {
	var codes []string
	err := tx.Raw(`SELECT permission_code FROM (
		SELECT rp.permission_code FROM role_permissions rp
		JOIN member_roles mr ON mr.organization_id=rp.organization_id AND mr.role_id=rp.role_id
		JOIN organization_members om ON om.organization_id=mr.organization_id AND om.id=mr.member_id
		JOIN organizations o ON o.id=om.organization_id
		WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active'
		AND rp.permission_code IN ('baseline.read','run.read','evidence.read')
		UNION
		SELECT mp.permission_code FROM member_permissions mp
		JOIN organization_members om ON om.organization_id=mp.organization_id AND om.id=mp.member_id
		JOIN organizations o ON o.id=om.organization_id
		WHERE om.organization_id=? AND om.user_id=? AND om.status='active' AND o.status='active'
		AND mp.permission_code IN ('baseline.read','run.read','evidence.read')
	) baseline_reader_permissions`, orgID, userID, orgID, userID).Scan(&codes).Error
	return codes, err
}
func (b *BaselineRepository) Update(ctx context.Context, orgID, id int64, version int, name *string, expiry *time.Time) (BaselineRecord, error) {
	if version < 1 || name == nil && expiry == nil || name != nil && !validManagementText(*name, 128, true) || expiry != nil && (!expiry.After(time.Now()) || expiry.After(time.Now().Add(365*24*time.Hour))) {
		return BaselineRecord{}, ErrBaselineInvalid
	}
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return BaselineRecord{}, err
	}
	var out BaselineRecord
	err = b.write(t, "baseline.write", func(tx *gorm.DB) error {
		r, e := b.load(tx, orgID, id, true)
		if e != nil {
			return e
		}
		if r.Version != version {
			return ErrConflict
		}
		if r.Status != "draft" {
			return ErrBaselineState
		}
		if r.Version == 2147483647 {
			return ErrBaselineState
		}
		if name != nil {
			r.Name = strings.TrimSpace(*name)
		}
		if expiry != nil {
			r.ExpiresAt = expiry.UTC().Truncate(time.Microsecond)
		}
		r.Version++
		r.UpdatedAt = time.Now().UTC().Truncate(time.Microsecond)
		if e := b.save(tx, &r, version); e != nil {
			return e
		}
		out = r
		return b.store.appendAudit(ctx, tx, orgID, auditObject("baseline.update", "baseline", id), nil)
	})
	return out, err
}
func (b *BaselineRepository) save(tx *gorm.DB, r *BaselineRecord, previous int) error {
	if err := b.seal(r); err != nil {
		return err
	}
	// Every timestamp is already canonicalized and MAC-bound. GORM must not
	// replace UpdatedAt after signing the record.
	result := tx.Session(&gorm.Session{SkipHooks: true}).Model(&BaselineRecord{}).Where("organization_id=? AND id=? AND version=?", r.OrganizationID, r.ID, previous).Select("*").Updates(r)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return ErrConflict
	}
	return nil
}
func (b *BaselineRepository) Approve(ctx context.Context, orgID, id int64, s *BaselineSource, scope BaselineScope, input BaselineApproval) (BaselineRecord, error) {
	if input.Version < 1 || !input.AcknowledgeDevelopmentLimits || !validManagementText(input.Reason, 256, true) || !validManagementText(input.BusinessReview, 512, false) {
		return BaselineRecord{}, ErrBaselineInvalid
	}
	if scope.ValidSamples < 6 || scope.OverallRisk == nil || scope.Completeness == "INSUFFICIENT" {
		return BaselineRecord{}, ErrBaselineSource
	}
	if *scope.OverallRisk >= 40 && !validManagementText(input.BusinessReview, 512, true) {
		return BaselineRecord{}, ErrBaselineInvalid
	}
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return BaselineRecord{}, err
	}
	var out BaselineRecord
	err = b.write(t, "baseline.approve", func(tx *gorm.DB) error {
		r, e := b.load(tx, orgID, id, true)
		if e != nil {
			return e
		}
		if r.Version != input.Version {
			return ErrConflict
		}
		if r.Status != "draft" || r.Version == 2147483647 {
			return ErrBaselineState
		}
		if !r.ExpiresAt.After(time.Now()) {
			return ErrBaselineExpired
		}
		if err := b.requireSourceGrants(tx, t); err != nil {
			return err
		}
		if err := b.recheckSource(tx, t, s); err != nil {
			return err
		}
		encoded, e := baselineJSON(scope)
		if e != nil || encoded != r.SnapshotJSON {
			return ErrBaselineSource
		}
		actor, _ := audit.ActorFromContext(ctx)
		now := time.Now().UTC().Truncate(time.Microsecond)
		r.Status = "approved"
		r.ReviewedBy = &actor.ActorID
		r.ReviewedAt = &now
		r.UpdatedAt = now
		r.ReviewExplanation = input.Reason + "\n" + input.BusinessReview
		r.Version++
		if e := b.save(tx, &r, input.Version); e != nil {
			return e
		}
		out = r
		return b.store.appendAudit(ctx, tx, orgID, auditObject("baseline.approve", "baseline", id), nil)
	})
	return out, err
}
func (b *BaselineRepository) Retire(ctx context.Context, orgID, id int64, version int, reason string) (BaselineRecord, error) {
	if version < 1 || !validManagementText(reason, 256, true) {
		return BaselineRecord{}, ErrBaselineInvalid
	}
	t, err := b.tenant(ctx, orgID)
	if err != nil {
		return BaselineRecord{}, err
	}
	var out BaselineRecord
	err = b.write(t, "baseline.approve", func(tx *gorm.DB) error {
		r, e := b.load(tx, orgID, id, true)
		if e != nil {
			return e
		}
		if r.Version != version {
			return ErrConflict
		}
		if r.Status == "retired" || r.Version == 2147483647 {
			return ErrBaselineState
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		r.Status = "retired"
		r.RetiredAt = &now
		r.RetirementReason = reason
		r.UpdatedAt = now
		r.Version++
		if e := b.save(tx, &r, version); e != nil {
			return e
		}
		out = r
		return b.store.appendAudit(ctx, tx, orgID, auditObject("baseline.retire", "baseline", id), nil)
	})
	return out, err
}
