package repository

import (
	"encoding/json"
	"math"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

// TargetRecord never contains credentials, custom header values or ciphertext.
// Services project it into explicit public DTOs or detached runtime snapshots.
type TargetRecord struct {
	ID                  int64
	OrganizationID      int64
	ProviderID          *int64
	ModelProfileID      *int64
	Name                string
	Endpoint            string
	EndpointFingerprint string `json:"-"`
	Protocol            string
	Model               string
	Environment         string
	ChannelID           string
	TagsJSON            string
	AuthType            string
	AuthHeaderName      string `json:"-"`
	SecretID            int64
	OptionsJSON         string
	Status              string
	Version             int64
	CreatedBy           int64
	UpdatedBy           int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           *time.Time
}

func (TargetRecord) TableName() string { return "integrity_targets" }

type TargetState struct {
	Target TargetRecord
	Secret SecretMetadata
}

type targetJoined struct {
	TargetRecord
	CredentialVersion   int64
	CredentialLastFour  string
	CredentialRotatedAt *time.Time
}

func (record targetJoined) state() TargetState {
	return TargetState{record.TargetRecord, SecretMetadata{record.SecretID, record.CredentialVersion, secretMask(record.CredentialLastFour), record.CredentialRotatedAt}}
}

func (t *Tenant) targetQuery() *gorm.DB {
	return t.store.db.WithContext(t.ctx).Table("integrity_targets AS target").
		Select("target.*, secret.secret_version AS credential_version, secret.last_four AS credential_last_four, secret.rotated_at AS credential_rotated_at").
		Joins("JOIN integrity_secrets AS secret ON secret.organization_id = target.organization_id AND secret.id = target.secret_id AND secret.deleted_at IS NULL").
		Where("target.organization_id = ? AND target.deleted_at IS NULL", t.orgID)
}

func (t *Tenant) GetTarget(id int64) (TargetState, error) {
	var record targetJoined
	err := t.targetQuery().Where("target.id = ?", id).Take(&record).Error
	if err != nil {
		return TargetState{}, persistenceError(err)
	}
	return record.state(), nil
}

// Target list selects only bounded target configuration and credential metadata;
// it never loads large Secret payloads, sample data or any historical Run JSON.
func (t *Tenant) ListTargets(options ListOptions) ([]TargetState, error) {
	options = options.normalized()
	var records []targetJoined
	err := t.targetQuery().Where("target.id > ?", options.AfterID).Order("target.id").Limit(options.Limit).Scan(&records).Error
	if err != nil {
		return nil, persistenceError(err)
	}
	result := make([]TargetState, len(records))
	for i, record := range records {
		result[i] = record.state()
	}
	return result, nil
}

func validTargetRecord(record TargetRecord, orgID int64) bool {
	return (record.OrganizationID == 0 || record.OrganizationID == orgID) &&
		(record.ProviderID == nil || *record.ProviderID > 0) && (record.ModelProfileID == nil || *record.ModelProfileID > 0) &&
		strings.TrimSpace(record.Name) != "" && len(record.Name) <= 512 && len(record.Endpoint) > 0 && len(record.Endpoint) <= 4096 &&
		len(record.EndpointFingerprint) == 64 && record.Protocol == "openai_chat" && strings.TrimSpace(record.Model) != "" && len(record.Model) <= 512 &&
		(record.AuthType == "bearer" || record.AuthType == "custom_header") && len(record.AuthHeaderName) <= 128 &&
		len(record.Environment) <= 256 && len(record.ChannelID) <= 512 && len(record.TagsJSON) <= 16<<10 && json.Valid([]byte(record.TagsJSON)) &&
		len(record.OptionsJSON) <= 4096 && json.Valid([]byte(record.OptionsJSON)) && (record.Status == "active" || record.Status == "disabled")
}

func (t *Tenant) targetActor() (int64, error) {
	if err := t.store.auditReady(t.ctx); err != nil {
		return 0, err
	}
	actor, err := audit.ActorFromContext(t.ctx)
	if err != nil || actor.ActorID <= 0 {
		return 0, audit.ErrActorRequired
	}
	return actor.ActorID, nil
}

func (t *Tenant) checkTargetReferences(tx *gorm.DB, record TargetRecord) error {
	providerID := record.ProviderID
	// Discover a profile's parent before taking locks, then recheck it after
	// provider -> model SHARE locks. An intervening parent edit fails closed.
	if record.ModelProfileID != nil {
		var parent struct{ ProviderID int64 }
		if err := tx.Model(&ModelProfile{}).Select("provider_id").Where("organization_id = ? AND id = ? AND deleted_at IS NULL", t.orgID, *record.ModelProfileID).Take(&parent).Error; err != nil {
			return err
		}
		if providerID == nil {
			providerID = &parent.ProviderID
		}
	}
	if providerID != nil {
		if _, err := t.store.catalogProviderLock(tx, t.orgID, *providerID, true, "SHARE"); err != nil {
			return err
		}
	}
	if record.ModelProfileID != nil {
		profile, err := t.store.catalogModelLock(tx, t.orgID, *record.ModelProfileID, "SHARE")
		if err != nil {
			return err
		}
		if profile.Status != "active" {
			return ErrNotFound
		}
		if profile.Protocol != record.Protocol || profile.ProviderID != *providerID {
			return ErrConflict
		}
	}
	return nil
}

// CreateTargetWithSecret commits the already-encrypted record, target and both
// audit events atomically. Encryption intentionally happens before this method.
func (t *Tenant) CreateTargetWithSecret(record TargetRecord, credential SecretRecord) (TargetState, error) {
	actor, err := t.targetActor()
	if err != nil {
		return TargetState{}, err
	}
	if !validTargetRecord(record, t.orgID) || !validSecretRecord(credential, t.orgID) || credential.SecretVersion != 1 {
		return TargetState{}, ErrConfiguration
	}
	if record.ID != 0 || record.SecretID != 0 {
		return TargetState{}, ErrConfiguration
	}
	id, err := NewID()
	if err != nil {
		return TargetState{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	record.ID, record.OrganizationID, record.SecretID, record.Version = id, t.orgID, credential.ID, 1
	record.CreatedBy, record.UpdatedBy, record.CreatedAt, record.UpdatedAt, record.DeletedAt = actor, actor, now, now, nil
	credential.CreatedAt, credential.RotatedAt, credential.DeletedAt = now, nil, nil
	err = t.controlTransaction("target.write", func(tx *gorm.DB) error {
		if err := t.checkTargetReferences(tx, record); err != nil {
			return err
		}
		if err := tx.Create(&credential).Error; err != nil {
			return err
		}
		if err := tx.Create(&record).Error; err != nil {
			return err
		}
		if err := t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("secret.create", "secret", credential.ID), nil); err != nil {
			return err
		}
		return t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("target.create", "target", record.ID), nil)
	})
	if err != nil {
		return TargetState{}, managementError(err)
	}
	return TargetState{record, SecretMetadata{credential.ID, 1, secretMask(credential.LastFour), nil}}, nil
}

func (t *Tenant) lockedTarget(tx *gorm.DB, id, version int64) (TargetRecord, error) {
	var record TargetRecord
	if id <= 0 || version <= 0 || version >= math.MaxInt32 {
		return record, ErrConflict
	}
	err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Where("organization_id = ? AND id = ? AND deleted_at IS NULL", t.orgID, id).First(&record).Error
	if err != nil {
		return record, err
	}
	if record.Version != version {
		return TargetRecord{}, ErrConflict
	}
	return record, nil
}

// UpdateTarget is a complete validated configuration replacement with a CAS.
// Secret references and authentication are deliberately not patchable here.
func (t *Tenant) UpdateTarget(id, expectedVersion int64, replacement TargetRecord) (TargetState, error) {
	actor, err := t.targetActor()
	if err != nil {
		return TargetState{}, err
	}
	if !validTargetRecord(replacement, t.orgID) {
		return TargetState{}, ErrConfiguration
	}
	var result TargetState
	err = t.controlTransaction("target.write", func(tx *gorm.DB) error {
		current, err := t.lockedTarget(tx, id, expectedVersion)
		if err != nil {
			return err
		}
		if err := t.checkTargetReferences(tx, replacement); err != nil {
			return err
		}
		if replacement.AuthType != current.AuthType || replacement.AuthHeaderName != current.AuthHeaderName || (replacement.SecretID != 0 && replacement.SecretID != current.SecretID) {
			return ErrConflict
		}
		replacement.ID, replacement.OrganizationID, replacement.SecretID = current.ID, t.orgID, current.SecretID
		replacement.CreatedBy, replacement.CreatedAt = current.CreatedBy, current.CreatedAt
		replacement.UpdatedBy, replacement.UpdatedAt, replacement.Version = actor, time.Now().UTC().Truncate(time.Microsecond), expectedVersion+1
		replacement.DeletedAt = nil
		changed := tx.Model(&TargetRecord{}).Where("organization_id = ? AND id = ? AND version = ? AND deleted_at IS NULL", t.orgID, id, expectedVersion).
			Select("provider_id", "model_profile_id", "name", "endpoint", "endpoint_fingerprint", "protocol", "model", "environment", "channel_id", "tags_json", "options_json", "status", "version", "updated_by", "updated_at").Updates(&replacement)
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrConflict
		}
		if err := t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("target.update", "target", id), nil); err != nil {
			return err
		}
		var metadata SecretRecord
		if err := tx.Select("id", "secret_version", "last_four", "rotated_at").Where("organization_id = ? AND id = ? AND deleted_at IS NULL", t.orgID, current.SecretID).First(&metadata).Error; err != nil {
			return err
		}
		result = TargetState{replacement, SecretMetadata{metadata.ID, metadata.SecretVersion, secretMask(metadata.LastFour), metadata.RotatedAt}}
		return nil
	})
	if err != nil {
		return TargetState{}, managementError(err)
	}
	return result, nil
}

func (t *Tenant) ReplaceTargetSecret(id, expectedTargetVersion, expectedSecretVersion int64, authType, headerName string, replacement SecretRecord) (TargetState, error) {
	actor, err := t.targetActor()
	if err != nil {
		return TargetState{}, err
	}
	if expectedSecretVersion <= 0 || expectedSecretVersion >= math.MaxInt32 || !validSecretRecord(replacement, t.orgID) || replacement.SecretVersion != expectedSecretVersion+1 ||
		(authType != "bearer" && authType != "custom_header") || len(headerName) > 128 || (authType == "bearer" && headerName != "") || (authType == "custom_header" && headerName == "") {
		return TargetState{}, ErrConfiguration
	}
	var result TargetState
	err = t.controlTransaction("secret.replace", func(tx *gorm.DB) error {
		current, err := t.lockedTarget(tx, id, expectedTargetVersion)
		if err != nil {
			return err
		}
		if current.SecretID != replacement.ID {
			return ErrConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		replacement.RotatedAt = &now
		changed := tx.Model(&SecretRecord{}).Where("organization_id = ? AND id = ? AND secret_version = ? AND deleted_at IS NULL", t.orgID, replacement.ID, expectedSecretVersion).
			Select("encrypted_data_key", "ciphertext", "nonce", "key_version", "payload_key_version", "secret_version", "fingerprint", "last_four", "rotated_at").Updates(&replacement)
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrConflict
		}
		changed = tx.Model(&TargetRecord{}).Where("organization_id = ? AND id = ? AND version = ? AND deleted_at IS NULL", t.orgID, id, expectedTargetVersion).
			Updates(map[string]any{"auth_type": authType, "auth_header_name": headerName, "version": expectedTargetVersion + 1, "updated_by": actor, "updated_at": now})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrConflict
		}
		if err := t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("secret.rotate", "secret", replacement.ID), nil); err != nil {
			return err
		}
		if err := t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("target.rotate_secret", "target", id), nil); err != nil {
			return err
		}
		current.AuthType, current.AuthHeaderName, current.Version, current.UpdatedBy, current.UpdatedAt = authType, headerName, expectedTargetVersion+1, actor, now
		result = TargetState{current, SecretMetadata{replacement.ID, replacement.SecretVersion, secretMask(replacement.LastFour), &now}}
		return nil
	})
	if err != nil {
		return TargetState{}, managementError(err)
	}
	return result, nil
}

// DeleteTarget refuses unfinished runs. The run creation transaction must lock
// this same target row before validating active/not-deleted (see README).
// Ciphertext/DEK references are cleared now, not deferred to retention cleanup.
func (t *Tenant) DeleteTarget(id, expectedVersion int64) error {
	actor, err := t.targetActor()
	if err != nil {
		return err
	}
	return t.controlTransaction("target.delete", func(tx *gorm.DB) error {
		current, err := t.lockedTarget(tx, id, expectedVersion)
		if err != nil {
			return err
		}
		var active int64
		if err := tx.Table("integrity_runs").Where("organization_id = ? AND target_id = ? AND execution_closed_at IS NULL", t.orgID, id).Count(&active).Error; err != nil {
			return err
		}
		if active != 0 {
			return ErrConflict
		}
		// A prematurely closed Run must not hide a queued/leased call. Read only
		// the jobs that can plan/execute its outbound work; report-only jobs are
		// allowed to keep consuming immutable history after target deletion.
		var activeJobs int64
		if err := tx.Table("integrity_jobs AS job").Where("job.organization_id = ? AND job.status IN ('pending', 'running')", t.orgID).
			Where(`(job.type IN (?, ?) AND EXISTS (SELECT 1 FROM integrity_runs AS run WHERE run.organization_id = job.organization_id AND run.id = job.object_id AND run.target_id = ?)) OR
				(job.type = ? AND EXISTS (SELECT 1 FROM integrity_logical_samples AS sample JOIN integrity_runs AS run ON run.organization_id = sample.organization_id AND run.id = sample.run_id WHERE sample.organization_id = job.organization_id AND sample.id = job.object_id AND run.target_id = ?)) OR
				(job.type = ? AND EXISTS (SELECT 1 FROM integrity_target_prechecks AS precheck WHERE precheck.organization_id = job.organization_id AND precheck.id = job.object_id AND precheck.target_id = ?))`,
				string(JobRunPlan), string(JobRunAnalyze), id, string(JobSampleExecute), id, string(JobTargetPrecheck), id).Count(&activeJobs).Error; err != nil {
			return err
		}
		if activeJobs != 0 {
			return ErrConflict
		}
		// Defensive refusal if legacy data shares one credential between targets.
		var others int64
		if err := tx.Model(&TargetRecord{}).Where("organization_id = ? AND secret_id = ? AND id <> ? AND deleted_at IS NULL", t.orgID, current.SecretID, id).Count(&others).Error; err != nil {
			return err
		}
		if others != 0 {
			return ErrConflict
		}
		now := time.Now().UTC().Truncate(time.Microsecond)
		changed := tx.Model(&TargetRecord{}).Where("organization_id = ? AND id = ? AND version = ? AND deleted_at IS NULL", t.orgID, id, expectedVersion).
			Updates(map[string]any{"deleted_at": now, "updated_at": now, "updated_by": actor, "version": expectedVersion + 1, "status": "disabled"})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrConflict
		}
		changed = tx.Model(&SecretRecord{}).Where("organization_id = ? AND id = ? AND deleted_at IS NULL", t.orgID, current.SecretID).
			Updates(map[string]any{"deleted_at": now, "encrypted_data_key": []byte{}, "ciphertext": []byte{}, "nonce": []byte{}, "fingerprint": "", "last_four": ""})
		if changed.Error != nil {
			return changed.Error
		}
		if changed.RowsAffected != 1 {
			return ErrConflict
		}
		if err := t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("secret.destroy", "secret", current.SecretID), nil); err != nil {
			return err
		}
		return t.store.appendAudit(t.ctx, tx, t.orgID, auditObject("target.delete", "target", id), nil)
	})
}

// LockTargetForRun joins the run/job transaction's serialization boundary with
// edits, rotation and deletion. The capability must be consumed within that
// transaction; committing a Run from Service.Snapshot alone is not safe.
func (tx *TenantTransaction) LockTargetForRun(id, expectedVersion int64) (TargetState, error) {
	if tx.closed.Load() {
		return TargetState{}, ErrTransactionClosed
	}
	tenant := &Tenant{store: tx.store, ctx: tx.ctx, orgID: tx.orgID}
	record, err := tenant.lockedTarget(tx.db, id, expectedVersion)
	if err != nil {
		return TargetState{}, persistenceError(err)
	}
	if record.Status != "active" {
		return TargetState{}, ErrConflict
	}
	var metadata SecretRecord
	if err := tx.db.Select("id", "secret_version", "last_four", "rotated_at").Where("organization_id = ? AND id = ? AND deleted_at IS NULL", tx.orgID, record.SecretID).First(&metadata).Error; err != nil {
		return TargetState{}, persistenceError(err)
	}
	return TargetState{record, SecretMetadata{metadata.ID, metadata.SecretVersion, secretMask(metadata.LastFour), metadata.RotatedAt}}, nil
}
