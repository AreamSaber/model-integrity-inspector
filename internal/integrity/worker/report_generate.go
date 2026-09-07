package worker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"model-integrity-inspector.local/mii/internal/integrity/report"
	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

type ReportConfig struct{ Storage *reportstorage.Store }

func NewReportHandler(cfg ReportConfig) (Handler, error) {
	if cfg.Storage == nil {
		return nil, ErrConfiguration
	}
	return func(ctx context.Context, execution Execution) (Completion, error) {
		if execution.Queue == nil || repository.JobType(execution.Lease.Job.Type) != repository.JobReportGenerate {
			return nil, repository.ErrJobInvalid
		}
		source, err := execution.Queue.LoadReportSource(ctx, execution.Lease)
		if err != nil {
			return nil, err
		}
		snapshot, encoded, err := runservice.BuildReportSnapshot(source)
		if err != nil {
			return nil, err
		}
		if err := execution.Queue.FreezeReportSource(ctx, execution.Lease, source, encoded); err != nil {
			return nil, err
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		artifacts, err := report.Generate(snapshot)
		if err != nil {
			return nil, err
		}
		scope := source.Scope()
		content := artifacts.JSON()
		expected := artifacts.JSONFileHash()
		if scope.Format == "html" {
			content = artifacts.HTML()
			expected = artifacts.HTMLFileHash()
		}
		ref, err := cfg.Storage.Put(ctx, scope.OrganizationID, scope.Format, content)
		if err != nil {
			if errors.Is(err, reportstorage.ErrUnavailable) {
				return nil, repository.ErrUnavailable
			}
			return nil, err
		}
		if "sha256:"+ref.Hash != expected {
			return nil, repository.ErrReportInvalid
		}
		inputDigest := sha256.Sum256(encoded)
		inputHash := hex.EncodeToString(inputDigest[:])
		publication := repository.ReportPublication{ContentHash: artifacts.ContentHash(), FileHash: ref.Hash, FileSize: ref.Size}
		return func(tx *repository.TenantTransaction) error { return tx.PublishReport(source, inputHash, publication) }, nil
	}, nil
}
