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
		scope := source.Scope()
		artifact, err := generateReportArtifact(snapshot, scope.Format)
		if err != nil {
			return nil, err
		}
		ref, err := cfg.Storage.Put(ctx, scope.OrganizationID, scope.Format, artifact.content)
		if err != nil {
			if errors.Is(err, reportstorage.ErrUnavailable) {
				return nil, repository.ErrUnavailable
			}
			return nil, err
		}
		if "sha256:"+ref.Hash != artifact.fileHash {
			return nil, repository.ErrReportInvalid
		}
		inputDigest := sha256.Sum256(encoded)
		inputHash := hex.EncodeToString(inputDigest[:])
		publication := repository.ReportPublication{ContentHash: artifact.contentHash, FileHash: ref.Hash, FileSize: ref.Size}
		return func(tx *repository.TenantTransaction) error { return tx.PublishReport(source, inputHash, publication) }, nil
	}, nil
}

type reportArtifact struct {
	content               []byte
	contentHash, fileHash string
}

// Every report row retains its own frozen snapshot. CSV is generated directly
// from that snapshot, never by converting or overwriting a ready JSON/HTML row.
// The CSV profile does not replace the document's mii.report.v1 schema version.
func generateReportArtifact(snapshot *report.Snapshot, format string) (reportArtifact, error) {
	switch format {
	case "json", "html":
		artifacts, err := report.Generate(snapshot)
		if err != nil {
			return reportArtifact{}, err
		}
		if format == "json" {
			return reportArtifact{artifacts.JSON(), artifacts.ContentHash(), artifacts.JSONFileHash()}, nil
		}
		return reportArtifact{artifacts.HTML(), artifacts.ContentHash(), artifacts.HTMLFileHash()}, nil
	case "csv":
		artifact, err := report.GenerateCSV(snapshot)
		if err != nil {
			return reportArtifact{}, err
		}
		return reportArtifact{artifact.Bytes(), artifact.ContentHash(), artifact.FileHash()}, nil
	default:
		return reportArtifact{}, repository.ErrReportInvalid
	}
}
