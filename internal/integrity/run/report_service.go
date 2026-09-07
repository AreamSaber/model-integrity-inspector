package run

import (
	"context"
	"strconv"
	"sync"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/reportstorage"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

type ReportConfig struct {
	Store   *repository.Store
	Storage *reportstorage.Store
	Ready   func(context.Context) bool
}
type ReportService struct {
	cfg       ReportConfig
	downloads chan struct{}
}

func NewReportService(cfg ReportConfig) (*ReportService, error) {
	if cfg.Store == nil || cfg.Storage == nil {
		return nil, ErrInvalid
	}
	return &ReportService{cfg: cfg, downloads: make(chan struct{}, 4)}, nil
}

type ReportView struct {
	ID               string    `json:"id"`
	RunID            string    `json:"run_id"`
	AnalysisRevision int       `json:"analysis_revision"`
	Revision         int       `json:"revision"`
	Format           string    `json:"format"`
	SchemaVersion    string    `json:"schema_version"`
	Status           string    `json:"status"`
	ContentHash      *string   `json:"content_hash,omitempty"`
	FileHash         *string   `json:"file_hash,omitempty"`
	FileSize         *int64    `json:"file_size,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	ErrorCode        *string   `json:"error_code,omitempty"`
	ReviewState      string    `json:"review_state"`
}

func reportView(row repository.ReportRecord) ReportView {
	v := ReportView{ID: decimal(row.ID), RunID: decimal(row.RunID), AnalysisRevision: row.AnalysisRevision, Revision: row.Revision, Format: row.FormatName, SchemaVersion: row.SchemaVersion, Status: row.Status, ContentHash: row.ContentHash, FileSize: row.FileSize, CreatedAt: row.CreatedAt, ErrorCode: row.ErrorCode, ReviewState: "not_included"}
	if row.FileHash != nil {
		hash := "sha256:" + *row.FileHash
		v.FileHash = &hash
	}
	return v
}
func (s *ReportService) tenant(ctx context.Context, org int64) (*repository.Tenant, error) {
	if s == nil {
		return nil, ErrExecutionNotReady
	}
	return s.cfg.Store.WithOrganization(ctx, org)
}
func (s *ReportService) Create(ctx context.Context, org int64, input repository.ReportInput) (ReportView, error) {
	tenant, err := s.tenant(ctx, org)
	if err != nil {
		return ReportView{}, err
	}
	if s.cfg.Ready == nil || !s.cfg.Ready(ctx) {
		return ReportView{}, ErrExecutionNotReady
	}
	row, err := tenant.CreateReport(input)
	if err != nil {
		return ReportView{}, err
	}
	return reportView(row), nil
}
func (s *ReportService) Get(ctx context.Context, org, id int64) (ReportView, error) {
	tenant, err := s.tenant(ctx, org)
	if err != nil {
		return ReportView{}, err
	}
	row, err := tenant.GetReport(id)
	if err != nil {
		return ReportView{}, err
	}
	return reportView(row), nil
}
func (s *ReportService) List(ctx context.Context, org, runID int64, revision int, page repository.ListOptions) ([]ReportView, error) {
	tenant, err := s.tenant(ctx, org)
	if err != nil {
		return nil, err
	}
	rows, err := tenant.ListReports(runID, revision, page)
	if err != nil {
		return nil, err
	}
	out := make([]ReportView, 0, len(rows))
	for _, row := range rows {
		out = append(out, reportView(row))
	}
	return out, nil
}

// ReportDownload owns one bounded in-memory verified file and one concurrency
// slot. The handler must Close it and revalidate during a slow transfer.
type ReportDownload struct {
	view    ReportView
	ref     reportstorage.Reference
	data    []byte
	store   *repository.Store
	release func()
	once    sync.Once
}

func parseReportID(value string) (int64, bool) {
	n, err := strconv.ParseInt(value, 10, 64)
	return n, err == nil && n > 0 && strconv.FormatInt(n, 10) == value
}
func (d *ReportDownload) View() ReportView {
	if d == nil {
		return ReportView{}
	}
	return d.view
}
func (d *ReportDownload) Bytes() []byte {
	if d == nil {
		return nil
	}
	return append([]byte(nil), d.data...)
}
func (d *ReportDownload) Close() {
	if d != nil {
		d.once.Do(func() {
			d.data = nil
			if d.release != nil {
				d.release()
			}
		})
	}
}
func (d *ReportDownload) Revalidate(ctx context.Context) error {
	if d == nil || d.store == nil {
		return repository.ErrReportInvalid
	}
	id, ok := parseReportID(d.view.ID)
	if !ok {
		return repository.ErrReportInvalid
	}
	tenant, err := d.store.WithOrganization(ctx, d.ref.OrganizationID)
	if err != nil {
		return err
	}
	row, err := tenant.GetReport(id)
	if err != nil {
		return err
	}
	if row.Status != "ready" || row.FileHash == nil || *row.FileHash != d.ref.Hash || row.FileSize == nil || *row.FileSize != d.ref.Size {
		return repository.ErrReportInvalid
	}
	return nil
}
func (s *ReportService) PrepareDownload(ctx context.Context, org, id int64) (*ReportDownload, error) {
	tenant, err := s.tenant(ctx, org)
	if err != nil {
		return nil, err
	}
	select {
	case s.downloads <- struct{}{}:
	default:
		return nil, repository.ErrReportLimit
	}
	success := false
	defer func() {
		if !success {
			<-s.downloads
		}
	}()
	row, err := tenant.GetReport(id)
	if err != nil {
		return nil, err
	}
	if row.Status != "ready" {
		return nil, repository.ErrReportNotReady
	}
	ref := reportstorage.Reference{OrganizationID: org, Hash: *row.FileHash, Format: row.FormatName, Size: *row.FileSize}
	data, err := s.cfg.Storage.Read(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := tenant.AuditReportDownload(id, ref.Hash, ref.Size); err != nil {
		return nil, err
	}
	success = true
	return &ReportDownload{view: reportView(row), ref: ref, data: data, store: s.cfg.Store, release: func() { <-s.downloads }}, nil
}
