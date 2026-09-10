package backupmanifest

import "math"

const (
	VersionV3                = "mii.backup-manifest.v3"
	LegacyReportUnverified   = "legacy_unverified"
	LegacyReportRowVersion   = "mii.legacy-report-row.v1"
	LegacyReportFileObserved = "observed"
	LegacyReportFileMissing  = "missing"
	LegacyReportFileUnmapped = "unmapped"
)

// LegacyReport preserves a retained report that lacks the modern immutable
// publication protocol. Its exact nullable row (including original format,
// schema, storage locator and declared hashes) remains in the database snapshot.
// RowSHA256 commits to that original row under RowVersion, NOT a regenerated
// report or invented source hash. The snapshot/restore coordinator must produce
// and verify that commitment from the same database image; this package checks
// only its structure. No raw locator, body or unknown metadata enters a manifest.
//
// ObservedFile describes bytes actually found through an approved, bounded,
// no-follow legacy layout mapping. It attests transport consistency, not report
// provenance. Missing means a recognized location was absent; Unmapped means no
// approved mapping exists. Neither may invent an empty file. An observed empty
// file is distinct from both. All states remain unverified and grant no download,
// execution, scoring, re-signing or activation authority.
type LegacyReport struct {
	ID               int64  `json:"id"`
	OrganizationID   int64  `json:"organization_id"`
	RunID            int64  `json:"run_id"`
	AnalysisRevision int64  `json:"analysis_revision"`
	Revision         int64  `json:"revision"`
	RowVersion       string `json:"row_version"`
	RowSHA256        string `json:"row_sha256"`
	Verification     string `json:"verification"`
	FileState        string `json:"file_state"`
	ObservedFile     *File  `json:"observed_file,omitempty"`
}

func validLegacyReports(m Manifest, organizations map[int64]bool, add func(File, bool) bool) bool {
	if m.SchemaVersion != VersionV3 {
		return len(m.LegacyReports) == 0
	}
	ids := make(map[int64]bool, len(m.Reports)+len(m.LegacyReports))
	for _, report := range m.Reports {
		ids[report.ID] = true
	}
	for _, r := range m.LegacyReports {
		if r.ID <= 0 || ids[r.ID] || !organizations[r.OrganizationID] || r.RunID <= 0 ||
			r.AnalysisRevision < 1 || r.AnalysisRevision > math.MaxInt32 || r.Revision < 1 || r.Revision > math.MaxInt32 ||
			r.RowVersion != LegacyReportRowVersion || !hash(r.RowSHA256) || r.Verification != LegacyReportUnverified {
			return false
		}
		ids[r.ID] = true
		switch r.FileState {
		case LegacyReportFileObserved:
			if r.ObservedFile == nil || !add(*r.ObservedFile, true) {
				return false
			}
		case LegacyReportFileMissing, LegacyReportFileUnmapped:
			if r.ObservedFile != nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}
