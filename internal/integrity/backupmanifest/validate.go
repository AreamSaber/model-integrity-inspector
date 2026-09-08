package backupmanifest

import (
	"math"
	"regexp"
	"slices"
)

var (
	identifier      = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	version         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	artifactVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	migrationName   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	dbVersion       = regexp.MustCompile(`^[0-9]{1,3}(\.[0-9]{1,3}){1,3}$`)
)

func hash(value string) bool { return hexDigest(value, 64) }
func hexDigest(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, b := range value {
		if (b < '0' || b > '9') && (b < 'a' || b > 'f') {
			return false
		}
	}
	return true
}

func bounded(m Manifest) error {
	if len(m.Migrations) > MaxMigrations || len(m.Reports) > MaxEntries-3 || len(m.Artifacts) > MaxEntries-3 || len(m.Reports)+len(m.Artifacts) > MaxEntries-3 || len(m.KeyVersions) > 64 || len(m.AuditAnchors) > MaxOrganizations || len(m.Jobs) > MaxOrganizations {
		return ErrLimit
	}
	return nil
}

func validate(m Manifest) error {
	const lastMicrosecond int64 = 253402300799999999
	if m.SchemaVersion != Version || m.BackupID <= 0 || m.StartedAtMicros <= 0 || m.SnapshotAtMicros < m.StartedAtMicros || m.SnapshotAtMicros > lastMicrosecond || !version.MatchString(m.ApplicationVersion) || !hexDigest(m.SourceCommit, 40) && !hexDigest(m.SourceCommit, 64) || m.AuditHistory != "complete" {
		return ErrInvalid
	}
	if !dbVersion.MatchString(m.Database.ServerVersion) || m.Database.File.EntryID != "database-snapshot" || m.ConfigTemplate.EntryID != "config-template" {
		return ErrInvalid
	}
	if (m.Database.Driver != "sqlite" || m.Database.SnapshotMethod != "sqlite_online_backup") && (m.Database.Driver != "postgres" || m.Database.SnapshotMethod != "pg_dump_snapshot") {
		return ErrInvalid
	}
	if len(m.Migrations) == 0 || len(m.KeyVersions) == 0 || len(m.AuditAnchors) == 0 || len(m.Jobs) != len(m.AuditAnchors) {
		return ErrInvalid
	}
	for i, row := range m.Migrations {
		if row.Version != i+1 || !migrationName.MatchString(row.Name) || !hash(row.SHA256) {
			return ErrInvalid
		}
	}
	for i, key := range m.KeyVersions {
		if !version.MatchString(key) || i > 0 && key == m.KeyVersions[i-1] {
			return ErrInvalid
		}
	}
	organizations := make(map[int64]bool, len(m.AuditAnchors))
	for i, anchor := range m.AuditAnchors {
		if anchor.OrganizationID <= 0 || organizations[anchor.OrganizationID] || anchor.EventCount < 0 || anchor.CanonicalizationVersion != "mii.audit.v1" {
			return ErrInvalid
		}
		if anchor.EventCount == 0 {
			if anchor.EndHash != "" || anchor.KeyVersion != "" && !slices.Contains(m.KeyVersions, anchor.KeyVersion) {
				return ErrInvalid
			}
		} else if !hash(anchor.EndHash) || !slices.Contains(m.KeyVersions, anchor.KeyVersion) {
			return ErrInvalid
		}
		organizations[anchor.OrganizationID] = true
		job := m.Jobs[i]
		if job.OrganizationID != anchor.OrganizationID || !validJobs(job) {
			return ErrInvalid
		}
	}
	ids := map[string]bool{"backup-manifest": true}
	var total int64
	add := func(f File) bool {
		if !identifier.MatchString(f.EntryID) || ids[f.EntryID] || f.Bytes < 1 || f.Bytes > MaxFileBytes || !hash(f.SHA256) || total > MaxFileBytes-f.Bytes {
			return false
		}
		ids[f.EntryID] = true
		total += f.Bytes
		return true
	}
	if !add(m.Database.File) || !add(m.ConfigTemplate) {
		return ErrInvalid
	}
	for i, r := range m.Reports {
		if r.ID <= 0 || i > 0 && r.ID == m.Reports[i-1].ID || !organizations[r.OrganizationID] || r.RunID <= 0 || r.AnalysisRevision < 1 || r.AnalysisRevision > math.MaxInt32 || r.Revision < 1 || r.Revision > math.MaxInt32 || !slices.Contains([]string{"json", "html", "pdf", "csv"}, r.Format) || r.SchemaVersion != "mii.report.v1" || !hash(r.ContentSHA256) || !hash(r.SourceSHA256) || !add(r.File) {
			return ErrInvalid
		}
	}
	categories := map[string]bool{}
	for i, a := range m.Artifacts {
		if !slices.Contains([]string{"rule", "template", "tokenizer", "scoring"}, a.Category) || !artifactVersion.MatchString(a.Version) || i > 0 && a.Category == m.Artifacts[i-1].Category && a.Version == m.Artifacts[i-1].Version || !add(a.File) {
			return ErrInvalid
		}
		categories[a.Category] = true
	}
	if len(categories) != 4 {
		return ErrInvalid
	}
	return nil
}

// Only called after validate has proved the non-manifest sum cannot overflow.
func inventoryBytes(m Manifest) int64 {
	total := m.Database.File.Bytes + m.ConfigTemplate.Bytes
	for _, r := range m.Reports {
		total += r.File.Bytes
	}
	for _, a := range m.Artifacts {
		total += a.File.Bytes
	}
	return total
}

func validJobs(j JobSummary) bool {
	if j.Running != 0 || j.DispatchedAttempts != 0 || j.UncertainAttempts < 0 {
		return false
	}
	var total int64
	for _, n := range []int64{j.Pending, j.Running, j.Completed, j.Failed, j.Cancelled} {
		if n < 0 || total > math.MaxInt64-n {
			return false
		}
		total += n
	}
	return true
}
