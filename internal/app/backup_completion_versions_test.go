package app

import (
	"errors"
	"os"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Inventory identities are deliberately synthetic, just like the common
// completion fixture. This verifies the actual v2/v3 archive/manifest/receipt
// integration, not acquisition or restoration of these historical SQL rows.
func TestBackupArchiveCompletionScopedAndLegacyManifestVersions(t *testing.T) {
	for _, mode := range []string{"v2", "v3", "v3_empty_replaced"} {
		t.Run(mode, func(t *testing.T) {
			for _, driver := range []string{"sqlite", "postgres"} {
				t.Run(driver, func(t *testing.T) {
					f := newBackupCompletionFixture(t, driver)
					org := f.manifest.AuditAnchors[0].OrganizationID
					f.manifest.SchemaVersion = backupmanifest.VersionV2
					for i := range f.manifest.Artifacts {
						a := &f.manifest.Artifacts[i]
						if a.Category == "rule" || a.Category == "template" {
							a.Scope, a.OrganizationID, a.ID = backupmanifest.ArtifactScopeOrganization, org, int64(i+1)
						} else {
							a.Scope = backupmanifest.ArtifactScopeInstalled
						}
					}
					wantEntries := 7
					if mode != "v2" {
						f.manifest.SchemaVersion = backupmanifest.VersionV3
						for i, state := range []string{backupmanifest.LegacyReportFileObserved, backupmanifest.LegacyReportFileMissing, backupmanifest.LegacyReportFileUnmapped} {
							row := backupmanifest.LegacyReport{ID: int64(i + 1), OrganizationID: org, RunID: 1, AnalysisRevision: 1, Revision: 1, RowVersion: backupmanifest.LegacyReportRowVersion, RowSHA256: backupCompletionDigest([]byte("explicit synthetic historical row: " + state)), Verification: backupmanifest.LegacyReportUnverified, FileState: state}
							if state == backupmanifest.LegacyReportFileObserved {
								row.ObservedFile = &backupmanifest.File{EntryID: "legacy-empty", SHA256: backupCompletionDigest(nil)}
								f.body["legacy-empty"] = nil // Actual authenticated zero-byte entry.
							}
							f.manifest.LegacyReports = append(f.manifest.LegacyReports, row)
						}
						wantEntries++ // Missing/unmapped never manufacture archive files.
					}
					encoded, sum, err := backupmanifest.Encode(f.manifest)
					if err != nil {
						t.Fatal("versioned manifest fixture", err)
					}
					f.body["backup-manifest"] = encoded
					f.scope = secret.BackupScope{BackupID: f.manifest.BackupID, ManifestHash: sum}
					if mode == "v3_empty_replaced" {
						f.body["legacy-empty"] = []byte("not the observed empty file")
					}
					f.publish(t, "") // Independently verifies complete authentic AEAD.
					if f.sealed.Entries != wantEntries {
						t.Fatal("legacy missing/unmapped entries were materialized")
					}
					got, err := f.finish()
					if mode == "v3_empty_replaced" {
						if !errors.Is(err, errBackupArchiveReadback) || got != (repository.BackupCompletionReceipt{}) {
							t.Fatal("authenticated replacement of observed empty file accepted", err)
						}
						f.assertNotReady(t)
					} else {
						if err != nil || got.ManifestVersion != f.manifest.SchemaVersion || got.ManifestSHA256 != sum || got.Entries != wantEntries {
							t.Fatal("original versioned manifest facts not bound to completion", err)
						}
						read, err := f.app.store.ReadBackupCompletion(f.ctx, f.auth, f.manifest.BackupID)
						if err != nil || read != got {
							t.Fatal("versioned durable receipt differs", err)
						}
					}
					if _, err := os.Stat(f.path()); err != nil {
						t.Fatal("versioned archive was deleted")
					}
				})
			}
		})
	}
}
