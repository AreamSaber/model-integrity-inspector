package backupmanifest_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/backupmanifest"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// Compose the public manifest and crypto APIs from an external test package:
// secret depends on repository, which consumes backupmanifest in production.
// Only the shared synthetic fixture is bridged through an internal _test.go.
func integrationDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestManifestPreservesRealTemplateRegistryVersions(t *testing.T) {
	for _, length := range []int{66, 128} {
		b := templates.Builtin()
		b.Version = "1.0.0-" + strings.Repeat("a", length-6)
		registry := templates.NewRegistry()
		sha, err := registry.Add(b)
		if err != nil {
			t.Fatal("actual template version contract", err)
		}
		retained, gotHash, err := registry.Get(b.Version)
		if err != nil || gotHash != sha {
			t.Fatal("actual retained template lookup", err)
		}
		data, _, err := retained.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		m := backupmanifest.TestOnlyFixture()
		m.Artifacts[2] = backupmanifest.Artifact{Category: "template", Version: retained.Version,
			File: backupmanifest.File{EntryID: "template-v1", Bytes: int64(len(data)), SHA256: sha}}
		encoded, sum, err := backupmanifest.Encode(m)
		if err != nil {
			t.Fatal("backup cannot retain a real supported version", err)
		}
		decoded, err := backupmanifest.Decode(encoded, m.BackupID, sum)
		if err != nil || decoded.Artifacts[2].Version != retained.Version {
			t.Fatal("template version altered", err)
		}
	}
	m := backupmanifest.TestOnlyFixture()
	m.Artifacts[0].Version = strings.Repeat("a", 129)
	if _, _, err := backupmanifest.Encode(m); err == nil {
		t.Fatal("artifact version limit lost")
	}
	m = backupmanifest.TestOnlyFixture()
	m.KeyVersions[1] = strings.Repeat("a", 65)
	if _, _, err := backupmanifest.Encode(m); err == nil {
		t.Fatal("artifact fix expanded key version contract")
	}
}

// Synthetic file payloads exercise the actual archive crypto and every planned
// entry kind. These are not database snapshots or real audit-chain verification.
func TestManifestPlanBindsActualAuthenticatedArchive(t *testing.T) {
	for _, m := range []backupmanifest.Manifest{backupmanifest.TestOnlyFixture(), backupmanifest.TestOnlyScopedFixture(), backupmanifest.TestOnlyLegacyFixture()} {
		// Use the actual fixed-column digest protocol for legacy rows in the
		// authenticated archive composition. This is still synthetic row input;
		// only the repository's later SQL adapter can prove snapshot acquisition.
		for i := range m.LegacyReports {
			m.LegacyReports[i].RowSHA256 = integrationLegacyRowDigest(t, m.LegacyReports[i], false, "2026-09-10 09:00:00.123456789+08:00")
		}
		t.Run(m.SchemaVersion, func(t *testing.T) { manifestPlanBindsActualAuthenticatedArchive(t, m) })
	}
}

func integrationLegacyRowDigest(t *testing.T, entry backupmanifest.LegacyReport, presentSource bool, timestamp string) string {
	t.Helper()
	text := func(raw string) backupmanifest.LegacyReportRowText {
		return backupmanifest.LegacyReportRowText{Present: true, Bytes: int64(len(raw)), Reader: strings.NewReader(raw)}
	}
	row := backupmanifest.LegacyReportRow{DatabaseDriver: "sqlite", ID: entry.ID, OrganizationID: entry.OrganizationID,
		RunID: entry.RunID, AnalysisRevision: entry.AnalysisRevision, Revision: entry.Revision,
		ReportFormat: text("historical-format"), SchemaVersion: text("historical-schema"), Status: text("ready"),
		CreatedAt: backupmanifest.LegacyReportRowTime(text(timestamp))}
	if presentSource {
		row.SourceJSON = text("") // Present empty TEXT is NOT historical SQL NULL.
	}
	sum, err := backupmanifest.DigestLegacyReportRow(t.Context(), row, backupmanifest.LegacyReportRowLimits{MaxBytes: 64 << 10, Timeout: time.Second})
	if err != nil {
		t.Fatal("actual legacy row digest failed", err)
	}
	return sum
}

func TestManifestV3ActualRowNullAndTimestampChangesBreakPinnedIdentity(t *testing.T) {
	m := backupmanifest.TestOnlyLegacyFixture()
	m.LegacyReports[0].RowSHA256 = integrationLegacyRowDigest(t, m.LegacyReports[0], false, "2026-09-10 09:00:00.123456789+08:00")
	_, original, err := backupmanifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name, timestamp string
		presentSource   bool
	}{
		{"null_to_empty", "2026-09-10 09:00:00.123456789+08:00", true},
		{"offset", "2026-09-10 09:00:00.123456789+07:00", false},
		{"nanosecond", "2026-09-10 09:00:00.123456788+08:00", false},
	} {
		t.Run(change.name, func(t *testing.T) {
			next := backupmanifest.TestOnlyLegacyFixture()
			next.LegacyReports[0].RowSHA256 = integrationLegacyRowDigest(t, next.LegacyReports[0], change.presentSource, change.timestamp)
			data, changed, err := backupmanifest.Encode(next)
			if err != nil || changed == original || next.LegacyReports[0].RowSHA256 == m.LegacyReports[0].RowSHA256 {
				t.Fatal("raw row difference lost in manifest identity", err)
			}
			if _, err := backupmanifest.Decode(data, m.BackupID, original); !errors.Is(err, backupmanifest.ErrMismatch) {
				t.Fatal("changed original row accepted against pinned manifest", err)
			}
		})
	}
}

func manifestPlanBindsActualAuthenticatedArchive(t *testing.T, m backupmanifest.Manifest) {
	t.Helper()
	payloads := map[string][]byte{}
	set := func(f *backupmanifest.File) {
		payloads[f.EntryID] = []byte("synthetic-payload-for-" + f.EntryID)
		f.Bytes = int64(len(payloads[f.EntryID]))
		f.SHA256 = integrationDigest(payloads[f.EntryID])
	}
	set(&m.Database.File)
	set(&m.ConfigTemplate)
	for i := range m.Reports {
		set(&m.Reports[i].File)
	}
	for i := range m.Artifacts {
		set(&m.Artifacts[i].File)
	}
	for i := range m.LegacyReports {
		if f := m.LegacyReports[i].ObservedFile; f != nil {
			if f.Bytes == 0 {
				payloads[f.EntryID] = nil
				f.SHA256 = integrationDigest(nil)
			} else {
				set(f)
			}
		}
	}
	data, sum, err := backupmanifest.Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	payloads["backup-manifest"] = data
	entries, err := backupmanifest.Entries(m)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := secret.NewKeyRing("key-v2", map[string][]byte{"key-v2": bytes.Repeat([]byte{0x29}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	sealer, opener, err := ring.NewBackupCapabilities()
	if err != nil {
		t.Fatal(err)
	}
	scope := secret.BackupScope{BackupID: m.BackupID, ManifestHash: sum}
	limits := secret.BackupLimits{MaxBytes: 1 << 20, MaxEntries: backupmanifest.MaxEntries, Timeout: time.Second}
	modes := []string{"valid", "changed_payload", "missing_entry", "extra_entry", "wrong_kind", "swapped_artifact"}
	if m.SchemaVersion == backupmanifest.VersionV3 {
		modes = append(modes, "changed_legacy", "missing_legacy", "nonempty_legacy_empty")
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			var archive bytes.Buffer
			_, err := sealer.Seal(t.Context(), scope, limits, &archive, func(_ context.Context, w *secret.BackupArchiveWriter) error {
				for _, entry := range entries {
					if mode == "missing_entry" && entry.Kind == "config" {
						continue
					}
					if mode == "missing_legacy" && entry.File.EntryID == "legacy-report-21" {
						continue
					}
					kind := entry.Kind
					payload := payloads[entry.File.EntryID]
					if mode == "changed_legacy" && entry.File.EntryID == "legacy-report-21" || mode == "nonempty_legacy_empty" && entry.File.EntryID == "legacy-report-24" {
						payload = []byte("different-but-authenticated-legacy-bytes")
					}
					if mode == "changed_payload" && entry.Kind == "database" {
						payload = []byte("different-but-authenticated")
					}
					if mode == "swapped_artifact" && entry.File.EntryID == "rule-v1" {
						otherID := "scoring-v1"
						if m.SchemaVersion != backupmanifest.Version {
							otherID = "rule-org9"
						}
						payload = payloads[otherID]
					}
					if mode == "wrong_kind" && entry.Kind == "database" {
						kind = "report"
					}
					if err := w.WriteEntry(secret.BackupEntry{Kind: kind, ID: entry.File.EntryID}, func(_ context.Context, out io.Writer) error { _, err := out.Write(payload); return err }); err != nil {
						return err
					}
				}
				if mode == "extra_entry" {
					return w.WriteEntry(secret.BackupEntry{Kind: "config", ID: "unlisted"}, func(_ context.Context, out io.Writer) error { _, err := out.Write([]byte("extra")); return err })
				}
				return nil
			})
			if err != nil {
				t.Fatal("actual encryption failed", err)
			}
			// The AEAD archive is deliberately valid in ALL cases: integrity of
			// archive framing alone cannot prove the manifest's exact file set.
			seen := map[string]bool{}
			mismatch := false
			_, err = opener.Open(t.Context(), scope, limits, bytes.NewReader(archive.Bytes()), func(_ context.Context, entry secret.BackupEntry, in io.Reader) error {
				plain, err := io.ReadAll(io.LimitReader(in, 1<<20))
				if err != nil {
					return err
				}
				var matched bool
				for _, want := range entries {
					if want.File.EntryID == entry.ID {
						matched = true
						if seen[entry.ID] || want.Kind != entry.Kind || want.File.Bytes != int64(len(plain)) || want.File.SHA256 != integrationDigest(plain) {
							mismatch = true
						}
					}
				}
				if !matched {
					mismatch = true
				}
				seen[entry.ID] = true
				if entry.Kind == "manifest" {
					if _, err := backupmanifest.Decode(plain, m.BackupID, sum); err != nil {
						mismatch = true
					}
				}
				return nil
			})
			if err != nil {
				t.Fatal("fixture should have authenticated complete framing", err)
			}
			if len(seen) != len(entries) {
				mismatch = true
			}
			if mismatch != (mode != "valid") {
				t.Fatal("manifest plan did not distinguish a valid archive from inconsistent inventory")
			}
			// Independently exercise the production streaming verifier. The
			// preceding pass proves every fixture has valid AEAD framing; this
			// pass must reject the inconsistent inventory without buffering files.
			verified := backupmanifest.VerifyStream(t.Context(), m, time.Second, func(ctx context.Context, accept func(string, string, io.Reader) error) error {
				_, err := opener.Open(ctx, scope, limits, bytes.NewReader(archive.Bytes()), func(_ context.Context, entry secret.BackupEntry, in io.Reader) error {
					return accept(entry.Kind, entry.ID, in)
				})
				return err
			})
			if mode == "valid" && verified != nil || mode != "valid" && !errors.Is(verified, backupmanifest.ErrMismatch) {
				t.Fatal("production inventory verifier disagreed with independent oracle", verified)
			}
			if mode == "valid" {
				for _, damaged := range [][]byte{append(bytes.Clone(archive.Bytes()), 1), bytes.Clone(archive.Bytes()[:archive.Len()-1])} {
					accepted := 0
					verified = backupmanifest.VerifyStream(t.Context(), m, time.Second, func(ctx context.Context, accept func(string, string, io.Reader) error) error {
						_, err := opener.Open(ctx, scope, limits, bytes.NewReader(damaged), func(_ context.Context, entry secret.BackupEntry, in io.Reader) error {
							if err := accept(entry.Kind, entry.ID, in); err != nil {
								return err
							}
							accepted++
							return nil
						})
						return err
					})
					if accepted != len(entries) || !errors.Is(verified, backupmanifest.ErrCallback) {
						t.Fatal("complete valid inventory concealed failed archive end/outer EOF", accepted, verified)
					}
				}
			}
		})
	}
}

func FuzzManifestDecode(f *testing.F) {
	valid, _, err := backupmanifest.Encode(backupmanifest.TestOnlyFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	scoped, _, err := backupmanifest.Encode(backupmanifest.TestOnlyScopedFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(scoped)
	legacy, _, err := backupmanifest.Encode(backupmanifest.TestOnlyLegacyFixture())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(legacy)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"backup_id":91,"backup_id":91}`))
	f.Add(append(bytes.Clone(valid), ' '))
	f.Add([]byte(`{"backup_id":91,"reports":[` + strings.Repeat(`{},`, backupmanifest.MaxEntries) + `{}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 256<<10 {
			t.Skip("bounded parser fuzz input")
		}
		got, err := backupmanifest.Decode(data, 91, integrationDigest(data))
		if (bytes.Equal(data, valid) || bytes.Equal(data, scoped) || bytes.Equal(data, legacy)) && err != nil {
			t.Fatal("valid seed rejected", err)
		}
		if err != nil {
			if err != backupmanifest.ErrInvalid && err != backupmanifest.ErrLimit && err != backupmanifest.ErrMismatch { //nolint:errorlint // Exact closed sentinel: no wrapped input or parser details.
				t.Fatal("unclassified error")
			}
			return
		}
		encoded, sum, err := backupmanifest.Encode(got)
		if err != nil || !bytes.Equal(encoded, data) || sum != integrationDigest(data) {
			t.Fatal("successful decode is not canonical", err)
		}
		if _, err := backupmanifest.Entries(got); err != nil {
			t.Fatal("accepted manifest cannot form a bounded archive", err)
		}
	})
}
