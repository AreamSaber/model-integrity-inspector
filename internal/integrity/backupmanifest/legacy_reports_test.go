package backupmanifest

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func legacyFixture() Manifest {
	m := scopedFixture()
	m.SchemaVersion = VersionV3
	m.LegacyReports = []LegacyReport{
		{ID: 21, OrganizationID: 5, RunID: 6, AnalysisRevision: 1, Revision: 3,
			RowVersion: LegacyReportRowVersion, RowSHA256: strings.Repeat("1", 64), Verification: LegacyReportUnverified,
			FileState: LegacyReportFileObserved, ObservedFile: &File{"legacy-report-21", 19, strings.Repeat("2", 64)}},
		{ID: 22, OrganizationID: 9, RunID: 7, AnalysisRevision: 1, Revision: 1,
			RowVersion: LegacyReportRowVersion, RowSHA256: strings.Repeat("3", 64), Verification: LegacyReportUnverified,
			FileState: LegacyReportFileMissing},
		{ID: 23, OrganizationID: 9, RunID: 7, AnalysisRevision: 1, Revision: 2,
			RowVersion: LegacyReportRowVersion, RowSHA256: strings.Repeat("4", 64), Verification: LegacyReportUnverified,
			FileState: LegacyReportFileUnmapped},
		{ID: 24, OrganizationID: 9, RunID: 7, AnalysisRevision: 1, Revision: 3,
			RowVersion: LegacyReportRowVersion, RowSHA256: strings.Repeat("5", 64), Verification: LegacyReportUnverified,
			FileState: LegacyReportFileObserved, ObservedFile: &File{"legacy-report-24", 0, digest(nil)}},
	}
	return m
}

// Independently specified extension bytes, not serialized from production
// structs. The earlier v2 literal is also independently pinned by its old tests.
const legacyReportGolden = `,"legacy_reports":[{"id":21,"organization_id":5,"run_id":6,"analysis_revision":1,"revision":3,"row_version":"mii.legacy-report-row.v1","row_sha256":"1111111111111111111111111111111111111111111111111111111111111111","verification":"legacy_unverified","file_state":"observed","observed_file":{"entry_id":"legacy-report-21","bytes":19,"sha256":"2222222222222222222222222222222222222222222222222222222222222222"}},{"id":22,"organization_id":9,"run_id":7,"analysis_revision":1,"revision":1,"row_version":"mii.legacy-report-row.v1","row_sha256":"3333333333333333333333333333333333333333333333333333333333333333","verification":"legacy_unverified","file_state":"missing"},{"id":23,"organization_id":9,"run_id":7,"analysis_revision":1,"revision":2,"row_version":"mii.legacy-report-row.v1","row_sha256":"4444444444444444444444444444444444444444444444444444444444444444","verification":"legacy_unverified","file_state":"unmapped"},{"id":24,"organization_id":9,"run_id":7,"analysis_revision":1,"revision":3,"row_version":"mii.legacy-report-row.v1","row_sha256":"5555555555555555555555555555555555555555555555555555555555555555","verification":"legacy_unverified","file_state":"observed","observed_file":{"entry_id":"legacy-report-24","bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}]}`

func TestManifestV3IndependentCanonicalGolden(t *testing.T) {
	base := bytes.Replace(independentV2Golden(), []byte("mii.backup-manifest.v2"), []byte("mii.backup-manifest.v3"), 1)
	want := append(bytes.Clone(base[:len(base)-1]), []byte(legacyReportGolden)...)
	got, sum, err := Encode(legacyFixture())
	if err != nil || !bytes.Equal(got, want) || sum != digest(want) {
		t.Fatal("legacy wire differs from independent exact-field golden", err)
	}
	if _, err := Decode(want, 91, digest(want)); err != nil {
		t.Fatal("independent v3 golden rejected", err)
	}
}

func TestManifestV3LegacyReportsPreserveStatesAndOriginalVersions(t *testing.T) {
	// Both previously published encodings must remain byte-for-byte unchanged.
	for _, old := range []struct {
		m    Manifest
		want []byte
	}{{fixture(), []byte(manifestV1Golden)}, {scopedFixture(), independentV2Golden()}} {
		data, sum, err := Encode(old.m)
		if err != nil || !bytes.Equal(data, old.want) {
			t.Fatal("historical canonical manifest changed", err)
		}
		if _, err := Decode(data, old.m.BackupID, sum); err != nil {
			t.Fatal("historical decoder compatibility lost", err)
		}
	}
	m := legacyFixture()
	data, sum, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data, m.BackupID, sum)
	if err != nil || !reflect.DeepEqual(decoded, canonical(m)) {
		t.Fatal("legacy nullable file state or original identity changed", err)
	}
	if bytes.Contains(data, []byte(`"source_sha256":""`)) || bytes.Contains(data, []byte(`"observed_file":null`)) {
		t.Fatal("fabricated source or noncanonical absent-file representation")
	}
	entries, err := Entries(decoded)
	if err != nil || len(entries) != 3+len(m.Reports)+len(m.Artifacts)+2 {
		t.Fatal("missing/unmapped rows fabricated archive files", err)
	}
	for _, e := range entries {
		if e.File.EntryID == "legacy-report-24" && (e.Kind != "report" || e.File.Bytes != 0 || e.File.SHA256 != digest(nil)) {
			t.Fatal("observed empty file is not independently represented")
		}
	}
	slices.Reverse(m.LegacyReports)
	before := *m.LegacyReports[0].ObservedFile
	data2, sum2, err := Encode(m)
	if err != nil || !bytes.Equal(data, data2) || sum != sum2 || *m.LegacyReports[0].ObservedFile != before || m.LegacyReports[0].ID != 24 {
		t.Fatal("canonicalization mutated caller or changed order", err)
	}
	owned := canonical(m)
	m.LegacyReports[0].ObservedFile.SHA256 = strings.Repeat("a", 64)
	if owned.LegacyReports[3].ObservedFile.SHA256 != digest(nil) {
		t.Fatal("nested observed file still aliases caller")
	}
	// An archive with no legacy reports uses the same optional omission rule.
	m.LegacyReports = nil
	data, sum, err = Encode(m)
	if err != nil || bytes.Contains(data, []byte(`"legacy_reports"`)) {
		t.Fatal("empty extension is not canonical", err)
	}
	if _, err := Decode(data, m.BackupID, sum); err != nil {
		t.Fatal(err)
	}
}

func TestManifestV3LegacyReportsRejectTrustPromotionAndAmbiguity(t *testing.T) {
	for name, change := range map[string]func(*Manifest){
		"v1":                           func(m *Manifest) { m.SchemaVersion = Version },
		"v2":                           func(m *Manifest) { m.SchemaVersion = VersionV2 },
		"id":                           func(m *Manifest) { m.LegacyReports[0].ID = 0 },
		"modern_collision":             func(m *Manifest) { m.LegacyReports[0].ID = m.Reports[0].ID },
		"duplicate":                    func(m *Manifest) { m.LegacyReports[1].ID = m.LegacyReports[0].ID },
		"organization":                 func(m *Manifest) { m.LegacyReports[0].OrganizationID = 88 },
		"run":                          func(m *Manifest) { m.LegacyReports[0].RunID = 0 },
		"analysis":                     func(m *Manifest) { m.LegacyReports[0].AnalysisRevision = 0 },
		"revision":                     func(m *Manifest) { m.LegacyReports[0].Revision = math.MaxInt64 },
		"row_protocol":                 func(m *Manifest) { m.LegacyReports[0].RowVersion = "unknown" },
		"row_hash":                     func(m *Manifest) { m.LegacyReports[0].RowSHA256 = "" },
		"row_hash_upper":               func(m *Manifest) { m.LegacyReports[0].RowSHA256 = strings.Repeat("A", 64) },
		"trusted":                      func(m *Manifest) { m.LegacyReports[0].Verification = "verified" },
		"empty_verification":           func(m *Manifest) { m.LegacyReports[0].Verification = "" },
		"state":                        func(m *Manifest) { m.LegacyReports[0].FileState = "available" },
		"observed_without_file":        func(m *Manifest) { m.LegacyReports[0].ObservedFile = nil },
		"missing_with_file":            func(m *Manifest) { m.LegacyReports[0].FileState = LegacyReportFileMissing },
		"unmapped_with_file":           func(m *Manifest) { m.LegacyReports[0].FileState = LegacyReportFileUnmapped },
		"file_path":                    func(m *Manifest) { m.LegacyReports[0].ObservedFile.EntryID = "../report" },
		"modern_file_collision":        func(m *Manifest) { m.LegacyReports[0].ObservedFile.EntryID = m.Reports[0].File.EntryID },
		"artifact_file_collision":      func(m *Manifest) { m.LegacyReports[0].ObservedFile.EntryID = m.Artifacts[0].File.EntryID },
		"manifest_file_collision":      func(m *Manifest) { m.LegacyReports[0].ObservedFile.EntryID = "backup-manifest" },
		"duplicate_file":               func(m *Manifest) { m.LegacyReports[3].ObservedFile.EntryID = m.LegacyReports[0].ObservedFile.EntryID },
		"negative_file":                func(m *Manifest) { m.LegacyReports[0].ObservedFile.Bytes = -1 },
		"empty_hash_lie":               func(m *Manifest) { m.LegacyReports[3].ObservedFile.SHA256 = strings.Repeat("a", 64) },
		"file_hash":                    func(m *Manifest) { m.LegacyReports[0].ObservedFile.SHA256 = "" },
		"total_bytes":                  func(m *Manifest) { m.LegacyReports[0].ObservedFile.Bytes = MaxFileBytes },
		"modern_source_still_required": func(m *Manifest) { m.Reports[0].SourceSHA256 = "" },
		"modern_file_still_positive":   func(m *Manifest) { m.Reports[0].File.Bytes = 0; m.Reports[0].File.SHA256 = digest(nil) },
		"artifact_file_still_positive": func(m *Manifest) { m.Artifacts[0].File.Bytes = 0; m.Artifacts[0].File.SHA256 = digest(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			m := legacyFixture()
			change(&m)
			if data, sum, err := Encode(m); err == nil || data != nil || sum != "" {
				t.Fatal("invalid legacy inventory returned usable bytes")
			}
			if entries, err := Entries(m); err == nil || entries != nil {
				t.Fatal("invalid legacy inventory returned partial entries")
			}
		})
	}
}

func TestManifestV3LegacyReportsStrictWireAndExternalBinding(t *testing.T) {
	m := legacyFixture()
	data, sum, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	for name, replacements := range map[string][2]string{
		"null_file": {`"file_state":"missing"`, `"file_state":"missing","observed_file":null`},
		"alias":     {`"row_sha256":`, `"Row_SHA256":`},
		"duplicate": {`"verification":"legacy_unverified"`, `"verification":"legacy_unverified","verification":"legacy_unverified"`},
		"unknown":   {`"file_state":"missing"`, `"file_state":"missing","trusted":false`},
		"omitted":   {`"row_version":"mii.legacy-report-row.v1",`, ``},
		"null":      {`"verification":"legacy_unverified"`, `"verification":null`},
		"float":     {`"id":21`, `"id":21.0`},
		"raw_path":  {`"file_state":"missing"`, `"file_state":"missing","storage_path":"C:/private"`},
	} {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Replace(data, []byte(replacements[0]), []byte(replacements[1]), 1)
			if bytes.Equal(data, changed) {
				t.Fatal("wire mutation did not occur")
			}
			if out, err := Decode(changed, m.BackupID, digest(changed)); err == nil || out.LegacyReports != nil {
				t.Fatal("noncanonical wire accepted")
			}
		})
	}
	for _, schema := range []string{Version, VersionV2, VersionV3} {
		empty := legacyFixture()
		empty.SchemaVersion, empty.LegacyReports = schema, nil
		if schema == Version {
			empty = fixture()
		}
		base, _, err := Encode(empty)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"null", "[]"} {
			wire := append(bytes.Clone(base[:len(base)-1]), []byte(`,"legacy_reports":`+value+`}`)...)
			if _, err := Decode(wire, empty.BackupID, digest(wire)); err == nil {
				t.Fatal("explicit empty extension changed old canonical protocol")
			}
		}
	}
	m.LegacyReports[0].RowSHA256 = strings.Repeat("6", 64)
	changed, newSum, err := Encode(m)
	if err != nil || sum == newSum {
		t.Fatal("row commitment was not bound", err)
	}
	if _, err := Decode(changed, m.BackupID, sum); !errors.Is(err, ErrMismatch) {
		t.Fatal("original external anchor allowed changed row")
	}
}

func TestManifestV3LegacyInventoryBudgetAndPredecodeBound(t *testing.T) {
	m := legacyFixture()
	base := m.LegacyReports[1]
	for len(m.LegacyReports)+len(m.Reports)+len(m.Artifacts) < MaxEntries-3 {
		r := base
		r.ID = int64(1000 + len(m.LegacyReports))
		m.LegacyReports = append(m.LegacyReports, r)
	}
	// Count bounds happen before encoding; many absent rows still consume
	// metadata budget even though they must never fabricate file entries.
	if err := bounded(m); err != nil {
		t.Fatal("exact inventory-count limit changed", err)
	}
	if data, sum, err := Encode(m); !errors.Is(err, ErrLimit) || data != nil || sum != "" {
		t.Fatal("v3 metadata beyond the real 16 MiB wire budget was accepted")
	}
	m.LegacyReports = append(m.LegacyReports, base)
	if data, sum, err := Encode(m); !errors.Is(err, ErrLimit) || data != nil || sum != "" {
		t.Fatal("metadata over limit allocated/returned manifest")
	}
	// Independently build compact input, avoiding typed allocation. This must
	// fail token preflight before []LegacyReport is materialized by json.Decode.
	wire := []byte(`{"legacy_reports":[` + strings.Repeat(`{},`, MaxEntries-3) + `{}` + `]}`)
	if err := preflight(wire); !errors.Is(err, ErrLimit) {
		t.Fatal("legacy array lacks predecode bound", err)
	}
	m = legacyFixture()
	entries, err := Entries(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.File.Bytes < 0 {
			t.Fatal("negative planned entry")
		}
	}
}

func TestManifestV3LegacyStreamIncludesObservedEmptyAndNoAbsentFiles(t *testing.T) {
	for _, mode := range []string{"valid", "missing_observed", "extra_missing_file", "changed_observed", "nonempty_empty_file", "wrong_kind", "duplicate", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			m := legacyFixture()
			payloads := map[string][]byte{}
			set := func(f *File) {
				data := []byte("actual archive bytes " + f.EntryID)
				if f.Bytes == 0 {
					data = nil
				}
				f.Bytes, f.SHA256 = int64(len(data)), digest(data)
				payloads[f.EntryID] = data
			}
			set(&m.Database.File)
			set(&m.ConfigTemplate)
			for i := range m.Artifacts {
				set(&m.Artifacts[i].File)
			}
			for i := range m.Reports {
				set(&m.Reports[i].File)
			}
			for i := range m.LegacyReports {
				if f := m.LegacyReports[i].ObservedFile; f != nil {
					set(f)
				}
			}
			data, sum, err := Encode(m)
			if err != nil {
				t.Fatal(err)
			}
			m, err = Decode(data, m.BackupID, sum)
			if err != nil {
				t.Fatal(err)
			}
			payloads["backup-manifest"] = data
			entries, err := Entries(m)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var late func(string, string, io.Reader) error
			forbidden := inventoryReaderFunc(func([]byte) (int, error) { t.Error("closed/unknown/failed reader was accessed"); return 0, io.EOF })
			err = VerifyStream(ctx, m, time.Second, func(_ context.Context, accept func(string, string, io.Reader) error) error {
				late = accept
				failed := false
				for _, e := range entries {
					if mode == "missing_observed" && e.File.EntryID == "legacy-report-21" {
						continue
					}
					body, kind := payloads[e.File.EntryID], e.Kind
					if e.File.EntryID == "legacy-report-21" {
						if mode == "changed_observed" {
							body = []byte("changed")
						}
						if mode == "wrong_kind" {
							kind = "rule"
						}
					}
					if mode == "nonempty_empty_file" && e.File.EntryID == "legacy-report-24" {
						body = []byte("x")
					}
					var in io.Reader = bytes.NewReader(body)
					if failed {
						in = forbidden
					}
					if accept(kind, e.File.EntryID, in) != nil {
						failed = true
					}
					if mode == "duplicate" && e.File.EntryID == "legacy-report-21" {
						_ = accept(kind, e.File.EntryID, forbidden)
						failed = true
					}
				}
				if mode == "extra_missing_file" {
					_ = accept("report", "legacy-report-"+strconv.Itoa(22), forbidden)
				}
				if mode == "cancel" {
					cancel()
				}
				return nil // Deliberately swallow every per-entry error.
			})
			want := ErrMismatch
			if mode == "valid" {
				want = nil
			}
			if mode == "cancel" {
				want = ErrCanceled
			}
			if !errors.Is(err, want) {
				t.Fatal("wrong legacy exact-set outcome", err)
			}
			if late == nil || !errors.Is(late("report", "legacy-report-21", forbidden), ErrClosed) {
				t.Fatal("legacy stream survived completion")
			}
		})
	}
}
