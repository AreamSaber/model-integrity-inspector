package backupmanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func fixture() Manifest {
	f := func(id string) File { return File{id, 17, strings.Repeat("a", 64)} }
	return Manifest{
		SchemaVersion: Version, BackupID: 91, StartedAtMicros: 1788840000000000, SnapshotAtMicros: 1788840001000000,
		ApplicationVersion: "0.1.0-dev", SourceCommit: strings.Repeat("c", 40),
		Database:    Database{"sqlite", "3.52.0", "sqlite_online_backup", f("database-snapshot")},
		Migrations:  []Migration{{1, "foundation", strings.Repeat("b", 64)}, {2, "queue_leases", strings.Repeat("c", 64)}},
		Reports:     []Report{{12, 5, 6, 1, 2, "json", "mii.report.v1", strings.Repeat("d", 64), strings.Repeat("e", 64), f("report-12")}},
		Artifacts:   []Artifact{{"rule", "1.0.0-dev.1", f("rule-v1")}, {"scoring", "1.0.0-dev.1", f("scoring-v1")}, {"template", "1.0.0-dev.1", f("template-v1")}, {"tokenizer", "1.0.0-dev.1", f("tokenizer-v1")}},
		KeyVersions: []string{"key-v1", "key-v2"}, AuditHistory: "complete",
		AuditAnchors:   []AuditAnchor{{5, 99, strings.Repeat("f", 64), "key-v1", "mii.audit.v1"}, {9, 0, "", "", "mii.audit.v1"}},
		Jobs:           []JobSummary{{OrganizationID: 5, Pending: 1, Completed: 7, Failed: 2, Cancelled: 3, UncertainAttempts: 1}, {OrganizationID: 9}},
		ConfigTemplate: f("config-template"),
	}
}

func encodedFixture(t *testing.T) ([]byte, string) {
	t.Helper()
	data, sum, err := Encode(fixture())
	if err != nil {
		t.Fatal(err)
	}
	return data, sum
}

func TestManifestCanonicalRoundTripAndOwnedOrder(t *testing.T) {
	want, sum := encodedFixture(t)
	in := fixture()
	slices.Reverse(in.Migrations)
	slices.Reverse(in.Artifacts)
	slices.Reverse(in.KeyVersions)
	slices.Reverse(in.AuditAnchors)
	slices.Reverse(in.Jobs)
	before := canonical(in)
	data, gotHash, err := Encode(in)
	if err != nil || gotHash != sum || !bytes.Equal(data, want) {
		t.Fatal("unstable canonical encoding", err)
	}
	if in.Migrations[0].Version != 2 || in.KeyVersions[0] != "key-v2" || !reflect.DeepEqual(canonical(in), before) {
		t.Fatal("caller-owned inventory mutated")
	}
	decoded, err := Decode(data, 91, sum)
	if err != nil || !reflect.DeepEqual(decoded, fixture()) {
		t.Fatal("exact round trip changed facts", err)
	}
	if decoded.Jobs[0].UncertainAttempts != 1 || decoded.Jobs[0].Pending != 1 {
		t.Fatal("unsettled history rewritten as success")
	}
	data[0] = '['
	if decoded.SchemaVersion != Version {
		t.Fatal("decoded manifest aliases input buffer")
	}
	// No native database was read: this golden is a synthetic inventory contract.
	if sum != "0fbbd751a365f53c7cb9c3e3763fa176d5d2ed1e43f88189993e9a0d3bfc80b2" {
		t.Fatal("canonical wire format drift")
	}
}

func TestManifestSupportedDatabaseAndReportInventory(t *testing.T) {
	for _, driver := range []string{"sqlite", "postgres"} {
		for _, format := range []string{"json", "html", "pdf", "csv"} {
			t.Run(driver+"/"+format, func(t *testing.T) {
				m := fixture()
				m.Reports[0].Format = format
				if driver == "postgres" {
					m.Database.Driver, m.Database.ServerVersion, m.Database.SnapshotMethod = driver, "18.6", "pg_dump_snapshot"
				}
				data, sum, err := Encode(m)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := Decode(data, m.BackupID, sum); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	m := fixture()
	m.Reports = nil
	data, sum, err := Encode(m)
	if err != nil || !bytes.Contains(data, []byte(`"reports":[]`)) {
		t.Fatal("zero ready reports not represented explicitly", err)
	}
	if _, err := Decode(data, m.BackupID, sum); err != nil {
		t.Fatal(err)
	}
}

func TestManifestRejectsInvalidInventory(t *testing.T) {
	cases := map[string]func(*Manifest){
		"schema":                     func(m *Manifest) { m.SchemaVersion = "v2" },
		"id":                         func(m *Manifest) { m.BackupID = 0 },
		"negative_time":              func(m *Manifest) { m.StartedAtMicros = -1 },
		"reversed_time":              func(m *Manifest) { m.SnapshotAtMicros = m.StartedAtMicros - 1 },
		"overflow_time":              func(m *Manifest) { m.SnapshotAtMicros = math.MaxInt64 },
		"unknown_commit":             func(m *Manifest) { m.SourceCommit = "unknown" },
		"uppercase_commit":           func(m *Manifest) { m.SourceCommit = strings.Repeat("A", 40) },
		"app_prose":                  func(m *Manifest) { m.ApplicationVersion = "secret\ncanary" },
		"wrong_driver":               func(m *Manifest) { m.Database.Driver = "mysql" },
		"mismatched_method":          func(m *Manifest) { m.Database.SnapshotMethod = "pg_dump_snapshot" },
		"version_sql":                func(m *Manifest) { m.Database.ServerVersion = "18.6;DROP" },
		"missing_migration":          func(m *Manifest) { m.Migrations = nil },
		"gap":                        func(m *Manifest) { m.Migrations[1].Version = 3 },
		"duplicate_migration":        func(m *Manifest) { m.Migrations[1].Version = 1 },
		"migration_path":             func(m *Manifest) { m.Migrations[0].Name = "../foundation" },
		"migration_hash":             func(m *Manifest) { m.Migrations[0].SHA256 = "a" },
		"no_keys":                    func(m *Manifest) { m.KeyVersions = nil },
		"duplicate_keys":             func(m *Manifest) { m.KeyVersions[1] = "key-v1" },
		"key_path":                   func(m *Manifest) { m.KeyVersions[0] = "C:/master.key" },
		"missing_historical_key":     func(m *Manifest) { m.KeyVersions = []string{"key-v2"} },
		"segmented_history":          func(m *Manifest) { m.AuditHistory = "segmented" },
		"no_org":                     func(m *Manifest) { m.AuditAnchors = nil },
		"duplicate_org":              func(m *Manifest) { m.AuditAnchors[1] = m.AuditAnchors[0] },
		"negative_events":            func(m *Manifest) { m.AuditAnchors[0].EventCount = -1 },
		"empty_end_hash":             func(m *Manifest) { m.AuditAnchors[0].EndHash = "" },
		"empty_chain_nonempty_hash":  func(m *Manifest) { m.AuditAnchors[1].EndHash = strings.Repeat("a", 64) },
		"audit_version":              func(m *Manifest) { m.AuditAnchors[0].CanonicalizationVersion = "future" },
		"missing_job_summary":        func(m *Manifest) { m.Jobs = m.Jobs[:1] },
		"job_wrong_org":              func(m *Manifest) { m.Jobs[1].OrganizationID = 88 },
		"running_job":                func(m *Manifest) { m.Jobs[0].Running = 1 },
		"dispatched_attempt":         func(m *Manifest) { m.Jobs[0].DispatchedAttempts = 1 },
		"negative_job":               func(m *Manifest) { m.Jobs[0].Pending = -1 },
		"negative_uncertain":         func(m *Manifest) { m.Jobs[0].UncertainAttempts = -1 },
		"overflow_job_total":         func(m *Manifest) { m.Jobs[0].Completed = math.MaxInt64 },
		"duplicate_report":           func(m *Manifest) { m.Reports = append(m.Reports, m.Reports[0]) },
		"foreign_report":             func(m *Manifest) { m.Reports[0].OrganizationID = 3 },
		"missing_run":                func(m *Manifest) { m.Reports[0].RunID = 0 },
		"revision":                   func(m *Manifest) { m.Reports[0].Revision = 0 },
		"analysis_revision_overflow": func(m *Manifest) { m.Reports[0].AnalysisRevision = math.MaxInt64 },
		"report_format":              func(m *Manifest) { m.Reports[0].Format = "zip" },
		"report_schema":              func(m *Manifest) { m.Reports[0].SchemaVersion = "future" },
		"report_source_hash":         func(m *Manifest) { m.Reports[0].SourceSHA256 = "unknown" },
		"report_content_hash":        func(m *Manifest) { m.Reports[0].ContentSHA256 = "sha256:" + strings.Repeat("a", 64) },
		"file_traversal":             func(m *Manifest) { m.Reports[0].File.EntryID = "../escape" },
		"file_ads":                   func(m *Manifest) { m.Reports[0].File.EntryID = "file:stream" },
		"file_path":                  func(m *Manifest) { m.Reports[0].File.EntryID = "C:\\file" },
		"case_alias":                 func(m *Manifest) { m.Reports[0].File.EntryID = "REPORT-12" },
		"manifest_collision":         func(m *Manifest) { m.Reports[0].File.EntryID = "backup-manifest" },
		"cross_kind_collision":       func(m *Manifest) { m.Artifacts[0].File.EntryID = "report-12" },
		"database_alias":             func(m *Manifest) { m.Database.File.EntryID = "different-db" },
		"config_alias":               func(m *Manifest) { m.ConfigTemplate.EntryID = "config.env" },
		"empty_file":                 func(m *Manifest) { m.Reports[0].File.Bytes = 0 },
		"negative_size":              func(m *Manifest) { m.Reports[0].File.Bytes = -1 },
		"overflow_size":              func(m *Manifest) { m.Reports[0].File.Bytes = math.MaxInt64 },
		"total_size":                 func(m *Manifest) { m.Database.File.Bytes = MaxFileBytes },
		"uppercase_hash":             func(m *Manifest) { m.ConfigTemplate.SHA256 = strings.Repeat("A", 64) },
		"missing_category":           func(m *Manifest) { m.Artifacts = m.Artifacts[:3] },
		"unknown_category":           func(m *Manifest) { m.Artifacts[0].Category = "master_key" },
		"duplicate_artifact_version": func(m *Manifest) {
			m.Artifacts = append(m.Artifacts, m.Artifacts[0])
			m.Artifacts[4].File.EntryID = "another"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			mutate(&m)
			if data, sum, err := Encode(m); err == nil || data != nil || sum != "" {
				t.Fatal("invalid inventory accepted")
			}
		})
	}
}

func TestManifestRejectsNoncanonicalAndUnexpectedDocuments(t *testing.T) {
	data, _ := encodedFixture(t)
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate_key": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"backup_id":91`), []byte(`"backup_id":91,"backup_id":91`), 1)
		},
		"case_alias":     func(b []byte) []byte { return bytes.Replace(b, []byte(`"backup_id"`), []byte(`"BACKUP_ID"`), 1) },
		"escaped_key":    func(b []byte) []byte { return bytes.Replace(b, []byte(`"backup_id"`), []byte(`"backup_\u0069d"`), 1) },
		"unknown_field":  func(b []byte) []byte { return append([]byte(`{"dsn":"protected-canary",`), b[1:]...) },
		"trailing_space": func(b []byte) []byte { return append(b, ' ') },
		"trailing_json":  func(b []byte) []byte { return append(b, []byte(`{}`)...) },
		"missing_field":  func(b []byte) []byte { return bytes.Replace(b, []byte(`"running":0,`), nil, 1) },
		"null_slice": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"key_versions":["key-v1","key-v2"]`), []byte(`"key_versions":null`), 1)
		},
		"unordered": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`["key-v1","key-v2"]`), []byte(`["key-v2","key-v1"]`), 1)
		},
		"float_id": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"backup_id":91`), []byte(`"backup_id":91.0`), 1)
		},
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		t.Run(name, func(t *testing.T) {
			changed := mutate(bytes.Clone(data))
			if bytes.Equal(changed, data) {
				t.Fatal("mutation did not affect current fixture")
			}
			if _, err := Decode(changed, 91, digest(changed)); err == nil {
				t.Fatal("noncanonical document accepted even with matching hash")
			}
		})
	}
	if _, err := Decode(data, 92, digest(data)); !errors.Is(err, ErrMismatch) {
		t.Fatal("wrong expected backup ID accepted")
	}
	if _, err := Decode(data, 91, strings.Repeat("0", 64)); !errors.Is(err, ErrMismatch) {
		t.Fatal("wrong external hash accepted")
	}
	if _, err := Decode(nil, 91, digest(nil)); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty document accepted")
	}
	if _, err := Decode(data, 91, "canary"); !errors.Is(err, ErrInvalid) {
		t.Fatal("bad expected hash accepted")
	}
}

func TestManifestLimitsAndNoImplicitSerialization(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"migrations": func(m *Manifest) { m.Migrations = make([]Migration, MaxMigrations+1) },
		"reports":    func(m *Manifest) { m.Reports = make([]Report, MaxEntries-2) },
		"artifacts":  func(m *Manifest) { m.Artifacts = make([]Artifact, MaxEntries-2) },
		"keys":       func(m *Manifest) { m.KeyVersions = make([]string, 65) },
		"orgs":       func(m *Manifest) { m.AuditAnchors = make([]AuditAnchor, MaxOrganizations+1) },
		"jobs":       func(m *Manifest) { m.Jobs = make([]JobSummary, MaxOrganizations+1) },
	} {
		t.Run(name, func(t *testing.T) {
			m := fixture()
			mutate(&m)
			if _, _, err := Encode(m); !errors.Is(err, ErrLimit) {
				t.Fatal("resource limit not enforced", err)
			}
		})
	}
	if _, err := Decode(make([]byte, MaxBytes+1), 91, strings.Repeat("0", 64)); !errors.Is(err, ErrLimit) {
		t.Fatal("input limit not enforced")
	}
	m := fixture()
	if _, err := json.Marshal(struct{ Manifest Manifest }{m}); err == nil {
		t.Fatal("implicit JSON exposed inventory")
	}
	if _, err := m.MarshalYAML(); err == nil {
		t.Fatal("implicit YAML exposed inventory")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if fmt.Sprintf(format, m) != "[private backup manifest]" {
			t.Fatal("fmt exposed inventory")
		}
	}
	if m.LogValue().String() != "[private backup manifest]" {
		t.Fatal("structured logging exposed inventory")
	}
}

func TestManifestEntryPlanAndManifestOverhead(t *testing.T) {
	m := fixture()
	data, sum, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Entries(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 8 || entries[0] != (Entry{"manifest", File{"backup-manifest", int64(len(data)), sum}}) {
		t.Fatal("manifest does not commit its own canonical bytes externally")
	}
	seen := map[string]bool{}
	for _, e := range entries {
		if seen[e.File.EntryID] {
			t.Fatal("duplicate archive identity")
		}
		seen[e.File.EntryID] = true
	}
	entries[0].File.EntryID = "mutated"
	second, err := Entries(m)
	if err != nil || second[0].File.EntryID != "backup-manifest" {
		t.Fatal("plan aliases previous result", err)
	}
	// Seven payload files at 17 bytes each; retain 1 TiB minus other payloads,
	// so the manifest's own bytes take this otherwise bounded archive over budget.
	m.Database.File.Bytes = MaxFileBytes - 6*17
	if _, _, err := Encode(m); !errors.Is(err, ErrLimit) {
		t.Fatal("Encode omitted manifest bytes from plaintext budget", err)
	}
	if _, err := Entries(m); !errors.Is(err, ErrLimit) {
		t.Fatal("manifest bytes omitted from archive limit", err)
	}
}

func TestManifestRejectsArrayCountBeforeTypedAllocation(t *testing.T) {
	// Under 200 KiB of JSON formerly allocated ~57 MiB of Report structs before
	// noticing the item limit. No giant input or out-of-memory experiment is used.
	data := []byte(`{"backup_id":91,"reports":[` + strings.Repeat(`{},`, MaxEntries) + `{}` + `]}`)
	sum := digest(data)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := Decode(data, 91, sum)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrLimit) {
		t.Fatal("excessive array was not rejected", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if allocated > 16<<20 {
		t.Fatalf("typed allocation preceded array limit: %d bytes", allocated)
	}
}

func TestManifestEmptyAuditHeadPreservesKeyVersion(t *testing.T) {
	m := fixture()
	m.AuditAnchors[1].KeyVersion = "key-v2"
	data, sum, err := Encode(m)
	if err != nil {
		t.Fatal("valid empty persisted head lost its version", err)
	}
	got, err := Decode(data, m.BackupID, sum)
	if err != nil || got.AuditAnchors[1].KeyVersion != "key-v2" {
		t.Fatal("empty head facts changed", err)
	}
}
