package backupmanifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func scopedFixture() Manifest {
	m := fixture()
	m.SchemaVersion = VersionV2
	for i := range m.Artifacts {
		a := &m.Artifacts[i]
		switch a.Category {
		case "rule", "template":
			a.Scope, a.OrganizationID, a.ID = ArtifactScopeOrganization, 5, 101
		default:
			a.Scope = ArtifactScopeInstalled
		}
	}
	// The same original version may have entirely different retained bytes in
	// another organization. IDs are globally unique within each source table,
	// but a rule and template may legally share the same numeric row ID.
	m.Artifacts = append(m.Artifacts, Artifact{Category: "rule", Scope: ArtifactScopeOrganization, OrganizationID: 9, ID: 102, Version: m.Artifacts[0].Version, File: File{"rule-org9", 19, strings.Repeat("9", 64)}})
	return m
}

const manifestV2ArtifactGolden = `"artifacts":[{"category":"rule","scope":"organization","organization_id":5,"id":101,"version":"1.0.0-dev.1","file":{"entry_id":"rule-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"category":"rule","scope":"organization","organization_id":9,"id":102,"version":"1.0.0-dev.1","file":{"entry_id":"rule-org9","bytes":19,"sha256":"9999999999999999999999999999999999999999999999999999999999999999"}},{"category":"scoring","scope":"installed","version":"1.0.0-dev.1","file":{"entry_id":"scoring-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"category":"template","scope":"organization","organization_id":5,"id":101,"version":"1.0.0-dev.1","file":{"entry_id":"template-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"category":"tokenizer","scope":"installed","version":"1.0.0-dev.1","file":{"entry_id":"tokenizer-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],`

func independentV2Golden() []byte {
	// Independent expected literals, not json.Marshal or production canonical.
	start := strings.Index(manifestV1Golden, `"artifacts":`)
	end := strings.Index(manifestV1Golden, `"key_versions":`)
	return []byte(strings.Replace(manifestV1Golden[:start]+manifestV2ArtifactGolden+manifestV1Golden[end:], "mii.backup-manifest.v1", "mii.backup-manifest.v2", 1))
}

func TestManifestV2ExactCanonicalFieldsAndBinding(t *testing.T) {
	m := scopedFixture()
	data, sum, err := Encode(m)
	want := independentV2Golden()
	independent := sha256.Sum256(want)
	const pinned = "3a58455cac5a12f3c36333279db2e5e200dfe726adbf99c3a1da6477a2ded1a6"
	if err != nil || !bytes.Equal(data, want) || sum != pinned || hex.EncodeToString(independent[:]) != pinned {
		t.Fatal("v2 fields/order/omission or hash differ from independent golden", err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"tenant_binding": func(m *Manifest) { m.Artifacts[2].OrganizationID = 9 },
		"row_binding":    func(m *Manifest) { m.Artifacts[0].ID = 111 },
		"version_binding": func(m *Manifest) {
			m.Artifacts[0].Version = "another-version"
		},
		"file_binding": func(m *Manifest) { m.Artifacts[0].File, m.Artifacts[4].File = m.Artifacts[4].File, m.Artifacts[0].File },
	} {
		t.Run(name, func(t *testing.T) {
			changed := scopedFixture()
			mutate(&changed)
			bytesChanged, newSum, err := Encode(changed)
			if err != nil || bytes.Equal(bytesChanged, data) || newSum == sum {
				t.Fatal("valid changed binding did not change manifest commitment", err)
			}
			if _, err := Decode(bytesChanged, m.BackupID, sum); !errors.Is(err, ErrMismatch) {
				t.Fatal("original external anchor accepted altered binding", err)
			}
			// A separately approved changed anchor would encode different facts;
			// the manifest cannot authenticate a hash taken from itself.
			if _, err := Decode(bytesChanged, m.BackupID, newSum); err != nil {
				t.Fatal("valid new facts are not structurally representable", err)
			}
		})
	}
}

func TestManifestV2CombinedEntryAndEncodedByteLimits(t *testing.T) {
	m := scopedFixture()
	// Use the real 65,536-entry cap, including manifest/database/config/report,
	// not a test-lowered substitute. Small identities fit the 16 MiB wire cap.
	target := MaxEntries - 3 - len(m.Reports)
	for len(m.Artifacts) < target {
		i := len(m.Artifacts) + 1000
		name := strconv.Itoa(i)
		m.Artifacts = append(m.Artifacts, Artifact{Category: "rule", Scope: ArtifactScopeOrganization, OrganizationID: 5, ID: int64(i), Version: "v" + name, File: File{"r" + name, 1, strings.Repeat("a", 64)}})
	}
	data, sum, err := Encode(m)
	if err != nil || len(data) > MaxBytes {
		t.Fatal("valid v2 inventory at exact total-entry cap rejected", err)
	}
	decoded, err := Decode(data, m.BackupID, sum)
	if err != nil || len(decoded.Artifacts)+len(decoded.Reports)+3 != MaxEntries {
		t.Fatal("v2 exact entry limit did not round trip", err)
	}
	m.Artifacts = append(m.Artifacts, Artifact{})
	if data, sum, err := Encode(m); !errors.Is(err, ErrLimit) || data != nil || sum != "" {
		t.Fatal("v2 entry limit plus one returned a partial manifest", err)
	}
	m.Artifacts = m.Artifacts[:target]
	for i := range m.Artifacts {
		if m.Artifacts[i].Category == "rule" {
			m.Artifacts[i].Version = strings.Repeat("v", 128-len(m.Artifacts[i].Version)) + m.Artifacts[i].Version
		}
	}
	if data, sum, err := Encode(m); !errors.Is(err, ErrLimit) || data != nil || sum != "" {
		t.Fatal("valid v2 identities exceeding real 16 MiB wire cap were truncated/accepted", err)
	}
	m = scopedFixture()
	m.AuditAnchors = make([]AuditAnchor, MaxOrganizations+1)
	if _, _, err := Encode(m); !errors.Is(err, ErrLimit) {
		t.Fatal("v2 organization cap was relaxed", err)
	}
}

func TestManifestV2StrictScopedFieldWireProtocol(t *testing.T) {
	data := independentV2Golden()
	for name, mutation := range map[string][2]string{
		"scope_omitted":           {`"scope":"organization",`, ""},
		"scope_null":              {`"scope":"organization"`, `"scope":null`},
		"scope_empty":             {`"scope":"organization"`, `"scope":""`},
		"scope_zero":              {`"scope":"organization"`, `"scope":0`},
		"scope_duplicate":         {`"scope":"organization"`, `"scope":"organization","scope":"organization"`},
		"scope_alias":             {`"scope":"organization"`, `"Scope":"organization"`},
		"organization_omitted":    {`"organization_id":5,"id":101,`, `"id":101,`},
		"organization_null":       {`"organization_id":5,"id":101`, `"organization_id":null,"id":101`},
		"organization_zero":       {`"organization_id":5,"id":101`, `"organization_id":0,"id":101`},
		"organization_string":     {`"organization_id":5,"id":101`, `"organization_id":"5","id":101`},
		"organization_duplicate":  {`"organization_id":5,"id":101`, `"organization_id":5,"organization_id":5,"id":101`},
		"row_omitted":             {`"id":101,`, ""},
		"row_null":                {`"id":101`, `"id":null`},
		"row_zero":                {`"id":101`, `"id":0`},
		"row_float":               {`"id":101`, `"id":101.0`},
		"row_negative":            {`"id":101`, `"id":-1`},
		"row_duplicate":           {`"id":101`, `"id":101,"id":101`},
		"row_alias":               {`"id":101`, `"ID":101`},
		"installed_scope_null":    {`"scope":"installed"`, `"scope":null`},
		"installed_scope_omitted": {`"scope":"installed",`, ""},
		"installed_org_zero":      {`"scope":"installed"`, `"scope":"installed","organization_id":0`},
		"installed_org_null":      {`"scope":"installed"`, `"scope":"installed","organization_id":null`},
		"installed_row_zero":      {`"scope":"installed"`, `"scope":"installed","id":0`},
		"installed_row_null":      {`"scope":"installed"`, `"scope":"installed","id":null`},
		"v2_fields_in_v1":         {`"schema_version":"mii.backup-manifest.v2"`, `"schema_version":"mii.backup-manifest.v1"`},
	} {
		t.Run(name, func(t *testing.T) {
			changed := bytes.Replace(data, []byte(mutation[0]), []byte(mutation[1]), 1)
			if bytes.Equal(data, changed) {
				t.Fatal("strict wire mutation did not reach the intended field")
			}
			if _, err := Decode(changed, 91, digest(changed)); !errors.Is(err, ErrInvalid) {
				t.Fatal("noncanonical scoped fields accepted with recomputed anchor", err)
			}
		})
	}
	for _, field := range []string{`"scope":"organization"`, `"scope":""`, `"scope":null`, `"organization_id":5`, `"organization_id":0`, `"organization_id":null`, `"id":101`, `"id":0`, `"id":null`} {
		changed := bytes.Replace([]byte(manifestV1Golden), []byte(`"category":"rule",`), []byte(`"category":"rule",`+field+","), 1)
		if _, err := Decode(changed, 91, digest(changed)); !errors.Is(err, ErrInvalid) {
			t.Fatal("v1 decoder accepted a new scoped identity field", field, err)
		}
	}
	changed := bytes.Replace([]byte(manifestV1Golden), []byte(Version), []byte(VersionV2), 1)
	if _, err := Decode(changed, 91, digest(changed)); !errors.Is(err, ErrInvalid) {
		t.Fatal("v1 inventory was silently upgraded without scoped identities", err)
	}
}

func TestManifestV2OwnedCopiesConcurrentCanonicalAndOriginalIdentityBounds(t *testing.T) {
	m := scopedFixture()
	want, sum, err := Encode(m)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			data, hash, err := Encode(m)
			if err != nil || hash != sum || !bytes.Equal(data, want) {
				t.Error("concurrent immutable source encoding changed", err)
				return
			}
			decoded, err := Decode(data, m.BackupID, sum)
			if err != nil {
				t.Error(err)
				return
			}
			decoded.Artifacts[0].OrganizationID = 999
			decoded.Artifacts[0].ID = 998
			data[0] = '['
			plan, err := Entries(m)
			if err != nil {
				t.Error(err)
				return
			}
			plan[0].File.SHA256 = "mutated"
		})
	}
	wg.Wait()
	data, hash, err := Encode(m)
	if err != nil || hash != sum || !bytes.Equal(data, want) {
		t.Fatal("owned results leaked mutation back to shared source", err)
	}
	m = scopedFixture()
	m.Artifacts[0].ID = math.MaxInt64
	m.Artifacts[4].OrganizationID = math.MaxInt64
	m.AuditAnchors[1].OrganizationID = math.MaxInt64
	m.Jobs[1].OrganizationID = math.MaxInt64
	m.Artifacts[0].Version = strings.Repeat("v", 128)
	data, sum, err = Encode(m)
	decoded, decodeErr := Decode(data, m.BackupID, sum)
	if err != nil || decodeErr != nil || decoded.Artifacts[0].ID != math.MaxInt64 || !bytes.Contains(data, []byte(strconv.FormatInt(math.MaxInt64, 10))) || decoded.Artifacts[0].Version != strings.Repeat("v", 128) {
		t.Fatal("valid original identity/version at exact bound changed", err, decodeErr)
	}
	m.Artifacts[0].Version += "v"
	if _, _, err := Encode(m); !errors.Is(err, ErrInvalid) {
		t.Fatal("artifact version boundary was relaxed", err)
	}
	for _, length := range []int{MaxEntries - 2, MaxEntries} {
		m = scopedFixture()
		m.Artifacts = make([]Artifact, length)
		if _, _, err := Encode(m); !errors.Is(err, ErrLimit) {
			t.Fatal("v2 bypassed combined archive entry cap", err)
		}
	}
	m = scopedFixture()
	m.Database.File.Bytes = MaxFileBytes - inventoryBytes(m) + m.Database.File.Bytes
	if _, _, err := Encode(m); !errors.Is(err, ErrLimit) {
		t.Fatal("v2 omitted manifest overhead from total plaintext cap", err)
	}
}

func TestManifestV2RetainsCrossOrganizationSameVersionDifferentBytes(t *testing.T) {
	m := scopedFixture()
	before := append([]Artifact(nil), m.Artifacts...)
	data, sum, err := Encode(m)
	if err != nil {
		t.Fatal("legal organization-scoped inventory is not representable", err)
	}
	got, err := Decode(data, m.BackupID, sum)
	if err != nil || !reflect.DeepEqual(got, canonical(m)) || !reflect.DeepEqual(before, m.Artifacts) {
		t.Fatal("scoped round trip lost or mutated source facts", err)
	}
	if got.Artifacts[0].OrganizationID != 5 || got.Artifacts[1].OrganizationID != 9 || got.Artifacts[0].Version != got.Artifacts[1].Version || got.Artifacts[0].File.SHA256 == got.Artifacts[1].File.SHA256 {
		t.Fatal("cross-organization content was conflated or version rewritten")
	}
	slices.Reverse(m.Artifacts)
	reordered, reorderedSum, err := Encode(m)
	if err != nil || reorderedSum != sum || !bytes.Equal(reordered, data) {
		t.Fatal("scoped canonical ordering is unstable", err)
	}
	if m.Artifacts[0].OrganizationID != 9 {
		t.Fatal("canonical sort mutated caller storage")
	}
	// An organization with no retained bundles remains valid; do not require
	// every organization to carry all four categories or invent installed rows.
	m.AuditAnchors = append(m.AuditAnchors, AuditAnchor{OrganizationID: 13, CanonicalizationVersion: "mii.audit.v1"})
	m.Jobs = append(m.Jobs, JobSummary{OrganizationID: 13})
	if _, _, err := Encode(m); err != nil {
		t.Fatal("empty retained inventory for one organization was rejected", err)
	}
}

// Independent legacy-protocol literal, manually assembled from the pre-v2
// fixture and field order (also checked read-only with git show HEAD). It is
// newly added here, not a claimed historical golden file or old-binary replay.
// The pinned hash below is the existing pre-v2 test's historical commitment.
const manifestV1Golden = `{"schema_version":"mii.backup-manifest.v1","backup_id":91,"started_at_micros":1788840000000000,"snapshot_at_micros":1788840001000000,"application_version":"0.1.0-dev","source_commit":"cccccccccccccccccccccccccccccccccccccccc","database":{"driver":"sqlite","server_version":"3.52.0","snapshot_method":"sqlite_online_backup","file":{"entry_id":"database-snapshot","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},"migrations":[{"version":1,"name":"foundation","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},{"version":2,"name":"queue_leases","sha256":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}],"reports":[{"id":12,"organization_id":5,"run_id":6,"analysis_revision":1,"revision":2,"format":"json","schema_version":"mii.report.v1","content_sha256":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","source_sha256":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","file":{"entry_id":"report-12","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"artifacts":[{"category":"rule","version":"1.0.0-dev.1","file":{"entry_id":"rule-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"category":"scoring","version":"1.0.0-dev.1","file":{"entry_id":"scoring-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"category":"template","version":"1.0.0-dev.1","file":{"entry_id":"template-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"category":"tokenizer","version":"1.0.0-dev.1","file":{"entry_id":"tokenizer-v1","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],"key_versions":["key-v1","key-v2"],"audit_history":"complete","audit_anchors":[{"organization_id":5,"event_count":99,"end_hash":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","key_version":"key-v1","canonicalization_version":"mii.audit.v1"},{"organization_id":9,"event_count":0,"end_hash":"","key_version":"","canonicalization_version":"mii.audit.v1"}],"jobs":[{"organization_id":5,"pending":1,"running":0,"completed":7,"failed":2,"cancelled":3,"dispatched_attempts":0,"uncertain_attempts":1},{"organization_id":9,"pending":0,"running":0,"completed":0,"failed":0,"cancelled":0,"dispatched_attempts":0,"uncertain_attempts":0}],"config_template":{"entry_id":"config-template","bytes":17,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}`

func TestManifestV1ExactBytesAndHashRemainUnchanged(t *testing.T) {
	data, sum, err := Encode(fixture())
	independent := sha256.Sum256([]byte(manifestV1Golden))
	const pinned = "0fbbd751a365f53c7cb9c3e3763fa176d5d2ed1e43f88189993e9a0d3bfc80b2"
	if err != nil || string(data) != manifestV1Golden || sum != pinned || hex.EncodeToString(independent[:]) != pinned || Version != "mii.backup-manifest.v1" {
		t.Fatal("v1 bytes/default/hash drifted", err)
	}
	if _, err := Decode([]byte(manifestV1Golden), 91, pinned); err != nil {
		t.Fatal("old independent v1 golden no longer decodes", err)
	}
}

func TestManifestV2RejectsConflictingScopedIdentities(t *testing.T) {
	for name, mutate := range map[string]func(*Manifest){
		"missing_scope":          func(m *Manifest) { m.Artifacts[0].Scope = "" },
		"unknown_scope":          func(m *Manifest) { m.Artifacts[0].Scope = "global" },
		"rule_installed":         func(m *Manifest) { m.Artifacts[0].Scope = ArtifactScopeInstalled },
		"template_installed":     func(m *Manifest) { m.Artifacts[2].Scope = ArtifactScopeInstalled },
		"scoring_organization":   func(m *Manifest) { m.Artifacts[1].Scope = ArtifactScopeOrganization },
		"tokenizer_organization": func(m *Manifest) { m.Artifacts[3].Scope = ArtifactScopeOrganization },
		"missing_org":            func(m *Manifest) { m.Artifacts[0].OrganizationID = 0 },
		"negative_org":           func(m *Manifest) { m.Artifacts[0].OrganizationID = -1 },
		"orphan_org":             func(m *Manifest) { m.Artifacts[0].OrganizationID = 10 },
		"missing_row":            func(m *Manifest) { m.Artifacts[0].ID = 0 },
		"negative_row":           func(m *Manifest) { m.Artifacts[0].ID = -1 },
		"installed_org":          func(m *Manifest) { m.Artifacts[1].OrganizationID = 5 },
		"installed_row":          func(m *Manifest) { m.Artifacts[3].ID = 101 },
		"reused_row_across_orgs": func(m *Manifest) { m.Artifacts[4].ID = m.Artifacts[0].ID },
		"same_org_version":       func(m *Manifest) { m.Artifacts[4].OrganizationID = 5 },
		"same_org_row_new_version": func(m *Manifest) {
			a := m.Artifacts[0]
			a.Version, a.File.EntryID = "v2", "another-rule"
			m.Artifacts = append(m.Artifacts, a)
		},
		"installed_duplicate_version": func(m *Manifest) {
			a := m.Artifacts[1]
			a.File.EntryID = "another-scoring"
			m.Artifacts = append(m.Artifacts, a)
		},
		"shared_archive_id":  func(m *Manifest) { m.Artifacts[4].File.EntryID = m.Artifacts[0].File.EntryID },
		"incomplete_history": func(m *Manifest) { m.AuditHistory = "segmented" },
		"active_work":        func(m *Manifest) { m.Jobs[0].Running = 1 },
		"category_missing":   func(m *Manifest) { m.Artifacts = slices.Delete(m.Artifacts, 2, 3) },
		"unknown_version":    func(m *Manifest) { m.SchemaVersion = "mii.backup-manifest.v999" },
	} {
		t.Run(name, func(t *testing.T) {
			m := scopedFixture()
			mutate(&m)
			if data, sum, err := Encode(m); !errors.Is(err, ErrInvalid) || data != nil || sum != "" {
				t.Fatal("invalid scoped inventory returned a manifest", err)
			}
		})
	}
	for _, field := range []string{"scope", "organization_id", "id"} {
		m := fixture()
		switch field {
		case "scope":
			m.Artifacts[0].Scope = ArtifactScopeOrganization
		case "organization_id":
			m.Artifacts[0].OrganizationID = 5
		case "id":
			m.Artifacts[0].ID = 101
		}
		if data, sum, err := Encode(m); !errors.Is(err, ErrInvalid) || data != nil || sum != "" {
			t.Fatal("v1 silently adopted a scoped field", field, err)
		}
	}
}
