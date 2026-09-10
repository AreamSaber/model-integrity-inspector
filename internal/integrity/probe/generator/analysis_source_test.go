package generator

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

// Encode the previous struct shape, omitting the newly added field entirely.
// Preserve the declared JSON order instead of converting the object to a map.
func encodeLegacySourceShape(t *testing.T, value any) []byte {
	t.Helper()
	v := reflect.ValueOf(value)
	fields, values := []reflect.StructField{}, []reflect.Value{}
	for i := 0; i < v.NumField(); i++ {
		field, item := v.Type().Field(i), v.Field(i)
		if field.Name == "AnalysisSourceVersion" {
			continue
		}
		if field.Name == "Options" {
			field.Type = reflect.TypeFor[json.RawMessage]()
			item = reflect.ValueOf(json.RawMessage(encodeLegacySourceShape(t, item.Interface())))
		}
		fields, values = append(fields, field), append(values, item)
	}
	legacy := reflect.New(reflect.StructOf(fields)).Elem()
	for i, value := range values {
		legacy.Field(i).Set(value)
	}
	encoded, err := json.Marshal(legacy.Interface())
	if err != nil {
		t.Fatal("legacy canonical encoding failed")
	}
	return encoded
}

func TestAnalysisSourceLegacyCanonicalAndSignatureRemainCompatible(t *testing.T) {
	g := testGenerator(t)
	m, err := g.Generate(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	unsigned := m
	unsigned.Integrity = ""
	oldUnsigned := encodeLegacySourceShape(t, unsigned)
	oldMAC, err := g.mac(m.KeyVersion, "manifest-v1", m.Options.OrganizationID, m.RunNonce, digest(oldUnsigned))
	if err != nil || oldMAC != m.Integrity {
		t.Fatal("legacy manifest signature changed")
	}
	oldBytes := encodeLegacySourceShape(t, m)
	currentBytes, currentHash, err := m.Canonical()
	if err != nil || !bytes.Equal(oldBytes, currentBytes) || digest(oldBytes) != currentHash || bytes.Contains(oldBytes, []byte("analysis_source_version")) {
		t.Fatal("empty source version changed legacy canonical bytes or hash")
	}
	if _, err := g.Verify(oldBytes, digest(oldBytes), m.Options.OrganizationID); err != nil {
		t.Fatal("old signed canonical manifest no longer verifies", err)
	}
	plan, err := g.ExecutionPlan(oldBytes, digest(oldBytes), m.Options.OrganizationID)
	if err != nil || plan.AnalysisSourceVersion != "" {
		t.Fatal("legacy plan was upgraded")
	}
	planBytes, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(planBytes, encodeLegacySourceShape(t, plan)) {
		t.Fatal("empty source version changed legacy execution snapshot bytes")
	}
}

func TestAnalysisSourceSignedModeAndExactProjection(t *testing.T) {
	g := testGenerator(t)
	o := testOptions()
	o.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
	m, err := g.Generate(o)
	if err != nil {
		t.Fatal(err)
	}
	data, hash, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	verified, err := g.Verify(data, hash, o.OrganizationID)
	if err != nil || verified.Options.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 {
		t.Fatal("new mode is not authenticated")
	}
	plan, err := g.ExecutionPlan(data, hash, o.OrganizationID)
	if err != nil || plan.AnalysisSourceVersion != domain.AnalysisSourceDerivedV1 || !bytes.Equal(plan.Manifest, data) {
		t.Fatal("execution replay lost signed mode")
	}
	// This is a deliberately re-signed test comparison, not a migration or an
	// oracle escape hatch: source metadata must not alter upstream requests.
	legacy := m
	legacy.Options.AnalysisSourceVersion = ""
	if err := g.sign(&legacy); err != nil {
		t.Fatal(err)
	}
	legacyBytes, legacyHash, err := legacy.Canonical()
	if err != nil || legacyHash == hash || legacy.Integrity == m.Integrity {
		t.Fatal("mode did not change manifest hash and authentication")
	}
	legacyPlan, err := g.ExecutionPlan(legacyBytes, legacyHash, o.OrganizationID)
	if err != nil || !reflect.DeepEqual(plan.Probes, legacyPlan.Probes) || !reflect.DeepEqual(m.Projection, legacy.Projection) {
		t.Fatal("source metadata changed frozen requests or estimate")
	}
}

func TestAnalysisSourceTamperUnknownAndNoncanonicalReject(t *testing.T) {
	g := testGenerator(t)
	for _, source := range []string{"", domain.AnalysisSourceDerivedV1} {
		o := testOptions()
		o.AnalysisSourceVersion = source
		m, err := g.Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		changed := m
		if source == "" {
			changed.Options.AnalysisSourceVersion = domain.AnalysisSourceDerivedV1
		} else {
			changed.Options.AnalysisSourceVersion = ""
		}
		// Recomputing the database's plain hash cannot re-sign a deleted marker.
		data, hash, err := changed.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Verify(data, hash, o.OrganizationID); !errors.Is(err, ErrIntegrity) {
			t.Fatal("changed signed mode accepted")
		}
	}
	for _, source := range []string{"legacy", "mii.derived-s1.v2", "MII.DERIVED-S1.V1", "mii.derived-s1.v1 "} {
		o := testOptions()
		o.AnalysisSourceVersion = source
		if _, err := g.Generate(o); !errors.Is(err, ErrConfiguration) {
			t.Fatal("unknown generation mode accepted")
		}
		m, err := g.Generate(testOptions())
		if err != nil {
			t.Fatal(err)
		}
		m.Options.AnalysisSourceVersion = source
		if err := g.sign(&m); err != nil {
			t.Fatal(err)
		}
		data, hash, err := m.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := g.Verify(data, hash, m.Options.OrganizationID); !errors.Is(err, ErrIntegrity) {
			t.Fatal("authenticated but unsupported source mode accepted")
		}
	}
	m, err := g.Generate(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	data, _, err := m.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	for _, empty := range []string{`""`, `null`} {
		bad := bytes.Replace(data, []byte(`"options":{`), []byte(`"options":{"analysis_source_version":`+empty+`,`), 1)
		if _, err := g.Verify(bad, digest(bad), m.Options.OrganizationID); !errors.Is(err, ErrIntegrity) {
			t.Fatal("noncanonical explicit empty source mode accepted")
		}
	}
}
