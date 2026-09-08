package secret

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func derivedDomain(version string, payload []byte) []byte {
	return append([]byte("mii/derived-s1/auth/v1\x00mii.derived-s1.v1\x00"+version+"\x00"), payload...)
}

func TestDerivedSourceMACPurposeIsolationAndCopies(t *testing.T) {
	ring := testRing(t)
	capability, err := ring.NewDerivedSourceMAC()
	if err != nil {
		t.Fatal(err)
	}
	message := derivedDomain("one", []byte(`{"sample_id":"123"}`))
	first, err := capability.DerivedMAC("one", message)
	if err != nil || len(first) != sha256.Size {
		t.Fatal("derived source authentication failed")
	}
	keys := ring.keys["one"]
	for _, key := range [][]byte{keys.wrap, keys.fingerprint, keys.audit, keys.cursor, keys.probe, keys.evidence, keys.baseline, keys.display} {
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(message)
		if bytes.Equal(first, mac.Sum(nil)) || bytes.Equal(key, keys.derivedSource) {
			t.Fatal("purpose isolation failed")
		}
	}
	ring.keys["one"].derivedSource[0] ^= 1
	second, err := capability.DerivedMAC("one", message)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("capability retained mutable parent key bytes")
	}
	second[0] ^= 1
	third, err := capability.DerivedMAC("one", message)
	if err != nil || !bytes.Equal(first, third) {
		t.Fatal("caller mutated later MAC")
	}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			mac, err := capability.DerivedMAC("one", message)
			if err != nil || !bytes.Equal(first, mac) {
				t.Error("concurrent independent capability changed")
			}
		})
	}
	wg.Wait()
}

func TestDerivedSourceRejectsOtherDomainsAndUnconfiguredVersions(t *testing.T) {
	capability, _ := testRing(t).NewDerivedSourceMAC()
	for _, tc := range []struct {
		version string
		value   []byte
	}{
		{"", derivedDomain("one", []byte("x"))}, {"missing", derivedDomain("missing", []byte("x"))},
		{"one", nil}, {"one", []byte("x")}, {"one", derivedDomain("two", []byte("x"))},
		{"one", derivedDomain("one", nil)}, {"one", derivedDomain("one", bytes.Repeat([]byte("x"), (32<<10)+1))},
		{"one", []byte("mii/derived-s1/auth/v2\x00mii.derived-s1.v1\x00one\x00x")},
	} {
		if value, err := capability.DerivedMAC(tc.version, tc.value); len(value) != 0 || !errors.Is(err, ErrDerivedSourceUnavailable) {
			t.Fatal("invalid authentication input accepted")
		}
	}
	if value, err := capability.DerivedMAC("one", derivedDomain("one", bytes.Repeat([]byte("x"), 32<<10))); err != nil || len(value) != 32 {
		t.Fatal("exact size bound rejected")
	}
	var missing *KeyRing
	for _, ring := range []*KeyRing{missing, {}, {active: "one", keys: map[string]keySet{}}, {active: "one", keys: map[string]keySet{"one": {derivedSource: []byte("bad")}}}} {
		if _, err := ring.NewDerivedSourceMAC(); !errors.Is(err, ErrDerivedSourceUnavailable) {
			t.Fatal("invalid ring accepted")
		}
	}
	var absent *DerivedSourceMAC
	if value, err := absent.DerivedMAC("one", derivedDomain("one", []byte("x"))); len(value) != 0 || !errors.Is(err, ErrDerivedSourceUnavailable) {
		t.Fatal("nil capability accepted")
	}
}

func TestDerivedSourceVersionsAndSafeDiagnostics(t *testing.T) {
	master := bytes.Repeat([]byte("A"), 32)
	ring, err := NewKeyRing("UPPER.2", map[string][]byte{"UPPER.2": master, "old.1": bytes.Repeat([]byte("B"), 32)})
	if err != nil {
		t.Fatal(err)
	}
	capability, err := ring.NewDerivedSourceMAC()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"UPPER.2", "old.1"} {
		if value, err := capability.DerivedMAC(version, derivedDomain(version, []byte("{}"))); err != nil || len(value) != 32 {
			t.Fatal("configured historical version failed")
		}
	}
	for _, value := range []any{capability, *capability} {
		for _, format := range []string{"%v", "%+v", "%#v"} {
			if fmt.Sprintf(format, value) != "[derived-S1-only authenticator]" {
				t.Fatal("authenticator formatting exposed fields")
			}
		}
		if raw, err := json.Marshal(value); len(raw) != 0 || !errors.Is(err, ErrSensitive) {
			t.Fatal("authenticator serialized")
		}
		var out bytes.Buffer
		slog.New(slog.NewJSONHandler(&out, nil)).Info("test", "capability", value)
		if strings.Contains(out.String(), "UPPER.2") || strings.Contains(out.String(), hex.EncodeToString(ring.keys["UPPER.2"].derivedSource)) {
			t.Fatal("authenticator log leaked private state")
		}
	}
	typ := reflect.TypeFor[*DerivedSourceMAC]()
	for i := 0; i < typ.NumMethod(); i++ {
		switch typ.Method(i).Name {
		case "DerivedMAC", "Format", "String", "MarshalJSON", "LogValue":
		default:
			t.Fatal("authenticator exposes another capability")
		}
	}
	for i := 0; i < typ.Elem().NumField(); i++ {
		if typ.Elem().Field(i).Type == reflect.TypeFor[*KeyRing]() {
			t.Fatal("authenticator retained KeyRing")
		}
	}
}
