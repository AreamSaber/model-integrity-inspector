package secret

import (
	"bytes"
	"errors"
	"testing"
)

func TestBaselineMACPurposeVersionAndBounds(t *testing.T) {
	k, err := NewKeyRing("v2", map[string][]byte{"v1": bytes.Repeat([]byte{1}, 32), "v2": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	input := []byte("synthetic-baseline-canonical-record")
	one, err := k.BaselineMAC("v1", input)
	if err != nil || len(one) != 32 {
		t.Fatal(err)
	}
	again, _ := k.BaselineMAC("v1", input)
	two, _ := k.BaselineMAC("v2", input)
	probe, _ := k.ProbeMAC("v1", input)
	audit, _ := k.AuditMAC("v1", input)
	if !bytes.Equal(one, again) || bytes.Equal(one, two) || bytes.Equal(one, probe) || bytes.Equal(one, audit) {
		t.Fatal("purpose/version separation")
	}
	for _, payload := range [][]byte{nil, {}, make([]byte, (256<<10)+1)} {
		if _, err := k.BaselineMAC("v1", payload); !errors.Is(err, ErrUnavailable) {
			t.Fatal("input bound")
		}
	}
	if _, err := k.BaselineMAC("unknown", input); !errors.Is(err, ErrUnavailable) {
		t.Fatal("unknown version")
	}
	var missing *KeyRing
	if _, err := missing.BaselineMAC("v1", input); !errors.Is(err, ErrUnavailable) {
		t.Fatal("missing keyring")
	}
}
