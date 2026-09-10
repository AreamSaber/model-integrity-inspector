package secret

import (
	"bytes"
	"testing"
)

func TestProbeMACPurposeRotationAndBoundaries(t *testing.T) {
	ring := testRing(t)
	payload := []byte(`{"org":"1","run_nonce":"synthetic"}`)
	mac, err := ring.ProbeMAC("one", payload)
	if err != nil || len(mac) != 32 {
		t.Fatal("probe MAC unavailable")
	}
	for _, other := range []func(string, []byte) ([]byte, error){ring.AuditMAC, ring.CursorMAC} {
		value, err := other("one", payload)
		if err != nil || bytes.Equal(mac, value) {
			t.Fatal("purposes not separated")
		}
	}
	rotated, err := ring.ProbeMAC("two", payload)
	if err != nil || bytes.Equal(mac, rotated) {
		t.Fatal("key versions not separated")
	}
	again, err := ring.ProbeMAC("one", payload)
	if err != nil || !bytes.Equal(mac, again) {
		t.Fatal("old version not replayable")
	}
	for _, data := range [][]byte{nil, make([]byte, 4097)} {
		if _, err := ring.ProbeMAC("one", data); err == nil {
			t.Fatal("unbounded signing input")
		}
	}
	if _, err := ring.ProbeMAC("unknown", payload); err == nil {
		t.Fatal("unknown key accepted")
	}
	if _, err := (*KeyRing)(nil).ProbeMAC("one", payload); err == nil {
		t.Fatal("nil key accepted")
	}
}
