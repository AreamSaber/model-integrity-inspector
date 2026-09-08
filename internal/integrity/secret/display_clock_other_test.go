//go:build !windows

package secret

import (
	"testing"
	"time"
)

func TestDisplayDefaultOtherClockKeepsTimeNow(t *testing.T) {
	ring, prepared, binding, _ := displayFixture(t)
	defer prepared.Close()
	sealer, opener, err := ring.NewDisplayCapabilities(nil)
	if err != nil {
		t.Fatal("construct default capability")
	}
	before := time.Now()
	observed := sealer.now()
	after := time.Now()
	if observed.Before(before) || observed.After(after) {
		t.Fatal("non-Windows clock is no longer bracketed by time.Now")
	}
	binding.CapturedAtMicros = before.UnixMicro()
	binding.ExpiresAtMicros = before.Add(30 * 24 * time.Hour).UnixMicro()
	record, err := sealer.Seal(t.Context(), binding, prepared)
	if err != nil {
		t.Fatal("non-Windows default seal failed")
	}
	defer clear(record.Ciphertext)
	opened, err := opener.Open(t.Context(), binding, record)
	if err != nil {
		t.Fatal("non-Windows default open failed")
	}
	opened.Close()
}
