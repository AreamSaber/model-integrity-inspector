package secret

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func preciseDisplayTestNow() time.Time {
	var ft windows.Filetime
	windows.GetSystemTimePreciseAsFileTime(&ft)
	return time.Unix(0, ft.Nanoseconds()).UTC()
}

func TestDisplayDefaultWindowsClockBracketsRealCodec(t *testing.T) {
	ring, prepared, binding, _ := displayFixture(t)
	defer prepared.Close()
	sealer, opener, err := ring.NewDisplayCapabilities(nil)
	if err != nil {
		t.Fatal("construct default display capability")
	}
	for i := 0; i < 32; i++ {
		before := preciseDisplayTestNow()
		observed := sealer.now()
		after := preciseDisplayTestNow()
		if observed.Before(before) || observed.After(after) {
			t.Fatal("default display clock falls outside native precise observation interval")
		}
		binding.CapturedAtMicros = before.UnixMicro()
		binding.ExpiresAtMicros = before.Add(30 * 24 * time.Hour).UnixMicro()
		original := binding
		record, err := sealer.Seal(context.Background(), binding, prepared)
		if err != nil {
			t.Fatal("default precise-clock codec rejected actual prepared input")
		}
		opened, err := opener.Open(context.Background(), binding, record)
		if err != nil {
			t.Fatal("default precise-clock opener rejected actual sealed input")
		}
		opened.Close()
		clear(record.Ciphertext)
		clear(record.Nonce)
		if original != binding {
			t.Fatal("codec adjusted the capture or expiry binding")
		}
		before = preciseDisplayTestNow()
		observed = opener.now()
		after = preciseDisplayTestNow()
		if observed.Before(before) || observed.After(after) {
			t.Fatal("default opener clock falls outside native precise observation interval")
		}
	}
}
