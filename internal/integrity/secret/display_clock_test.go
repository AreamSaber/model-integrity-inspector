package secret

import (
	"context"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
)

func TestDisplayExplicitClockOverrideKeepsStrictValidity(t *testing.T) {
	ring, prepared, binding, now := displayFixture(t)
	defer prepared.Close()
	current := now
	calls := 0
	sealer, opener, err := ring.NewDisplayCapabilities(func() time.Time { calls++; return current })
	if err != nil {
		t.Fatal("construct explicit clock capability")
	}
	record, err := sealer.Seal(t.Context(), binding, prepared)
	if err != nil {
		t.Fatal("explicit equal-clock seal failed")
	}
	defer clear(record.Ciphertext)
	opened, err := opener.Open(t.Context(), binding, record)
	if err != nil {
		t.Fatal("explicit equal-clock open failed")
	}
	opened.Close()
	if calls != 4 {
		t.Fatal("explicit override did not receive both codec observations")
	}
	for _, boundary := range []string{"future_one_microsecond", "expiry_equal"} {
		t.Run(boundary, func(t *testing.T) {
			current = now.Add(-time.Microsecond)
			if boundary == "expiry_equal" {
				current = time.UnixMicro(binding.ExpiresAtMicros)
			}
			if _, err := sealer.Seal(t.Context(), binding, prepared); !errors.Is(err, ErrDisplayUnavailable) {
				t.Fatal("explicit seal validity boundary widened")
			}
			if value, err := opener.Open(t.Context(), binding, record); !errors.Is(err, ErrDisplayUnavailable) || value != nil {
				t.Fatal("explicit open validity boundary widened")
			}
		})
	}
	current = now
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := sealer.Seal(ctx, binding, prepared); !errors.Is(err, evidencedisplay.ErrCancelled) {
		t.Fatal("cancelled seal classification changed")
	}
	if value, err := opener.Open(ctx, binding, record); !errors.Is(err, evidencedisplay.ErrCancelled) || value != nil {
		t.Fatal("cancelled open classification changed")
	}
}
