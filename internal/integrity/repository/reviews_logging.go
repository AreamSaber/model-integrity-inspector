package repository

import (
	"fmt"
	"log/slog"
)

// Human notes and retry identities do not belong in generic diagnostics. The
// authorized ReviewView is the only serialization that intentionally exposes
// the note to readers; input hashing uses its own explicit private structure.
func (ReviewRecord) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("ReviewRecord{redacted}"))
}
func (ReviewInput) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("ReviewInput{redacted}"))
}
func (ReviewRecord) LogValue() slog.Value { return slog.StringValue("ReviewRecord{redacted}") }
func (ReviewInput) LogValue() slog.Value  { return slog.StringValue("ReviewInput{redacted}") }
func (ReviewInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"type":"review-input","redacted":true}`), nil
}
