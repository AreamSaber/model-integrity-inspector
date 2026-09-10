package repository

import (
	"fmt"
	"log/slog"
)

// User-entered review notes, source snapshots and approval authenticators must
// not enter generic diagnostics. Canonical signing uses an explicit structure;
// only the service's whitelist View is an HTTP response.
func (BaselineRecord) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("BaselineRecord{redacted}"))
}
func (BaselineRecord) LogValue() slog.Value  { return slog.StringValue("BaselineRecord{redacted}") }
func (*BaselineSource) LogValue() slog.Value { return slog.StringValue("BaselineSource{redacted}") }
func (BaselineApproval) Format(w fmt.State, _ rune) {
	_, _ = w.Write([]byte("BaselineApproval{redacted}"))
}
func (BaselineApproval) LogValue() slog.Value { return slog.StringValue("BaselineApproval{redacted}") }
func (BaselineApproval) MarshalJSON() ([]byte, error) {
	return []byte(`{"type":"baseline-approval","redacted":true}`), nil
}
