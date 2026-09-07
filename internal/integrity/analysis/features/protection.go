package features

import (
	"fmt"
	"io"
	"log/slog"
)

const redacted = "[redacted feature input]"

func (Input) String() string                             { return redacted }
func (Input) Format(w fmt.State, _ rune)                 { _, _ = io.WriteString(w, redacted) }
func (Input) MarshalJSON() ([]byte, error)               { return []byte(`"` + redacted + `"`), nil }
func (Input) LogValue() slog.Value                       { return slog.StringValue(redacted) }
func (RunBinding) String() string                        { return redacted }
func (RunBinding) Format(w fmt.State, _ rune)            { _, _ = io.WriteString(w, redacted) }
func (RunBinding) MarshalJSON() ([]byte, error)          { return []byte(`"` + redacted + `"`), nil }
func (RunBinding) LogValue() slog.Value                  { return slog.StringValue(redacted) }
func (SampleBinding) String() string                     { return redacted }
func (SampleBinding) Format(w fmt.State, _ rune)         { _, _ = io.WriteString(w, redacted) }
func (SampleBinding) MarshalJSON() ([]byte, error)       { return []byte(`"` + redacted + `"`), nil }
func (SampleBinding) LogValue() slog.Value               { return slog.StringValue(redacted) }
func (AttemptBinding) String() string                    { return redacted }
func (AttemptBinding) Format(w fmt.State, _ rune)        { _, _ = io.WriteString(w, redacted) }
func (AttemptBinding) MarshalJSON() ([]byte, error)      { return []byte(`"` + redacted + `"`), nil }
func (AttemptBinding) LogValue() slog.Value              { return slog.StringValue(redacted) }
func (Evidence) String() string                          { return redacted }
func (Evidence) Format(w fmt.State, _ rune)              { _, _ = io.WriteString(w, redacted) }
func (Evidence) MarshalJSON() ([]byte, error)            { return []byte(`"` + redacted + `"`), nil }
func (Evidence) LogValue() slog.Value                    { return slog.StringValue(redacted) }
func (Batch) String() string                             { return redacted }
func (Batch) Format(w fmt.State, _ rune)                 { _, _ = io.WriteString(w, redacted) }
func (Batch) MarshalJSON() ([]byte, error)               { return []byte(`"` + redacted + `"`), nil }
func (Batch) LogValue() slog.Value                       { return slog.StringValue(redacted) }
func (OpaqueTokenInput) String() string                  { return redacted }
func (OpaqueTokenInput) Format(w fmt.State, _ rune)      { _, _ = io.WriteString(w, redacted) }
func (OpaqueTokenInput) MarshalJSON() ([]byte, error)    { return []byte(`"` + redacted + `"`), nil }
func (OpaqueTokenInput) LogValue() slog.Value            { return slog.StringValue(redacted) }
func (OpaqueBehaviorInput) String() string               { return redacted }
func (OpaqueBehaviorInput) Format(w fmt.State, _ rune)   { _, _ = io.WriteString(w, redacted) }
func (OpaqueBehaviorInput) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }
func (OpaqueBehaviorInput) LogValue() slog.Value         { return slog.StringValue(redacted) }
func (Config) String() string                            { return redacted }
func (Config) Format(w fmt.State, _ rune)                { _, _ = io.WriteString(w, redacted) }
func (Config) MarshalJSON() ([]byte, error)              { return []byte(`"` + redacted + `"`), nil }
func (Config) LogValue() slog.Value                      { return slog.StringValue(redacted) }
func (Builder) String() string                           { return redacted }
func (Builder) Format(w fmt.State, _ rune)               { _, _ = io.WriteString(w, redacted) }
func (Builder) MarshalJSON() ([]byte, error)             { return []byte(`"` + redacted + `"`), nil }
func (Builder) LogValue() slog.Value                     { return slog.StringValue(redacted) }
