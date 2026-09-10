package tokenizer

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dlclark/regexp2/v2"
)

type installedTestCounter struct{}

func (installedTestCounter) Count(string) (int, error) { return 0, nil }

func installedTestRejected(t *testing.T, data []byte, ref InstalledRef, want error) {
	t.Helper()
	a, err := VerifyInstalledArtifact(t.Context(), data, ref)
	if !errors.Is(err, want) || a != nil || err.Error() != want.Error() {
		t.Fatalf("invalid carrier returned partial result or unsafe error: %v", err)
	}
}

func TestInstalledTokenizerArtifactRejectsExternalIdentityAndFraming(t *testing.T) {
	_, a := installedTestArtifact(t)
	data, ref := a.Bytes(), a.Ref()
	for _, tc := range []struct {
		name string
		edit func(*InstalledRef)
	}{
		{"schema", func(r *InstalledRef) { r.SchemaVersion = "unknown" }},
		{"version", func(r *InstalledRef) { r.Version = "0.9.0" }},
		{"implementation", func(r *InstalledRef) { r.Implementation = "historical-unknown" }},
		{"configuration", func(r *InstalledRef) { r.ConfigurationSHA256 = strings.Repeat("0", 64) }},
		{"carrier_hash", func(r *InstalledRef) { r.SHA256 = strings.Repeat("0", 64) }},
		{"carrier_hash_alias", func(r *InstalledRef) { r.SHA256 = strings.ToUpper(r.SHA256) }},
		{"carrier_as_config", func(r *InstalledRef) { r.ConfigurationSHA256 = r.SHA256 }},
		{"config_as_carrier", func(r *InstalledRef) { r.SHA256 = r.ConfigurationSHA256 }},
		{"bytes_zero", func(r *InstalledRef) { r.Bytes = 0 }},
		{"bytes_overflow", func(r *InstalledRef) { r.Bytes = math.MaxInt64 }},
		{"bytes_changed", func(r *InstalledRef) { r.Bytes-- }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := ref
			tc.edit(&changed)
			installedTestRejected(t, data, changed, ErrInstalledArtifact)
		})
	}
	// Every resource is actually present, and changing a byte under the old
	// anchor fails. Rehashing each malformed carrier below must also fail.
	for _, position := range []int{0, len(installedMagic), len(data) / 2, len(data) - 1} {
		changed := bytes.Clone(data)
		changed[position] ^= 1
		installedTestRejected(t, changed, ref, ErrInstalledArtifact)
	}
	for _, size := range []int{0, 1, len(installedMagic) - 1, len(installedMagic), len(installedMagic) + 1, 100, len(data) - 1} {
		changed := bytes.Clone(data[:size])
		anchor := ref
		anchor.SHA256, anchor.Bytes = installedTestHash(changed), int64(len(changed))
		installedTestRejected(t, changed, anchor, ErrInstalledArtifact)
	}
	for _, edit := range []func([]byte) []byte{
		func(v []byte) []byte { v[0] ^= 1; return v },
		func(v []byte) []byte { v[len(installedMagic)] = 4; return v },
		func(v []byte) []byte { v[len(installedMagic)] = 6; return v },
		func(v []byte) []byte { v[len(installedMagic)+1] = 0xff; return v },
		func(v []byte) []byte { v[len(installedMagic)+3] = '/'; return v },
		func(v []byte) []byte {
			binary.BigEndian.PutUint64(v[len(installedMagic)+3+len("implementation"):], math.MaxUint64)
			return v
		},
		func(v []byte) []byte {
			binary.BigEndian.PutUint64(v[len(installedMagic)+3+len("implementation"):], 0)
			return v
		},
		func(v []byte) []byte { return append(v, 0) },
		func(v []byte) []byte { return append(v, []byte("private-appended-canary")...) },
	} {
		changed := edit(bytes.Clone(data))
		anchor := ref
		anchor.SHA256, anchor.Bytes = installedTestHash(changed), int64(len(changed))
		installedTestRejected(t, changed, anchor, ErrInstalledArtifact)
	}
	oversize := make([]byte, MaxInstalledArtifactBytes+1)
	installedTestRejected(t, oversize, ref, ErrLimit)
	boundary := oversize[:MaxInstalledArtifactBytes]
	boundaryRef := ref
	boundaryRef.SHA256, boundaryRef.Bytes = installedTestHash(boundary), int64(len(boundary))
	installedTestRejected(t, boundary, boundaryRef, ErrInstalledArtifact)
	var missing context.Context
	if a, err := VerifyInstalledArtifact(missing, data, ref); !errors.Is(err, ErrInstalledArtifact) || a != nil {
		t.Fatal("nil context accepted")
	}
}

func TestInstalledTokenizerArtifactRehashedResourceChangesStillFail(t *testing.T) {
	_, a := installedTestArtifact(t)
	base := installedTestParts(t, a.Bytes())
	for _, tc := range []struct {
		name string
		part int
		edit func([]byte) []byte
	}{
		{"metadata_byte", 0, func(v []byte) []byte { v[len(v)/2] ^= 1; return v }},
		{"metadata_unknown", 0, func(v []byte) []byte {
			return bytes.Replace(v, []byte("{"), []byte(`{"arbitrary_plugin":"private-code-canary",`), 1)
		}},
		{"metadata_duplicate", 0, func(v []byte) []byte { return bytes.Replace(v, []byte("{"), []byte(`{"Version":"1.0.0",`), 1) }},
		{"metadata_alias", 0, func(v []byte) []byte { return bytes.Replace(v, []byte(`"Version"`), []byte(`"version"`), 1) }},
		{"metadata_unknown_regex", 0, func(v []byte) []byte {
			var m installedMetadata
			if json.Unmarshal(v, &m) != nil {
				t.Fatal("fixture metadata")
			}
			m.CLPattern = ".*"
			out, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			return out
		}},
		{"config_byte", 1, func(v []byte) []byte { v[len(v)/2] ^= 1; return v }},
		{"config_no_lf", 1, func(v []byte) []byte { return v[:len(v)-1] }},
		{"config_add_lf", 1, func(v []byte) []byte { return append(v, '\n') }},
		{"config_version", 1, func(v []byte) []byte { return bytes.Replace(v, []byte(`"1.0.0"`), []byte(`"0.9.0"`), 1) }},
		{"cl_byte", 2, func(v []byte) []byte { v[0] = 'J'; return v }},
		{"cl_missing_rank", 2, func(v []byte) []byte { return v[bytes.IndexByte(v, '\n')+1:] }},
		{"cl_duplicate_rank", 2, func(v []byte) []byte {
			first := bytes.IndexByte(v, '\n') + 1
			return append(bytes.Clone(v[:first]), v...)
		}},
		{"cl_rank_alias", 2, func(v []byte) []byte { return bytes.Replace(v, []byte(" 0\n"), []byte(" 00\n"), 1) }},
		{"cl_rank_order", 2, func(v []byte) []byte { return bytes.Replace(v, []byte(" 0\n"), []byte(" 1\n"), 1) }},
		{"cl_invalid_base64", 2, func(v []byte) []byte { v[0] = '!'; return v }},
		{"cl_bad_pad_bits", 2, func(v []byte) []byte { return bytes.Replace(v, []byte("IQ=="), []byte("IR=="), 1) }},
		{"cl_no_final_lf", 2, func(v []byte) []byte { return v[:len(v)-1] }},
		{"cl_extra_line", 2, func(v []byte) []byte { return append(v, []byte("eA== 100256\n")...) }},
		{"o_byte", 3, func(v []byte) []byte { v[len(v)-10] ^= 1; return v }},
		{"notice_byte", 4, func(v []byte) []byte { v[0] ^= 1; return v }},
		{"notice_shortened", 4, func(v []byte) []byte { return v[:100] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var parts [5][]byte
			for i := range parts {
				parts[i] = bytes.Clone(base[i])
			}
			parts[tc.part] = tc.edit(parts[tc.part])
			if bytes.Equal(parts[tc.part], base[tc.part]) {
				t.Fatal("mutation missed intended source")
			}
			data, err := encodeInstalledParts(t.Context(), parts)
			if err != nil {
				t.Fatal("encode bounded test mutation", err)
			}
			ref := a.Ref()
			ref.SHA256, ref.Bytes = installedTestHash(data), int64(len(data))
			installedTestRejected(t, data, ref, ErrInstalledArtifact)
		})
	}
	// Swap entire encoding parts with their names left in place. The fixed
	// internal encoding identities must reject this otherwise framed carrier.
	var parts [5][]byte
	for i := range parts {
		parts[i] = bytes.Clone(base[i])
	}
	parts[2], parts[3] = parts[3], parts[2]
	if _, err := encodeInstalledParts(t.Context(), parts); !errors.Is(err, ErrLimit) {
		t.Fatal("cl-specific bound accepted the larger o resource")
	}
	// Write actual binary NAME fields independently, rather than accidentally
	// mutating matching text in the embedded configuration resource.
	for _, names := range [][5]string{
		{"implementation", "configuration", "unknown", "o200k_base", "notices"},
		{"implementation", "configuration", "o200k_base", "o200k_base", "notices"},
		{"implementation", "implementation", "cl100k_base", "o200k_base", "notices"},
		{"implementation", "configuration", "../outside", "o200k_base", "notices"},
		{"configuration", "implementation", "cl100k_base", "o200k_base", "notices"},
	} {
		var framed bytes.Buffer
		_, _ = framed.WriteString("MII-TOKENIZER-INSTALLED-V1\n")
		_ = framed.WriteByte(5)
		for i, name := range names {
			nameSize := len(name)
			if nameSize < 1 || nameSize > 65535 {
				t.Fatal("test resource name overflow")
				return
			}
			if err := binary.Write(&framed, binary.BigEndian, uint16(nameSize)); err != nil {
				t.Fatal(err)
			}
			_, _ = framed.WriteString(name)
			if err := binary.Write(&framed, binary.BigEndian, uint64(len(base[i]))); err != nil {
				t.Fatal(err)
			}
			_, _ = framed.Write(base[i])
		}
		data := framed.Bytes()
		ref := a.Ref()
		ref.SHA256, ref.Bytes = installedTestHash(data), int64(len(data))
		installedTestRejected(t, data, ref, ErrInstalledArtifact)
	}
}

func TestInstalledTokenizerRankDecoderRejectsStructuralDamage(t *testing.T) {
	// Small private parser fixtures exercise structure independently of the
	// real official digest. No public API accepts this invented vocabulary.
	good := []byte("IQ== 0\nIg== 1\n/w== 2\n")
	identity := encodingArtifact{ID: "cl100k_base", Tokens: 3, SHA256: installedTestHash(good)}
	ranks, err := decodeInstalledRanks(t.Context(), good, identity)
	if err != nil || ranks["!"] != 0 || ranks["\xff"] != 2 {
		t.Fatal("canonical private parser fixture")
	}
	for _, bad := range [][]byte{nil, []byte("IQ== 0\n"), []byte("IQ== 0\nIQ== 1\n/w== 2\n"), []byte("IR== 0\nIg== 1\n/w== 2\n"), []byte("IQ== 0\r\nIg== 1\n/w== 2\n"), []byte("IQ== 00\nIg== 1\n/w== 2\n"), []byte("IQ== +0\nIg== 1\n/w== 2\n"), []byte("IQ== 1\nIg== 0\n/w== 2\n"), []byte("IQ== 0 \nIg== 1\n/w== 2\n"), []byte("IQ== 0\nIg== 1\n/w== 2"), append(bytes.Clone(good), '\n'), []byte(strings.Repeat("A", 1381) + " 0\n"), []byte(" 0\nIg== 1\n/w== 2\n")} {
		changed := identity
		changed.SHA256 = installedTestHash(bad)
		if got, err := decodeInstalledRanks(t.Context(), bad, changed); !errors.Is(err, ErrInstalledArtifact) || got != nil {
			t.Fatal("structural rank damage accepted despite coherent self-hash")
		}
	}
	for _, count := range []int{0, 2, 4, 200001} {
		changed := identity
		changed.Tokens = count
		if got, err := decodeInstalledRanks(t.Context(), good, changed); !errors.Is(err, ErrInstalledArtifact) || got != nil {
			t.Fatal("wrong rank cardinality accepted")
		}
	}
	for _, bad := range []map[string]int{nil, {"!": 0, "\"": 0, "\xff": 2}, {"!": -1, "\"": 1, "\xff": 2}, {"!": 0, "\"": 1, "\xff": 3}, {"": 0, "\"": 1, "\xff": 2}, {strings.Repeat("x", 1025): 0, "\"": 1, "\xff": 2}} {
		if data, err := installedRankBytes(t.Context(), bad, identity, 4096); !errors.Is(err, ErrInstalledArtifact) || data != nil {
			t.Fatal("bad actual engine ranks exported")
		}
	}
	if got, err := installedRankBytes(t.Context(), ranks, identity, len(good)); err != nil || !bytes.Equal(got, good) {
		t.Fatal("exact byte limit rejected")
	}
	if got, err := installedRankBytes(t.Context(), ranks, identity, len(good)-1); !errors.Is(err, ErrLimit) || got != nil {
		t.Fatal("byte limit yielded partial rank file")
	}
}

// Err delegates to a real cancelable context, cancelling deterministically at
// an observed checkpoint inside bounded work. No sleep/timing race or product
// test hook is needed to cover cancellation during the second vocabulary.
type installedCancelContext struct {
	context.Context
	calls  atomic.Int64
	after  int64
	cancel context.CancelFunc
}

func (c *installedCancelContext) Err() error {
	if c.calls.Add(1) == c.after {
		c.cancel()
	}
	return c.Context.Err()
}

func TestInstalledTokenizerArtifactCancellationAndSourceGuards(t *testing.T) {
	e, a := installedTestArtifact(t)
	for _, after := range []int64{1, 350} {
		base, cancel := context.WithCancel(t.Context())
		ctx := &installedCancelContext{Context: base, after: after, cancel: cancel}
		got, err := e.InstalledArtifact(ctx)
		cancel()
		if !errors.Is(err, context.Canceled) || got != nil || ctx.calls.Load() < after {
			t.Fatal("cancel during actual source export returned partial carrier")
		}
		base, cancel = context.WithCancel(t.Context())
		ctx = &installedCancelContext{Context: base, after: after, cancel: cancel}
		got, err = VerifyInstalledArtifact(ctx, a.Bytes(), a.Ref())
		cancel()
		if !errors.Is(err, context.Canceled) || got != nil || ctx.calls.Load() < after {
			t.Fatal("cancel during actual archived vocabulary validation returned partial candidate")
		}
		base, cancel = context.WithCancel(t.Context())
		ctx = &installedCancelContext{Context: base, after: after, cancel: cancel}
		restored, err := a.NewEngine(ctx)
		cancel()
		if !errors.Is(err, context.Canceled) || restored != nil || ctx.calls.Load() < after {
			t.Fatal("cancel during reconstruction returned partially restored engine")
		}
	}
	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	if got, err := e.InstalledArtifact(expired); !errors.Is(err, context.DeadlineExceeded) || got != nil {
		t.Fatal("expired export deadline accepted")
	}
	if got, err := VerifyInstalledArtifact(expired, a.Bytes(), a.Ref()); !errors.Is(err, context.DeadlineExceeded) || got != nil {
		t.Fatal("expired verify deadline accepted")
	}
	if got, err := a.NewEngine(expired); !errors.Is(err, context.DeadlineExceeded) || got != nil {
		t.Fatal("expired restore deadline accepted")
	}
	var missing context.Context
	if got, err := e.InstalledArtifact(missing); !errors.Is(err, ErrInstalledArtifact) || got != nil {
		t.Fatal("missing context exported")
	}
	for _, change := range []func(*Engine){
		func(e *Engine) { e.hash = "unknown" },
		func(e *Engine) { e.bundle.Version = "0.9.0" },
		func(e *Engine) { e.bundle.Implementation = "unknown" },
		func(e *Engine) { e.bundle.Models[0].Encoding = "o200k_base" },
		func(e *Engine) { e.codecs = nil },
		func(e *Engine) { e.work = nil },
		func(e *Engine) { e.codecs["cl100k_base"] = (*boundedBPE)(nil) },
		func(e *Engine) { e.codecs["cl100k_base"] = installedTestCounter{} },
		func(e *Engine) {
			ranks := e.codecs["cl100k_base"].(*boundedBPE).ranks
			ranks["!"], ranks["\""] = ranks["\""], ranks["!"]
		},
		func(e *Engine) { e.codecs["cl100k_base"].(*boundedBPE).split = nil },
		func(e *Engine) { e.codecs["cl100k_base"].(*boundedBPE).split.MatchTimeout = time.Hour },
		func(e *Engine) {
			re, err := regexp2.Compile(".*", regexp2.None)
			if err != nil {
				t.Fatal(err)
			}
			e.codecs["cl100k_base"].(*boundedBPE).split = re
		},
	} {
		copy, err := a.NewEngine(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		change(copy)
		if got, err := copy.InstalledArtifact(t.Context()); !errors.Is(err, ErrInstalledArtifact) || got != nil {
			t.Fatal("unrecognized or malformed live Engine exported")
		}
	}
}

func TestInstalledTokenizerArtifactConcurrentDetachedRestores(t *testing.T) {
	e, a := installedTestArtifact(t)
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			exported, err := e.InstalledArtifact(t.Context())
			if err != nil || exported.Ref() != a.Ref() {
				t.Error("concurrent immutable export")
				return
			}
			copy, err := exported.NewEngine(t.Context())
			if err != nil {
				t.Error("concurrent independent restore")
				return
			}
			count, err := copy.CountOutput("hello world", Selection{RequestedModel: "gpt-4o"})
			if err != nil || count.Tokens == nil || *count.Tokens != 2 || count.Quality != Exact {
				t.Error("concurrent actual restored counter")
			}
		})
	}
	wg.Wait()
}

func FuzzInstalledTokenizerArtifactFraming(f *testing.F) {
	ctx := context.Background()
	seed, err := encodeInstalledParts(ctx, [5][]byte{[]byte("{}"), []byte("{}\n"), []byte("IQ== 0\n"), []byte("IQ== 0\n"), []byte("MIT notice fixture")})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte("MII-TOKENIZER-INSTALLED-V1\n"))
	f.Add([]byte("private-invalid-framing"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxInstalledArtifactBytes+1 {
			return
		}
		parts, err := decodeInstalledParts(ctx, data)
		if err != nil {
			for _, part := range parts {
				if part != nil {
					t.Fatal("framing failure returned partial resource slices")
				}
			}
			return
		}
		canonical, err := encodeInstalledParts(ctx, parts)
		if err != nil || !bytes.Equal(data, canonical) {
			t.Fatal("accepted noncanonical framing or mismatched limits")
		}
	})
}

type installedMutationContext struct {
	context.Context
	calls  int
	action func()
}

func (c *installedMutationContext) Err() error {
	c.calls++
	if c.calls == 5 {
		c.action()
	}
	return c.Context.Err()
}

func TestInstalledTokenizerArtifactOwnsInputBeforeVerification(t *testing.T) {
	_, artifact := installedTestArtifact(t)
	data := artifact.Bytes()
	ctx := &installedMutationContext{Context: t.Context(), action: func() { data[0] ^= 1 }}
	verified, err := VerifyInstalledArtifact(ctx, data, artifact.Ref())
	if err != nil || verified == nil || data[0] == artifact.data[0] || !bytes.Equal(verified.Bytes(), artifact.Bytes()) {
		t.Fatal("verifier did not own its input before validation")
	}
	if ctx.calls < 5 {
		t.Fatal("mutation checkpoint was not exercised")
	}
}
