package evidencedisplay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func TestFinitePolicyDoesNotClaimRecursiveSecretDetection(t *testing.T) {
	once := base64.StdEncoding.EncodeToString([]byte(displayCanary))
	twice := base64.StdEncoding.EncodeToString([]byte(once))
	s := displaySource(t, func(s *Source) { s.Response.Content = twice })
	p, err := Prepare(context.Background(), s, []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if preparedDocument(t, p).Response.Content != twice {
		t.Fatal("finite one-layer policy unexpectedly changed")
	}
	// This is an explicit coverage limitation, not a guarantee of secret-free
	// plaintext: arbitrary nesting/encoding and third-party secrets are unknown.
}

func TestPrepareRefusesUnboundedSourceBeforeSerialization(t *testing.T) {
	for _, change := range []func(*Source){
		func(s *Source) { s.Request.Messages = make([]domain.NormalizedMessage, 257) },
		func(s *Source) { s.Request.Messages[0].Content = strings.Repeat("x", MaxTextBytes+1) },
		func(s *Source) { s.Request.Messages[0].Role = strings.Repeat("x", 17) },
		func(s *Source) { s.Request.Model = strings.Repeat("x", 129) },
		func(s *Source) { s.Request.Stop = []string{strings.Repeat("x", 257)} },
		func(s *Source) { s.Request.ExtraAllowedParams = map[string]any{"one": 1, "two": 2, "three": 3} },
		func(s *Source) {
			s.Request.ExtraAllowedParams = map[string]any{"frequency_penalty": json.Number(strings.Repeat("1", 65))}
		},
		func(s *Source) { s.Response.ParseWarnings = make([]string, 65) },
		func(s *Source) { s.Response.ParseWarnings = []string{strings.Repeat("x", 129)} },
		func(s *Source) { s.Response.HeaderSummary = map[string]string{strings.Repeat("x", 129): "value"} },
		func(s *Source) { s.Response.Events = make([]domain.StreamEventSummary, 257) },
	} {
		s := displaySource(t, nil)
		change(&s)
		if p, err := Prepare(context.Background(), s, []byte(displayCanary), nil); p != nil || !errors.Is(err, ErrLimit) {
			t.Fatal("source size not rejected before encoding")
		}
	}
}

func TestPrepareTypedObservationsDoNotInventMissingValues(t *testing.T) {
	s := displaySource(t, func(s *Source) {
		s.Response.ParseStatus = ""
		s.Response.FinishReason = "unrecognized-upstream-value"
		s.Response.HTTPStatus = 0
	})
	p, err := Prepare(context.Background(), s, []byte(displayCanary), map[string][]byte{"X-Empty": nil})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	v := preparedDocument(t, p).Response
	if v.PromptTokens != nil || v.CompletionTokens != nil || v.TotalTokens != nil || v.FirstTokenMS != nil || v.ParseStatus != "unobserved" || v.FinishReason != "unknown" {
		t.Fatal("missing observations fabricated")
	}
	negative := int64(-1)
	for _, change := range []func(*Source){func(s *Source) { s.Response.PromptTokens = &negative }, func(s *Source) { s.Response.FirstTokenMs = &negative }, func(s *Source) { s.Response.DurationMs = -1 }, func(s *Source) { s.Response.HTTPStatus = 600 }, func(s *Source) {
		s.Response.Events = []domain.StreamEventSummary{{Sequence: 2, Type: "done", ArrivalMs: 21}}
	}} {
		s := displaySource(t, change)
		if p, err := Prepare(context.Background(), s, []byte(displayCanary), nil); p != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid observation accepted")
		}
	}
}

func TestCanonicalDisplayDecoderRejectsContradictoryAuthenticatedFields(t *testing.T) {
	p, err := Prepare(context.Background(), displaySource(t, nil), []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	v := preparedDocument(t, p)
	source, request := p.Hashes()
	for _, change := range []func(*document){func(v *document) { v.Version = 2 }, func(v *document) { v.Policy = "other" }, func(v *document) { v.MetadataOmitted = false }, func(v *document) { v.RequestChanged = true }, func(v *document) { v.TemplateHash = strings.Repeat("b", 64) }, func(v *document) { v.RequestJSON = "not-json" }, func(v *document) { v.RequestHash = strings.Repeat("c", 64) }, func(v *document) { v.SourceHash = strings.Repeat("d", 64) }, func(v *document) { v.Response.ParseStatus = "unknown" }} {
		bad := v
		change(&bad)
		data, e := json.Marshal(bad)
		if e != nil {
			t.Fatal(e)
		}
		if result, e := DecodeAuthenticatedCanonical(data, source, request); result != nil || !errors.Is(e, ErrInvalid) {
			t.Fatal("contradictory payload accepted")
		}
	}
	if result, err := DecodeAuthenticatedCanonical(make([]byte, MaxPayloadBytes+1), source, request); result != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize decoder input accepted")
	}
	if result, err := DecodeAuthenticatedCanonical([]byte("{}"), "invalid", request); result != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid expected hash accepted")
	}
}

func TestDisplayExplicitCallbacksRemainBoundedAndClosed(t *testing.T) {
	p, err := Prepare(context.Background(), displaySource(t, nil), []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var data []byte
	if err := p.WithCanonicalForSeal(context.Background(), func(value []byte) error { data = bytes.Clone(value); return nil }); err != nil {
		t.Fatal(err)
	}
	source, request := p.Hashes()
	opened, err := DecodeAuthenticatedCanonical(data, source, request)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := opened.WithCanonicalForDisplay(ctx, func([]byte) error { t.Fatal("cancelled view callback ran"); return nil }); !errors.Is(err, ErrCancelled) {
		t.Fatal("cancelled callback accepted")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := p.WithCanonicalForSeal(ctx, func([]byte) error { cancel(); return nil }); !errors.Is(err, ErrCancelled) {
		t.Fatal("callback-time cancellation ignored")
	}
	if err := p.WithCanonicalForSeal(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil callback accepted")
	}
	opened.Close()
	if err := opened.WithCanonicalForDisplay(context.Background(), func([]byte) error { t.Fatal("closed view callback ran"); return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("closed view accepted")
	}
	var noPrepared *Prepared
	var noOpened *Opened
	noPrepared.Close()
	noOpened.Close()
	if _, hash := noPrepared.Hashes(); hash != "" {
		t.Fatal("nil prepared has a hash")
	}
	if err := noPrepared.WithCanonicalForSeal(context.Background(), func([]byte) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil prepared accepted")
	}
	if err := noOpened.WithCanonicalForDisplay(context.Background(), func([]byte) error { return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil opened accepted")
	}
}

func TestQuotedSizeMatchesEncoderForEscapedUTF8(t *testing.T) {
	for _, value := range []string{"plain", "\"\\\n\r\t\b\f", "<>&\x00\x01", "中文😀\u2028\u2029"} {
		encoded, err := json.Marshal(value)
		if err != nil || len(encoded) != quotedBytes(value) {
			t.Fatal("pre-allocation string sizing mismatch")
		}
	}
}

func TestFiniteVariantsMatchIndependentPublicVectors(t *testing.T) {
	// Fixed public vectors, not inputs generated by variants itself. This also
	// catches accidentally dropping a promised encoding from both sides of a test.
	value := "A+/&中😀"
	expected := []string{
		value, `A+/\u0026中😀`, `\u0041\u002b\u002f\u0026\u4e2d\ud83d\ude00`, `\u0041\u002B\u002F\u0026\u4E2D\uD83D\uDE00`,
		"A%2B%2F%26%E4%B8%AD%F0%9F%98%80", "A+%2F&%E4%B8%AD%F0%9F%98%80",
		"%41%2B%2F%26%E4%B8%AD%F0%9F%98%80", "%41%2b%2f%26%e4%b8%ad%f0%9f%98%80",
		"QSsvJuS4rfCfmIA=", "QSsvJuS4rfCfmIA", "QSsvJuS4rfCfmIA=", "QSsvJuS4rfCfmIA", "412b2f26e4b8adf09f9880", "412B2F26E4B8ADF09F9880",
	}
	actual := variants([]byte(value))
	if len(actual) != len(expected) {
		t.Fatal("finite encoding set changed")
	}
	for i, form := range expected {
		if actual[i] != form {
			t.Fatalf("public encoding vector %d changed", i)
		}
		source := displaySource(t, func(s *Source) { s.Response.Content = form })
		prepared, err := Prepare(context.Background(), source, []byte(value), nil)
		if err != nil {
			t.Fatal(err)
		}
		if preparedDocument(t, prepared).Response.Content != marker {
			t.Fatal("independent credential vector survived")
		}
		prepared.Close()
	}
	for _, form := range []string{"w7/Dv8O/", "w7_Dv8O_"} {
		source := displaySource(t, func(s *Source) { s.Response.Content = form })
		prepared, err := Prepare(context.Background(), source, []byte("ÿÿÿ"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if preparedDocument(t, prepared).Response.Content != marker {
			t.Fatal("standard/url-safe Base64 distinction lost")
		}
		prepared.Close()
	}
}
