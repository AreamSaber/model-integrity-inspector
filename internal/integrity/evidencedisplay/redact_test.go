package evidencedisplay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

const displayCanary = "synthetic-display-key-CANARY-9e47"
const headerCanary = "synthetic-header-value-CANARY-24ab"

func displaySource(t testing.TB, change func(*Source)) Source {
	t.Helper()
	s := Source{Request: domain.NormalizedRequest{Model: "test-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "Return a synthetic probe."}}, MaxOutputTokens: 64}, Response: domain.NormalizedResponse{Content: "Synthetic response.", ModelReported: "test-model", HTTPStatus: 200, ParseStatus: "valid", FinishReason: "stop", DurationMs: 20}}
	if change != nil {
		change(&s)
	}
	a, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", Doer: noNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	request, snapshot, err := a.BuildRequest(context.Background(), s.Request)
	if err != nil {
		t.Fatal("invalid synthetic source")
	}
	_ = request.Body.Close()
	s.Snapshot = snapshot
	return s
}

func preparedDocument(t testing.TB, p *Prepared) document {
	t.Helper()
	var result document
	if err := p.WithCanonicalForSeal(context.Background(), func(data []byte) error { return json.Unmarshal(data, &result) }); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPrepareRedactsActualValuesAndEveryFiniteVariant(t *testing.T) {
	for _, secretValue := range []string{displayCanary, headerCanary, "utf8-密钥-😀-value"} {
		for i, form := range variants([]byte(secretValue)) {
			t.Run(fmt.Sprintf("variant-%d-%d", len(secretValue), i), func(t *testing.T) {
				s := displaySource(t, func(s *Source) {
					s.Response.Content = "before " + form + " after"
					s.Request.Messages[0].Content = "before " + form + " after"
				})
				p, err := Prepare(context.Background(), s, []byte(displayCanary), map[string][]byte{"X-Ordinary-Header": []byte(secretValue)})
				if err != nil {
					t.Fatal(err)
				}
				defer p.Close()
				v := preparedDocument(t, p)
				if v.Response.Content != "before "+marker+" after" || strings.Contains(v.RequestJSON, form) || !strings.Contains(v.RequestJSON, marker) || !v.RequestChanged || !v.MetadataOmitted {
					t.Fatal("known credential variant not removed")
				}
			})
		}
	}
}

func TestPreparePreservesInputsNumbersAndAnalysis(t *testing.T) {
	seed := int64(9223372036854775807)
	s := displaySource(t, func(s *Source) {
		s.Request.Seed = &seed
		s.Request.Stream = true
		s.Response.Content = "<script>ignored markup</script> " + displayCanary
		s.Response.ModelReported = displayCanary
		s.Response.ProviderRequestID = headerCanary
		s.Response.HeaderSummary = map[string]string{"X-Request-Id": headerCanary}
		s.Response.DurationMs = 20
		s.Response.StreamChunkCount = 25
		s.Response.Events = []domain.StreamEventSummary{{Sequence: 1, Type: "content_delta", Bytes: 64, ArrivalMs: 1, IntervalMs: 1}, {Sequence: 25, Type: "done", Bytes: 8, ArrivalMs: 20, IntervalMs: 1}}
	})
	responseBefore, _ := json.Marshal(s.Response)
	requestBefore, _ := json.Marshal(s.Request)
	snapshotBefore := bytes.Clone(s.Snapshot.Payload)
	key := []byte(displayCanary)
	headers := map[string][]byte{"X-Test": []byte(headerCanary)}
	p, err := Prepare(context.Background(), s, key, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	v := preparedDocument(t, p)
	responseAfter, _ := json.Marshal(s.Response)
	requestAfter, _ := json.Marshal(s.Request)
	if !bytes.Equal(responseBefore, responseAfter) || !bytes.Equal(requestBefore, requestAfter) || !bytes.Equal(snapshotBefore, s.Snapshot.Payload) || string(key) != displayCanary || string(headers["X-Test"]) != headerCanary {
		t.Fatal("display changed an analysis/source/credential input")
	}
	if v.RequestChanged || v.TemplateHash != s.Snapshot.RequestHash || !strings.Contains(v.RequestJSON, "9223372036854775807") || !v.Response.EventSummaryPartial || v.Response.ModelReported != marker || v.Response.Content != "<script>ignored markup</script> "+marker {
		t.Fatal("display corrupted values or claimed full event history")
	}
	if err := p.WithCanonicalForSeal(context.Background(), func(data []byte) error {
		if bytes.Contains(data, []byte("<script>")) || bytes.Contains(data, []byte(headerCanary)) {
			t.Fatal("unescaped markup or dropped metadata leaked")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPrepareAllHeaderValuesNotJustAuthenticationNames(t *testing.T) {
	headers := map[string][]byte{}
	text := []string{}
	for i := range 32 {
		value := fmt.Sprintf("ordinary-sensitive-value-%02d", i)
		headers[fmt.Sprintf("X-Field-%02d", i)] = []byte(value)
		text = append(text, value)
	}
	s := displaySource(t, func(s *Source) { s.Response.Content = strings.Join(text, " ") })
	p, err := Prepare(context.Background(), s, []byte(displayCanary), headers)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if preparedDocument(t, p).Response.Content != strings.TrimSpace(strings.Repeat(marker+" ", 32)) {
		t.Fatal("ordinary header values were skipped")
	}
}

func TestPrepareOverlapDeterminismAndUnicodeForms(t *testing.T) {
	long := headerCanary + "-suffix"
	s := displaySource(t, func(s *Source) { s.Response.Content = long + " " + headerCanary })
	var previous string
	for range 8 {
		p, err := Prepare(context.Background(), s, []byte(displayCanary), map[string][]byte{"X-Short": []byte(headerCanary), "X-Long": []byte(long)})
		if err != nil {
			t.Fatal(err)
		}
		v := preparedDocument(t, p)
		p.Close()
		if v.Response.Content != marker+" "+marker || previous != "" && v.SourceHash != previous {
			t.Fatal("overlap order was nondeterministic")
		}
		previous = v.SourceHash
	}
	forms := variants([]byte("JA😀"))
	if !strings.Contains(strings.Join(forms, "|"), `\u004A\u0041\uD83D\uDE00`) {
		t.Fatal("uppercase Unicode hex changed lowercase u syntax")
	}
}

func TestPreparePolicyAndResourceFailuresAreClosed(t *testing.T) {
	for _, item := range []struct {
		name    string
		change  func(*Source)
		key     []byte
		headers map[string][]byte
		want    error
	}{
		{"short-key", nil, []byte("abc"), nil, ErrPolicy},
		{"short-header", nil, []byte(displayCanary), map[string][]byte{"X-Ordinary": []byte("a")}, ErrPolicy},
		{"mask-collision", nil, []byte("REDACTED"), nil, ErrPolicy},
		{"duplicate-header", nil, []byte(displayCanary), map[string][]byte{"X-One": []byte(headerCanary), "x-one": []byte(headerCanary)}, ErrInvalid},
		{"bad-header", nil, []byte(displayCanary), map[string][]byte{"X-\rOne": []byte(headerCanary)}, ErrInvalid},
		{"bad-key", nil, []byte("test\ncredential"), nil, ErrInvalid},
		{"oversize-key", nil, bytes.Repeat([]byte("x"), 8193), nil, ErrInvalid},
		{"secret-syntax", func(s *Source) { s.Response.Content = "password = unrecognized-third-party-value" }, []byte(displayCanary), nil, ErrPolicy},
		{"private-key", func(s *Source) { s.Response.Content = "-----BEGIN RSA PRIVATE KEY-----" }, []byte(displayCanary), nil, ErrPolicy},
		{"unknown-token", func(s *Source) { s.Response.Content = "sk-unrecognized-secret-12345678" }, []byte(displayCanary), nil, ErrPolicy},
		{"large-body", func(s *Source) { s.Response.Content = strings.Repeat("x", MaxTextBytes+1) }, []byte(displayCanary), nil, ErrLimit},
		{"escaped-body", func(s *Source) { s.Response.Content = strings.Repeat("\x01", MaxTextBytes) }, []byte(displayCanary), nil, ErrLimit},
		{"invalid-utf8", func(s *Source) { s.Response.Content = string([]byte{255}) }, []byte(displayCanary), nil, ErrLimit},
		{"large-metadata", func(s *Source) {
			s.Response.HeaderSummary = map[string]string{"X-Request-Id": strings.Repeat("x", 513)}
		}, []byte(displayCanary), nil, ErrLimit},
		{"invalid-event", func(s *Source) { s.Response.Events = []domain.StreamEventSummary{{Type: displayCanary}} }, []byte(displayCanary), nil, ErrInvalid},
		{"unknown-parse", func(s *Source) { s.Response.ParseStatus = "unexpected" }, []byte(displayCanary), nil, ErrInvalid},
	} {
		t.Run(item.name, func(t *testing.T) {
			s := displaySource(t, item.change)
			p, err := Prepare(context.Background(), s, item.key, item.headers)
			if p != nil || !errors.Is(err, item.want) || strings.Contains(err.Error(), displayCanary) {
				t.Fatal("policy did not fail closed")
			}
		})
	}
	s := displaySource(t, func(s *Source) { s.Response.Content = strings.Repeat("quad", MaxTextBytes/4-1024) })
	if p, err := Prepare(context.Background(), s, []byte("quad"), nil); p != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("replacement expansion escaped byte ceiling")
	}
	s = displaySource(t, nil)
	headers := map[string][]byte{}
	for i := range 5 {
		headers[fmt.Sprintf("X-%d", i)] = bytes.Repeat([]byte("x"), 8192)
	}
	if p, err := Prepare(context.Background(), s, []byte(displayCanary), headers); p != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("credential dictionary source bound ignored")
	}
}

func TestPrepareRequestBindingAndCancellation(t *testing.T) {
	for _, mutate := range []func(*Source){func(s *Source) { s.Snapshot.RequestHash = strings.Repeat("a", 64) }, func(s *Source) { s.Snapshot.Model = "different-model" }, func(s *Source) { s.Snapshot.PayloadBytes++ }, func(s *Source) { s.Snapshot.MaxOutputTokens++ }, func(s *Source) { s.Snapshot.MaxOutputParameter = "unknown" }, func(s *Source) { s.Request.Messages[0].Content = "different frozen request" }, func(s *Source) {
		s.Snapshot.Payload = []byte(`{"model":"different-model"}`)
		s.Snapshot.PayloadBytes = len(s.Snapshot.Payload)
		s.Snapshot.RequestHash = digest(s.Snapshot.Payload)
	}} {
		s := displaySource(t, nil)
		mutate(&s)
		if p, err := Prepare(context.Background(), s, []byte(displayCanary), nil); p != nil || err == nil {
			t.Fatal("inconsistent wire snapshot accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := Prepare(ctx, displaySource(t, nil), []byte(displayCanary), nil); p != nil || !errors.Is(err, ErrCancelled) {
		t.Fatal("cancellation ignored")
	}
	var absentContext context.Context
	if p, err := Prepare(absentContext, Source{}, nil, nil); p != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context accepted")
	}
}

func TestPreparedOpaqueLifetimeAndAuthenticatedDecode(t *testing.T) {
	s := displaySource(t, func(s *Source) { s.Response.Content = displayCanary })
	p, err := Prepare(context.Background(), s, []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	sourceHash, requestHash := p.Hashes()
	var encoded, borrowed []byte
	if err := p.WithCanonicalForSeal(context.Background(), func(v []byte) error { borrowed = v; encoded = bytes.Clone(v); return nil }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed buffer retained")
	}
	opened, err := DecodeAuthenticatedCanonical(encoded, sourceHash, requestHash)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	for _, v := range []any{s, &s, p, *p, opened, *opened} {
		if _, err := json.Marshal(v); !errors.Is(err, ErrSensitive) {
			t.Fatal("opaque value serialized")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			value := fmt.Sprintf(format, v)
			if strings.Contains(value, displayCanary) || strings.Contains(value, sourceHash) || strings.Contains(value, requestHash) {
				t.Fatal("opaque value formatted protected fields")
			}
		}
		var logs bytes.Buffer
		for _, handler := range []slog.Handler{slog.NewJSONHandler(&logs, nil), slog.NewTextHandler(&logs, nil)} {
			slog.New(handler).Info("bounded", "value", v, slog.Group("nested", "value", v))
		}
		if strings.Contains(logs.String(), displayCanary) || strings.Contains(logs.String(), sourceHash) {
			t.Fatal("structured log leaked opaque content")
		}
	}
	for _, bad := range [][]byte{append(bytes.Clone(encoded), []byte(` {}`)...), bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(encoded, []byte(`"version":1`), []byte(`"version":1,"unknown":"x"`), 1), bytes.Replace(encoded, []byte(PolicyVersion), []byte("unknown"), 1)} {
		if v, err := DecodeAuthenticatedCanonical(bad, sourceHash, requestHash); v != nil || err == nil {
			t.Fatal("noncanonical authenticated bytes accepted")
		}
	}
	for _, panicMode := range []bool{false, true} {
		var used []byte
		err := p.WithCanonicalForSeal(context.Background(), func(v []byte) error {
			used = v
			if panicMode {
				panic(displayCanary)
			}
			return errors.New(displayCanary)
		})
		if !errors.Is(err, ErrConsumer) || !bytes.Equal(used, make([]byte, len(used))) {
			t.Fatal("consumer failure leaked/retained bytes")
		}
	}
	p.Close()
	opened.Close()
	if a, b := p.Hashes(); a != "" || b != "" {
		t.Fatal("closed prepared remains usable")
	}
	if err := p.WithCanonicalForSeal(context.Background(), func([]byte) error { t.Fatal("closed callback ran"); return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("closed prepared accepted")
	}
	if reflect.TypeOf(*p).ConvertibleTo(reflect.TypeOf(*opened)) {
		t.Fatal("opened bytes can be cast to a sealable prepared value")
	}
}

func TestBoundedWriterCancellationAndLimit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	w := &boundedText{ctx: ctx, limit: 3}
	if _, err := w.Write([]byte("four")); !errors.Is(err, ErrLimit) {
		t.Fatal("writer limit ignored")
	}
	cancel()
	if _, err := w.WriteString("ok"); !errors.Is(err, ErrCancelled) {
		t.Fatal("writer cancellation ignored")
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if _, _, err := prepareContext(ctx); !errors.Is(err, ErrCancelled) {
		t.Fatal("expired input accepted")
	}
}

func FuzzPrepareKnownCredentialDoesNotLeak(f *testing.F) {
	f.Add("prefix and suffix")
	f.Add("中文😀 <script> value")
	f.Add("authorization: third-party")
	f.Add("\x00\xff")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 8192 {
			return
		}
		s := displaySource(t, func(s *Source) { s.Response.Content = value + displayCanary + value })
		p, err := Prepare(context.Background(), s, []byte(displayCanary), nil)
		if err != nil {
			if !errors.Is(err, ErrInvalid) && !errors.Is(err, ErrLimit) && !errors.Is(err, ErrPolicy) && !errors.Is(err, ErrCancelled) {
				t.Fatal("unclosed error")
			}
			return
		}
		defer p.Close()
		if err := p.WithCanonicalForSeal(context.Background(), func(data []byte) error {
			if bytes.Contains(data, []byte(displayCanary)) {
				t.Fatal("known credential retained")
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	})
}
