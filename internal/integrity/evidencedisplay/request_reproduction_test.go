package evidencedisplay

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/adapter/openaichat"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

func reproductionSource(t testing.TB, parameter string, change func(*domain.NormalizedRequest)) RequestReproductionSource {
	t.Helper()
	r := domain.NormalizedRequest{Model: "test-model", Messages: []domain.NormalizedMessage{{Role: "user", Content: "Synthetic probe."}}, MaxOutputTokens: 64}
	if change != nil {
		change(&r)
	}
	a, err := openaichat.New(openaichat.Config{Endpoint: "https://analysis.invalid/v1", MaxOutputParameter: parameter, Doer: noNetwork{}})
	if err != nil {
		t.Fatal(err)
	}
	wire, snapshot, err := a.BuildRequest(context.Background(), r)
	if err != nil {
		t.Fatal("invalid synthetic request")
	}
	_ = wire.Body.Close()
	return RequestReproductionSource{Request: r, Snapshot: snapshot, ManifestHash: strings.Repeat("a", 64)}
}

func reproductionDocument(t testing.TB, prepared *PreparedRequestReproduction) requestReproductionDocument {
	t.Helper()
	var doc requestReproductionDocument
	if err := prepared.WithCanonicalForSeal(context.Background(), func(value []byte) error { return json.Unmarshal(value, &doc) }); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestRequestReproductionUsesActualWireAndFiniteRedactionWithoutResponse(t *testing.T) {
	for _, value := range []string{displayCanary, headerCanary, "utf8-密钥-😀-value"} {
		for i, form := range variants([]byte(value)) {
			t.Run(fmt.Sprintf("variant-%d-%d", len(value), i), func(t *testing.T) {
				s := reproductionSource(t, "max_completion_tokens", func(r *domain.NormalizedRequest) { r.Messages[0].Content = "before " + form + " after" })
				prepared, err := PrepareRequestReproduction(context.Background(), s, []byte(displayCanary), map[string][]byte{"X-Ordinary-Synthetic": []byte(value)})
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				doc := reproductionDocument(t, prepared)
				if !doc.RequestChanged || doc.RequestHash != s.Snapshot.RequestHash || strings.Contains(doc.RequestJSON, form) || !strings.Contains(doc.RequestJSON, marker) {
					t.Fatal("request redaction did not use actual values")
				}
				if err := prepared.WithCanonicalForSeal(context.Background(), func(data []byte) error {
					for _, absent := range []string{"response", "endpoint", "X-Ordinary-Synthetic", "headers", "analysis.invalid", s.ManifestHash} {
						if bytes.Contains(data, []byte(absent)) {
							t.Fatal("transport/response metadata entered request payload")
						}
					}
					opened, err := DecodeAuthenticatedRequestReproduction(data, s.ManifestHash, s.Snapshot.RequestHash)
					if err != nil {
						return err
					}
					opened.Close()
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestRequestReproductionExactSeedsSharedDisplayAndUnmodifiedInputs(t *testing.T) {
	for _, seed := range []int64{-9223372036854775808, -9007199254740993, 9007199254740993, 9223372036854775807} {
		for _, parameter := range []string{"max_tokens", "max_completion_tokens"} {
			s := reproductionSource(t, parameter, func(r *domain.NormalizedRequest) {
				r.Seed = &seed
				r.Stream = true
				r.Stop = []string{"END"}
				r.ResponseFormat = &domain.ResponseFormat{Type: "json_object"}
				r.ExtraAllowedParams = map[string]any{"frequency_penalty": json.Number("1.2"), "presence_penalty": -1.0}
			})
			before, _ := json.Marshal(s.Request)
			original := bytes.Clone(s.Snapshot.Payload)
			p, err := PrepareRequestReproduction(context.Background(), s, []byte(displayCanary), nil)
			if err != nil {
				t.Fatal(err)
			}
			doc := reproductionDocument(t, p)
			p.Close()
			after, _ := json.Marshal(s.Request)
			if !bytes.Equal(before, after) || !bytes.Equal(original, s.Snapshot.Payload) || doc.RequestChanged || doc.TemplateHash != s.Snapshot.RequestHash || doc.RequestJSON != string(original) || !strings.Contains(doc.RequestJSON, strconv.FormatInt(seed, 10)) || !validReproductionRequest(doc.RequestJSON) {
				t.Fatal("request wire precision or immutable source changed")
			}
			// A real display source exists only for this compatibility assertion;
			// the request-only API itself cannot accept or invent a response.
			display := displaySource(t, nil)
			display.Request, display.Snapshot = s.Request, s.Snapshot
			legacy, err := Prepare(context.Background(), display, []byte(displayCanary), nil)
			if err != nil {
				t.Fatal(err)
			}
			if preparedDocument(t, legacy).RequestJSON != doc.RequestJSON {
				t.Fatal("request helper diverged between purposes")
			}
			legacy.Close()
		}
	}
}

func TestRequestReproductionAllHeadersAndChangedModelStop(t *testing.T) {
	headers := map[string][]byte{}
	values := []string{}
	for i := range 32 {
		value := fmt.Sprintf("synthetic-private-header-%02d", i)
		headers[fmt.Sprintf("X-Ordinary-%02d", i)] = []byte(value)
		values = append(values, value)
	}
	s := reproductionSource(t, "", func(r *domain.NormalizedRequest) {
		r.Model = displayCanary
		r.Stop = []string{displayCanary}
		r.Messages[0].Content = strings.Join(values, " ")
	})
	p, err := PrepareRequestReproduction(context.Background(), s, []byte(displayCanary), headers)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	doc := reproductionDocument(t, p)
	if !validReproductionRequest(doc.RequestJSON) || strings.Contains(doc.RequestJSON, displayCanary) {
		t.Fatal("redacted model/stop rejected or leaked")
	}
	for _, value := range values {
		if strings.Contains(doc.RequestJSON, value) {
			t.Fatal("ordinary header skipped")
		}
	}
}

func TestRequestReproductionProtectedLifecycleAndCallbacks(t *testing.T) {
	s := reproductionSource(t, "", func(r *domain.NormalizedRequest) { r.Messages[0].Content = displayCanary })
	p, err := PrepareRequestReproduction(context.Background(), s, []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var borrowed []byte
	var opened *OpenedRequestReproduction
	if err := p.WithCanonicalForSeal(context.Background(), func(data []byte) error {
		borrowed = data
		opened, err = DecodeAuthenticatedRequestReproduction(data, s.ManifestHash, s.Snapshot.RequestHash)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed buffer not cleared")
	}
	for _, value := range []any{s, &s, p, *p, opened, *opened} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrSensitive) {
			t.Fatal("protected wrapper serialized")
		}
		var log bytes.Buffer
		for _, handler := range []slog.Handler{slog.NewJSONHandler(&log, nil), slog.NewTextHandler(&log, nil)} {
			slog.New(handler).Info("safe", "value", value)
		}
		for _, text := range []string{fmt.Sprintf("%v %+v %#v %s", value, value, value, value), log.String()} {
			if strings.Contains(text, displayCanary) || strings.Contains(text, s.ManifestHash) || strings.Contains(text, s.Snapshot.RequestHash) {
				t.Fatal("protected wrapper exposed data")
			}
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[PreparedRequestReproduction](), reflect.TypeFor[OpenedRequestReproduction](), reflect.TypeFor[Prepared](), reflect.TypeFor[Opened]()} {
		for _, other := range []reflect.Type{reflect.TypeFor[PreparedRequestReproduction](), reflect.TypeFor[OpenedRequestReproduction]()} {
			if typ != other && typ.ConvertibleTo(other) {
				t.Fatal("purpose/state wrapper convertible")
			}
		}
	}
	if err := opened.WithCanonicalForReproduction(context.Background(), func([]byte) error { panic(displayCanary) }); !errors.Is(err, ErrConsumer) {
		t.Fatal("panic escaped closed error")
	}
	if err := opened.WithCanonicalForReproduction(context.Background(), func([]byte) error { return errors.New(displayCanary) }); !errors.Is(err, ErrConsumer) {
		t.Fatal("consumer error exposed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := opened.WithCanonicalForReproduction(ctx, func(data []byte) error { borrowed = data; cancel(); return nil }); !errors.Is(err, ErrCancelled) || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("late cancellation or clearing ignored")
	}
	opened.Close()
	p.Close()
	if err := opened.WithCanonicalForReproduction(context.Background(), func([]byte) error { t.Fatal("closed callback invoked"); return nil }); !errors.Is(err, ErrInvalid) {
		t.Fatal("closed view accepted")
	}
	if m, r := p.BindingHashes(); m != "" || r != "" {
		t.Fatal("closed prepared binding retained")
	}
}

func TestRequestReproductionSourceAndPolicyFailuresAreClosed(t *testing.T) {
	for _, item := range []struct {
		name   string
		change func(*RequestReproductionSource)
		key    []byte
		want   error
	}{
		{"manifest", func(s *RequestReproductionSource) { s.ManifestHash = "unknown" }, []byte(displayCanary), ErrInvalid},
		{"hash", func(s *RequestReproductionSource) { s.Snapshot.RequestHash = strings.Repeat("b", 64) }, []byte(displayCanary), ErrInvalid},
		{"wire", func(s *RequestReproductionSource) { s.Request.Messages[0].Content = "different" }, []byte(displayCanary), ErrInvalid},
		{"mapping", func(s *RequestReproductionSource) { s.Snapshot.MaxOutputParameter = "max_completion_tokens" }, []byte(displayCanary), ErrInvalid},
		{"size", func(s *RequestReproductionSource) {
			s.Request.Messages[0].Content = strings.Repeat("x", MaxTextBytes+1)
		}, []byte(displayCanary), ErrLimit},
		{"short", nil, []byte("abc"), ErrPolicy},
		{"schema-collision", nil, []byte("request_hash"), ErrPolicy},
		{"unknown-secret", func(s *RequestReproductionSource) {
			*s = reproductionSource(t, "", func(r *domain.NormalizedRequest) { r.Messages[0].Content = "password = uncaptured-private-value" })
		}, []byte(displayCanary), ErrPolicy},
	} {
		t.Run(item.name, func(t *testing.T) {
			s := reproductionSource(t, "", nil)
			if item.change != nil {
				item.change(&s)
			}
			p, err := PrepareRequestReproduction(context.Background(), s, item.key, nil)
			if p != nil || !errors.Is(err, item.want) {
				t.Fatal("invalid source or policy accepted", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p, err := PrepareRequestReproduction(ctx, reproductionSource(t, "", nil), []byte(displayCanary), nil); p != nil || !errors.Is(err, ErrCancelled) {
		t.Fatal("canceled preparation accepted")
	}
}

func TestRequestReproductionStrictAuthenticatedCodec(t *testing.T) {
	s := reproductionSource(t, "", nil)
	p, err := PrepareRequestReproduction(context.Background(), s, []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	base := reproductionDocument(t, p)
	for _, mutate := range []func(*requestReproductionDocument){
		func(d *requestReproductionDocument) { d.Version++ }, func(d *requestReproductionDocument) { d.Policy = PolicyVersion }, func(d *requestReproductionDocument) { d.RequestHash = strings.Repeat("b", 64) }, func(d *requestReproductionDocument) { d.TemplateHash = strings.Repeat("c", 64) }, func(d *requestReproductionDocument) { d.RequestChanged = !d.RequestChanged },
	} {
		d := base
		mutate(&d)
		data, _ := json.Marshal(d)
		if opened, err := DecodeAuthenticatedRequestReproduction(data, s.ManifestHash, s.Snapshot.RequestHash); opened != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("inconsistent document accepted")
		}
	}
	for _, raw := range []string{
		`{}`, `null`, `[]`, strings.Replace(base.RequestJSON, `"model":`, `"endpoint":"https://synthetic.invalid","model":`, 1),
		strings.Replace(base.RequestJSON, `"role":"user"`, `"role":"user","headers":{"X-Test":"canary"}`, 1),
		strings.Replace(base.RequestJSON, `"role":"user"`, `"role":"user","role":"user"`, 1),
		strings.Replace(base.RequestJSON, `"model":"test-model"`, `"model":"test-model","model":"test-model"`, 1),
		strings.Replace(base.RequestJSON, `"stream":false`, `"stream":false,"seed":9007199254740993.0`, 1),
		strings.Replace(base.RequestJSON, `"stream":false`, `"stream":null`, 1),
		strings.Replace(base.RequestJSON, `"stream":false`, `"stream":true`, 1), base.RequestJSON + `{}`,
	} {
		d := base
		d.RequestJSON = raw
		d.TemplateHash = digest([]byte(raw))
		d.RequestChanged = d.TemplateHash != d.RequestHash
		data, _ := json.Marshal(d)
		if opened, err := DecodeAuthenticatedRequestReproduction(data, s.ManifestHash, s.Snapshot.RequestHash); opened != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid nested request accepted")
		}
	}
	data, _ := json.Marshal(base)
	for _, invalid := range [][]byte{append(bytes.Clone(data), data...), bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1), bytes.Replace(data, []byte(`"version":1`), []byte(`"version":1,"response":{}`), 1)} {
		if opened, err := DecodeAuthenticatedRequestReproduction(invalid, s.ManifestHash, s.Snapshot.RequestHash); opened != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("noncanonical outer document accepted")
		}
	}
}

func TestRequestReproductionLargeBoundedRequestAndExpansion(t *testing.T) {
	s := reproductionSource(t, "", func(r *domain.NormalizedRequest) { r.Messages[0].Content = strings.Repeat("x", 900<<10) })
	p, err := PrepareRequestReproduction(context.Background(), s, []byte(displayCanary), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.WithCanonicalForSeal(context.Background(), func(data []byte) error {
		opened, err := DecodeAuthenticatedRequestReproduction(data, s.ManifestHash, s.Snapshot.RequestHash)
		if opened != nil {
			opened.Close()
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	s = reproductionSource(t, "", func(r *domain.NormalizedRequest) { r.Messages[0].Content = strings.Repeat("zxQ7", 110000) })
	if value, err := PrepareRequestReproduction(context.Background(), s, []byte("zxQ7"), nil); value != nil || !errors.Is(err, ErrLimit) {
		t.Fatal("redaction expansion exceeded bounded request")
	}
}
