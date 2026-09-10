package openaichat

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
)

type byteReader struct {
	data []byte
	step int
}

func (reader *byteReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	n := min(len(buffer), len(reader.data), reader.step)
	copy(buffer, reader.data[:n])
	reader.data = reader.data[n:]
	return n, nil
}
func (*byteReader) Close() error { return nil }

func chunk(delta, finish string) string {
	return `{"id":"chatcmpl-fixture","object":"chat.completion.chunk","model":"test-model","choices":[{"index":0,"delta":` + delta + `,"finish_reason":` + finish + `}]}`
}
func event(data string) string { return "data: " + data + "\n\n" }
func basicStream() string {
	return event(chunk(`{"role":"assistant","content":""}`, "null")) + event(chunk(`{"content":"你好世界"}`, "null")) +
		event(chunk(`{}`, `"stop"`)) + event(`{"object":"chat.completion.chunk","model":"test-model","choices":[],"usage":{"prompt_tokens":2,"completion_tokens":4,"total_tokens":6}}`) + event("[DONE]")
}

func TestSSEArbitraryByteSplittingUTF8UsageAndDone(t *testing.T) {
	t.Parallel()
	for _, step := range []int{1, 2, 3, 7, 4096} {
		for _, ending := range []string{"\n", "\r\n", "\r"} {
			body := strings.ReplaceAll(basicStream(), "\n", ending)
			a := adapterForTest(t, nil)
			response := rawResponse(200, "text/event-stream; charset=utf-8", "")
			response.Body = &byteReader{data: []byte(body), step: step}
			var summaries []domain.StreamEventSummary
			result, err := a.ParseStream(t.Context(), response, func(event domain.StreamEventSummary) { summaries = append(summaries, event) })
			if err != nil || result.Content != "你好世界" || !result.StreamTerminated || result.EndCause != "done" || result.ParseStatus != "valid" || result.StreamChunkCount != 4 || result.FirstTokenMs == nil || result.TotalTokens == nil || *result.TotalTokens != 6 {
				t.Fatalf("stream failed for byte step %d: %v", step, err)
			}
			if len(summaries) != 5 || summaries[4].Type != "done" || result.RawResponseBytes != int64(len(body)) {
				t.Fatal("event/byte accounting failed")
			}
		}
	}
}

func TestSSEMultilineEmptyCommentsAndBOM(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, nil)
	body := "\ufeff: heartbeat\n\nretry: 1000\n\ndata:\n\nid: CANARY_SECRET\nevent: message\ndata: {\ndata: \"object\":\"chat.completion.chunk\",\"model\":\"test-model\",\ndata: \"choices\":[{\"index\":0,\"delta\":{\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\n" + event("[DONE]")
	result, err := a.ParseStream(t.Context(), rawResponse(200, "text/event-stream", body), nil)
	if err != nil || result.Content != "hello" || !result.StreamTerminated || len(result.Events) != 2 {
		t.Fatalf("multiline/empty/comment handling failed: %v", err)
	}
	encoded, _ := json.Marshal(result.Events)
	if strings.Contains(string(encoded), "CANARY") || strings.Contains(string(encoded), "hello") {
		t.Fatal("event summaries retain body/id data")
	}
}

func TestSSEEOFMalformedAndClientLimitRemainDistinct(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, nil)
	content := event(chunk(`{"content":"partial"}`, "null"))
	for _, test := range []struct {
		name, body, code, status, end string
		warning                       string
	}{
		{"normal eof", content, "", "partial", "eof", "STREAM_EOF_BEFORE_DONE"},
		{"unfinished event", content + "data: " + chunk(`{"content":"discarded"}`, `"stop"`), "", "partial", "eof", "UNTERMINATED_EVENT"},
		{"malformed JSON", content + event("{CANARY_BAD_JSON"), "MI_PROTOCOL_INVALID", "invalid", "protocol", "STREAM_MALFORMED_EVENT"},
		{"invalid usage", content + event(`{"choices":[],"usage":{"completion_tokens":-1}}`), "MI_PROTOCOL_INVALID", "invalid", "protocol", ""},
		{"event error", content + "event: error\ndata: CANARY_SECRET\n\n", "MI_UPSTREAM_STREAM_ERROR", "invalid", "protocol", ""},
		{"empty stream", ": heartbeat\n\n", "MI_PROTOCOL_INVALID", "invalid", "eof", ""},
		{"only done", event("[DONE]"), "MI_PROTOCOL_INVALID", "invalid", "protocol", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := a.ParseStream(t.Context(), rawResponse(200, "text/event-stream", test.body), nil)
			if errorCode(err) != test.code || result.ParseStatus != test.status || result.EndCause != test.end {
				t.Fatalf("wrong partial/error distinction: status=%s end=%s error=%v", result.ParseStatus, result.EndCause, err)
			}
			if strings.HasPrefix(test.body, content) && result.Content != "partial" {
				t.Fatal("valid partial content was lost or malformed fragment was appended")
			}
			if test.warning != "" && !hasWarning(result, test.warning) {
				t.Fatal("termination warning missing")
			}
			if err != nil && strings.Contains(err.Error(), "CANARY") {
				t.Fatal("SSE error leaked payload")
			}
		})
	}
	for _, mode := range []string{"long-line", "multiline", "aggregate"} {
		t.Run(mode, func(t *testing.T) {
			a := adapterForTest(t, func(config *Config) {
				config.MaxEventBytes = 256
				if mode == "aggregate" {
					config.MaxResponseBytes = 300
				}
			})
			body := content + event(chunk(`{"content":"`+strings.Repeat("x", 300)+`"}`, "null"))
			if mode == "multiline" {
				body = content + strings.Repeat(": heartbeat\r\n", 24) + "\r\n"
			}
			if mode == "aggregate" {
				body = strings.Repeat(content, 4)
			}
			result, err := a.ParseStream(t.Context(), rawResponse(200, "text/event-stream", body), nil)
			if errorCode(err) != "CLIENT_SAFETY_LIMIT" || result.ParseStatus != "invalid" || result.EndCause != "client_safety_limit" {
				t.Fatalf("SSE safety limit was misclassified: %v", err)
			}
		})
	}
}

func TestSSEBoundedSummaryAndBehavioralWarnings(t *testing.T) {
	t.Parallel()
	a := adapterForTest(t, nil)
	body := event(chunk(`{"content":"first"}`, `"stop"`))
	for index := 0; index < 40; index++ {
		body += event(chunk(`{"content":"x"}`, "null"))
	}
	body += event(chunk(`{}`, `"length"`)) + event("[DONE]")
	result, err := a.ParseStream(t.Context(), rawResponse(200, "text/event-stream", body), nil)
	if err != nil || len(result.Events) != 16 || result.Events[0].Sequence != 1 || result.Events[7].Sequence != 8 || result.Events[15].Sequence != 43 || !hasWarning(result, "CONTENT_AFTER_FINISH") || !hasWarning(result, "FINISH_REASON_CONFLICT") || result.FinishReason != "stop" {
		t.Fatalf("bounded summaries or conflict evidence failed: %v", err)
	}
}

type hangingBody struct {
	prefix *strings.Reader
	closed chan struct{}
	once   sync.Once
}

func (body *hangingBody) Read(buffer []byte) (int, error) {
	if body.prefix.Len() > 0 {
		return body.prefix.Read(buffer)
	}
	<-body.closed
	return 0, errors.New("CANARY_NETWORK_READ")
}
func (body *hangingBody) Close() error { body.once.Do(func() { close(body.closed) }); return nil }

func TestSSEFirstEffectiveEventIdleAndCancellation(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"first", "idle", "cancel", "total"} {
		t.Run(mode, func(t *testing.T) {
			a := adapterForTest(t, func(config *Config) {
				config.FirstEventTimeout = time.Second
				config.StreamIdleTimeout = time.Second
				config.RequestTimeout = time.Second
				if mode == "first" {
					config.FirstEventTimeout = 30 * time.Millisecond
				}
				if mode == "idle" {
					config.StreamIdleTimeout = 30 * time.Millisecond
				}
				if mode == "total" {
					config.RequestTimeout = 30 * time.Millisecond
				}
			})
			prefix := event(chunk(`{"content":"partial"}`, "null"))
			if mode == "first" {
				prefix = event(chunk(`{"role":"assistant"}`, "null"))
			}
			body := &hangingBody{prefix: strings.NewReader(prefix), closed: make(chan struct{})}
			response := rawResponse(200, "text/event-stream", "")
			response.Body = body
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancel" {
				timer := time.AfterFunc(30*time.Millisecond, cancel)
				defer timer.Stop()
			}
			started := time.Now()
			result, err := a.ParseStream(ctx, response, nil)
			want := "MI_HTTP_TIMEOUT"
			if mode == "cancel" {
				want = "MI_HTTP_CANCELED"
			}
			if errorCode(err) != want || time.Since(started) > time.Second {
				t.Fatalf("stream deadline failed: %v", err)
			}
			if mode == "first" && !hasWarning(result, "FIRST_EVENT_TIMEOUT") {
				t.Fatal("first event timeout missing")
			}
			if mode == "idle" && !hasWarning(result, "STREAM_IDLE_TIMEOUT") {
				t.Fatal("idle timeout missing")
			}
			if mode != "first" && result.Content != "partial" {
				t.Fatal("valid content lost on transport failure")
			}
		})
	}
}

func FuzzSSEByteBoundaries(f *testing.F) {
	f.Add(basicStream(), uint8(1))
	f.Add("data: {invalid\r\n\r\n", uint8(3))
	f.Add(event("[DONE]"), uint8(2))
	f.Fuzz(func(t *testing.T, body string, step uint8) {
		if len(body) > 65536 {
			t.Skip()
		}
		a := adapterForTest(t, nil)
		response := rawResponse(200, "text/event-stream", "")
		response.Body = &byteReader{data: []byte(body), step: int(step) + 1}
		result, err := a.ParseStream(t.Context(), response, nil)
		if len(result.Events) > 16 || len(result.ParseWarnings) > 32 || len(result.Content) > len(body) {
			t.Fatal("parser bounds violated")
		}
		if err != nil && errorCode(err) == "UNCLASSIFIED" {
			t.Fatal("unsanitized error escaped")
		}
	})
}
