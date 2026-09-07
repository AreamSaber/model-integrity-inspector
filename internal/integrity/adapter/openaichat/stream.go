package openaichat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/safehttp"
)

func (a *Adapter) ParseStream(ctx context.Context, response *http.Response, sink StreamEventSink) (domain.NormalizedResponse, error) {
	if ctx == nil {
		return domain.NormalizedResponse{ParseStatus: "invalid", EndCause: "protocol"}, failure("MI_REQUEST_INVALID")
	}
	ctx, cancel := context.WithTimeout(ctx, a.config.RequestTimeout)
	defer cancel()
	return a.parseStream(ctx, response, sink, a.config.Now())
}

// splitSSELine supports LF, CRLF and CR, including split CRLF pairs and a final
// unterminated line. An unterminated EVENT is deliberately not dispatched at EOF.
func splitSSELine(data []byte, atEOF bool) (int, []byte, error) {
	for index, character := range data {
		if character == '\n' {
			return index + 1, data[:index], nil
		}
		if character == '\r' {
			if index+1 == len(data) && !atEOF {
				return 0, nil, nil
			}
			advance := index + 1
			if index+1 < len(data) && data[index+1] == '\n' {
				advance++
			}
			return advance, data[:index], nil
		}
	}
	if atEOF && len(data) > 0 {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func (a *Adapter) parseStream(ctx context.Context, response *http.Response, sink StreamEventSink, started time.Time) (result domain.NormalizedResponse, returned error) {
	result = metadata(response)
	if response == nil || response.Body == nil {
		return result, failure("MI_PROTOCOL_INVALID")
	}
	guard := a.guard(ctx, response.Body, true, started)
	defer guard.close()
	reader := newBoundedReader(guard, a.config.MaxResponseBytes, a.config.Now, started)
	defer func() {
		result.DurationMs = elapsed(a.config.Now(), started)
		result.RawResponseBytes, result.FirstByteMs = reader.count, reader.firstByteMs
		if response.StatusCode == http.StatusOK {
			result.ResponseHash = hex.EncodeToString(reader.digest.Sum(nil))
		}
		if guard.firstExpired.Load() {
			warning(&result, "FIRST_EVENT_TIMEOUT")
		}
		if guard.idleExpired.Load() {
			warning(&result, "STREAM_IDLE_TIMEOUT")
		}
		completeWarnings(&result)
	}()
	if response.StatusCode != http.StatusOK {
		response.Body = reader
		result.EndCause = "http_error"
		return result, a.httpError(response)
	}
	if !contentType(response, "text/event-stream") {
		return result, failure("MI_PROTOCOL_CONTENT_TYPE")
	}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, min(4096, a.config.MaxEventBytes+2)), a.config.MaxEventBytes+2)
	lineBytes := 0
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		advance, token, err := splitSSELine(data, atEOF)
		lineBytes = advance
		return advance, token, err
	})
	var data bytes.Buffer
	eventBytes, sequence := 0, 0
	var eventName string
	firstLine := true
	lastArrival := int64(0)
	var content strings.Builder
	finish := func(err error) (domain.NormalizedResponse, error) {
		result.Content = content.String()
		if err != nil {
			result.EndCause = transportEnd(err)
			result.ParseStatus = "invalid"
			if content.Len() > 0 && !errors.Is(err, safehttp.ErrSafetyLimit) {
				result.ParseStatus = "partial"
			}
			return result, transportFailure(err)
		}
		warning(&result, "STREAM_EOF_BEFORE_DONE")
		if eventBytes > 0 || data.Len() > 0 {
			warning(&result, "UNTERMINATED_EVENT")
		}
		result.EndCause = "eof"
		if result.ChoiceCount == 0 {
			result.ParseStatus = "invalid"
			return result, failure("MI_PROTOCOL_INVALID")
		}
		result.ParseStatus = "partial"
		return result, nil
	}
	for scanner.Scan() {
		line := scanner.Text()
		if firstLine {
			line = strings.TrimPrefix(line, "\ufeff")
			firstLine = false
		}
		eventBytes += lineBytes
		if eventBytes > a.config.MaxEventBytes {
			return finish(safehttp.ErrSafetyLimit)
		}
		if line != "" {
			if strings.HasPrefix(line, ":") {
				continue
			}
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "data":
				data.WriteString(value)
				data.WriteByte('\n')
			case "event":
				eventName = value
			}
			continue
		}
		payload := bytes.TrimSuffix(data.Bytes(), []byte{'\n'})
		if len(bytes.TrimSpace(payload)) == 0 {
			data.Reset()
			eventBytes = 0
			eventName = ""
			continue
		}
		sequence++
		arrival := elapsed(a.config.Now(), started)
		summary := domain.StreamEventSummary{Sequence: sequence, Bytes: eventBytes, ArrivalMs: arrival, IntervalMs: max(0, arrival-lastArrival)}
		lastArrival = arrival
		if err := guard.err(); err != nil {
			return finish(err)
		}
		if bytes.Equal(bytes.TrimSpace(payload), []byte("[DONE]")) {
			summary.Type = "done"
			saveEvent(&result, summary, sink)
			result.StreamTerminated = true
			result.Content = content.String()
			if result.ChoiceCount == 0 {
				return result, failure("MI_PROTOCOL_INVALID")
			}
			result.ParseStatus, result.EndCause = "valid", "done"
			return result, nil
		}
		if eventName == "error" {
			summary.Type = "error"
			saveEvent(&result, summary, sink)
			result.Content = content.String()
			return result, failure("MI_UPSTREAM_STREAM_ERROR")
		}
		decoded, err := decodeCompletion(payload)
		if err == nil {
			err = applyIdentity(&result, decoded, true)
		}
		if err != nil {
			summary.Type = "malformed"
			saveEvent(&result, summary, sink)
			result.Content = content.String()
			warning(&result, "STREAM_MALFORMED_EVENT")
			return result, err
		}
		result.StreamChunkCount++
		if err := applyUsage(&result, decoded.Usage); err != nil {
			result.Content = content.String()
			return result, err
		}
		if len(decoded.Choices) == 0 && decoded.Usage != nil {
			summary.Type = "usage"
		} else {
			result.ChoiceCount = len(decoded.Choices)
			if len(decoded.Choices) != 1 || decoded.Choices[0].Index == nil || *decoded.Choices[0].Index != 0 {
				result.Content = content.String()
				return result, failure("MI_PROTOCOL_INVALID")
			}
			selected := decoded.Choices[0]
			delta, refusal, err := textMessage(selected.Delta, true)
			if err != nil {
				result.Content = content.String()
				return result, err
			}
			if int64(content.Len()+len(delta)) > a.config.MaxResponseBytes {
				return finish(safehttp.ErrSafetyLimit)
			}
			summary.Type = "empty_delta"
			if selected.Delta.Role != "" {
				summary.Type = "role"
			}
			if delta != "" {
				guard.effective()
				if result.FirstTokenMs == nil {
					measured := arrival
					result.FirstTokenMs = &measured
				}
				if result.FinishReason != "" {
					warning(&result, "CONTENT_AFTER_FINISH")
				}
				content.WriteString(delta)
				summary.Type = "content_delta"
			}
			result.Refusal = result.Refusal || refusal
			if selected.FinishReason != nil && *selected.FinishReason != "" {
				guard.effective()
				summary.Type = "finish"
			}
			finishReason(&result, selected.FinishReason)
		}
		saveEvent(&result, summary, sink)
		data.Reset()
		eventBytes = 0
		eventName = ""
	}
	if err := guard.err(); err != nil {
		return finish(err)
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return finish(safehttp.ErrSafetyLimit)
		}
		return finish(err)
	}
	return finish(nil)
}

func saveEvent(result *domain.NormalizedResponse, event domain.StreamEventSummary, sink StreamEventSink) {
	const retained = 16
	if len(result.Events) < retained {
		result.Events = append(result.Events, event)
	} else {
		copy(result.Events[retained/2:], result.Events[retained/2+1:])
		result.Events[retained-1] = event
	}
	if sink != nil {
		sink(event)
	}
}
