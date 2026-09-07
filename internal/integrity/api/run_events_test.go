package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
)

// Every stream below is a real net/http connection to a real database-backed
// control handler. The fixture's queue is controlled; no upstream calls run.
func runEventFixture(t *testing.T) (controlFixture, *http.Cookie, string, string, runHTTPView) {
	t.Helper()
	f := newRunHTTPFixture(t, true)
	f.initialize(t)
	cookie, csrf, org := f.login(t)
	target := runAuthorizationTarget(t, f, cookie, csrf, org)
	quote := runAuthorizationEstimate(t, f, cookie, csrf, org, runAuthorizationQuick(target))
	return f, cookie, csrf, org, runAuthorizationConfirm(t, f, cookie, csrf, org, quote)
}

func runEventServer(t *testing.T, f controlFixture, configure func(*runEvents)) (*httptest.Server, *runEvents) {
	t.Helper()
	if configure == nil {
		server := httptest.NewServer(f.handler)
		t.Cleanup(server.Close)
		return server, nil
	}
	c := &control{cfg: f.cfg, origin: localOrigin}
	events := newRunEvents(c)
	configure(events)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/runs/{id}/events", events.serve)
	server := httptest.NewServer(c.middleware(mux))
	t.Cleanup(server.Close)
	return server, events
}

func runEventOpen(t *testing.T, server *httptest.Server, cookie *http.Cookie, org, id, last string) (*http.Response, *bufio.Scanner, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/v1/runs/"+id+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("X-Organization-ID", org)
	req.Header.Set("Accept", "text/event-stream")
	if last != "" {
		req.Header.Set("Last-Event-ID", last)
	}
	response, err := server.Client().Do(req)
	if err != nil {
		t.Fatal("open stream", err)
	}
	t.Cleanup(func() { _ = response.Body.Close() })
	scanner := bufio.NewScanner(response.Body)
	scanner.Buffer(make([]byte, 4096), runEventMaxBytes+1024)
	return response, scanner, cancel
}

func runEventFrame(t *testing.T, response *http.Response, scanner *bufio.Scanner) (string, string, string) {
	t.Helper()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream; charset=utf-8" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid stream response status %d", response.StatusCode)
	}
	var event, id, data string
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			return event, id, data
		}
		switch {
		case strings.HasPrefix(line, "event: "):
			event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "id: "):
			id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "data: "):
			data = strings.TrimPrefix(line, "data: ")
		case strings.HasPrefix(line, ":"):
			event = "heartbeat"
		default:
			t.Fatal("unexpected frame field")
		}
	}
	t.Fatal("stream closed before frame", scanner.Err())
	return "", "", ""
}

func runEventProgress(t *testing.T, response *http.Response, scanner *bufio.Scanner, id string, version int64, status string) string {
	t.Helper()
	event, cursor, data := runEventFrame(t, response, scanner)
	if event != "progress" || cursor != id+":"+strconv.FormatInt(version, 10) {
		t.Fatal("wrong event identity")
	}
	runHTTPAssertNoS2(t, data)
	var record runHTTPView
	if json.Unmarshal([]byte(data), &record) != nil || record.ID != id || record.Version != version || record.Status != status {
		t.Fatal("event did not reflect persisted state")
	}
	return data
}

func TestRunEventsActualCancellationAndTerminalReconnect(t *testing.T) {
	f, cookie, csrf, org, record := runEventFixture(t)
	server, _ := runEventServer(t, f, nil)
	response, scanner, cancel := runEventOpen(t, server, cookie, org, record.ID, "")
	first := runEventProgress(t, response, scanner, record.ID, 1, "QUEUED")
	w := f.request(t, "GET", "/api/v1/runs/"+record.ID, "", runAuthorizationHeaders(org, csrf), cookie)
	expectControl(t, w, 200, "")
	var get map[string]any
	managementHTTPData(t, w, &get)
	var progress map[string]any
	if json.Unmarshal([]byte(first), &progress) != nil || runAuthorizationJSON(t, get) != runAuthorizationJSON(t, progress) {
		t.Fatal("SSE and JSON public projections diverged")
	}
	w = f.request(t, "POST", "/api/v1/runs/"+record.ID+"/cancel", `{"version":1}`, runAuthorizationHeaders(org, csrf), cookie)
	expectControl(t, w, 200, "")
	runEventProgress(t, response, scanner, record.ID, 2, "CANCELLING")
	queue, err := f.cfg.Store.OpenJobQueue(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = queue.Close(t.Context()) })
	lease, err := queue.Claim(t.Context())
	id, _ := managementID(record.ID)
	if err != nil || lease == nil || lease.Job.ObjectID != id {
		t.Fatal("claim controlled plan")
	}
	if err := queue.CompleteWith(t.Context(), *lease, func(tx *repository.TenantTransaction) error { return tx.StartRun(id) }); err != nil {
		t.Fatal(err)
	}
	// Completing the already cancelled plan closes unstarted samples without
	// creating sample execution jobs or making network requests.
	terminal := runEventProgress(t, response, scanner, record.ID, 3, "CANCELLED")
	if scanner.Scan() || scanner.Err() != nil {
		t.Fatal("terminal stream did not close cleanly")
	}
	cancel()
	for _, cursor := range []string{record.ID + ":1", record.ID + ":3", record.ID + ":999999"} {
		resumed, reader, stop := runEventOpen(t, server, cookie, org, record.ID, cursor)
		if runEventProgress(t, resumed, reader, record.ID, 3, "CANCELLED") != terminal {
			t.Fatal("reconnection lost current terminal snapshot")
		}
		if reader.Scan() || reader.Err() != nil {
			t.Fatal("reconnected terminal did not close")
		}
		stop()
	}
	if err := f.cfg.Store.VerifyAllAudit(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRunEventsLiveAuthorizationRevocation(t *testing.T) {
	for _, kind := range []string{"membership", "logout", "disabled", "password-reset", "database-unavailable"} {
		t.Run(kind, func(t *testing.T) {
			f, admin, csrf, org, record := runEventFixture(t)
			viewer := runAuthorizationMember(t, f, admin, csrf, org, "events-"+kind, "viewer", nil)
			// The fixture's first password change increments the user version;
			// read the current CAS token through its authorized public endpoint.
			currentUser := f.request(t, "GET", "/api/v1/auth/me", "", nil, viewer.cookie)
			expectControl(t, currentUser, 200, "")
			var session struct {
				User managementHTTPObject `json:"user"`
			}
			managementHTTPData(t, currentUser, &session)
			viewer.user = session.User
			server, _ := runEventServer(t, f, nil)
			response, scanner, _ := runEventOpen(t, server, viewer.cookie, org, record.ID, "")
			runEventProgress(t, response, scanner, record.ID, 1, "QUEUED")
			started := time.Now()
			code := "MI_SESSION_REQUIRED"
			switch kind {
			case "membership":
				code = "MI_PERMISSION_DENIED"
				w := f.request(t, "PATCH", "/api/v1/organizations/"+org+"/members/"+viewer.member.ID, runAuthorizationJSON(t, map[string]any{"version": viewer.member.Version, "status": "disabled"}), runAuthorizationHeaders(org, csrf), admin)
				expectControl(t, w, 200, "")
			case "logout":
				expectControl(t, f.request(t, "POST", "/api/v1/auth/logout", "", runAuthorizationHeaders(org, viewer.csrf), viewer.cookie), 200, "")
			case "disabled":
				expectControl(t, f.request(t, "PATCH", "/api/v1/users/"+viewer.user.ID, runAuthorizationJSON(t, map[string]any{"version": viewer.user.Version, "status": "disabled"}), runAuthorizationHeaders(org, csrf), admin), 200, "")
			case "password-reset":
				expectControl(t, f.request(t, "POST", "/api/v1/users/"+viewer.user.ID+"/reset-password", runAuthorizationJSON(t, map[string]any{"version": viewer.user.Version, "password": controlPassword}), runAuthorizationHeaders(org, csrf), admin), 200, "")
			case "database-unavailable":
				code = "MI_SERVICE_UNAVAILABLE"
				if err := f.cfg.Store.Close(); err != nil {
					t.Fatal(err)
				}
			}
			event, id, data := runEventFrame(t, response, scanner)
			if event != "error" || id != "" || time.Since(started) > 5*time.Second {
				t.Fatal("live authorization was not revoked within five seconds")
			}
			var failure map[string]string
			if json.Unmarshal([]byte(data), &failure) != nil || len(failure) != 2 || failure["code"] != code || failure["request_id"] == "" {
				t.Fatal("invalid closed stream error")
			}
			if scanner.Scan() || scanner.Err() != nil {
				t.Fatal("revoked stream remained open")
			}
		})
	}
}

func TestRunEventsStrictHandshakeAndScope(t *testing.T) {
	f, cookie, csrf, org, record := runEventFixture(t)
	headers := runAuthorizationHeaders(org, csrf)
	base := "/api/v1/runs/" + record.ID + "/events"
	for _, cursor := range []string{"", "0:1", "1:1", record.ID + ":0", record.ID + ":-1", record.ID + ":01", record.ID + ":+1", record.ID + ":1:2", record.ID + ":9223372036854775808", strings.Repeat("1", 129)} {
		t.Run("cursor="+cursor, func(t *testing.T) {
			copy := runAuthorizationHeaders(org, csrf)
			copy["Last-Event-ID"] = cursor
			expectControl(t, f.request(t, "GET", base, "", copy, cookie), 400, "MI_INVALID_REQUEST")
		})
	}
	expectControl(t, f.request(t, "GET", base+"?token=not-allowed", "", headers, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", base, "", nil, cookie), 400, "MI_INVALID_REQUEST")
	expectControl(t, f.request(t, "GET", base, "", headers, nil), 401, "MI_SESSION_REQUIRED")
	expectControl(t, f.request(t, "GET", "/api/v1/runs/1/events", "", headers, cookie), 404, "MI_NOT_FOUND")
	other := f.request(t, "POST", "/api/v1/organizations", `{"name":"SSE other organization","timezone":"UTC"}`, headers, cookie)
	expectControl(t, other, 201, "")
	var organization managementHTTPObject
	managementHTTPData(t, other, &organization)
	expectControl(t, f.request(t, "GET", base, "", runAuthorizationHeaders(organization.ID, csrf), cookie), 404, "MI_NOT_FOUND")
	// A plain recorder cannot implement a bounded network write. The handler
	// fails before promising a streaming response in this unsupported host.
	expectControl(t, f.request(t, "GET", base, "", headers, cookie), 503, "MI_SERVICE_UNAVAILABLE")
	request := httptest.NewRequestWithContext(t.Context(), "GET", base, nil)
	request.Header.Add("Last-Event-ID", record.ID+":1")
	request.Header.Add("Last-Event-ID", record.ID+":2")
	id, _ := managementID(record.ID)
	if runEventCursor(request, id) {
		t.Fatal("duplicate cursors accepted")
	}
	// Service's new narrow method must preserve the private bound context
	// boundary; an arbitrary org/header/actor cannot construct authorization.
	orgID, _ := managementID(org)
	if _, err := f.cfg.Runs.Version(t.Context(), orgID, id); !errors.Is(err, repository.ErrManagementSession) {
		t.Fatal("unbound service version read")
	}
	principal, err := f.cfg.Identity.Principal(t.Context(), cookie.Value, orgID)
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := f.cfg.Store.BindControlAuthority(audit.WithActor(t.Context(), audit.Actor{ActorID: principal.UserID, ReasonCode: "integration.test"}), digest(cookie.Value), orgID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cfg.Runs.Version(ctx, orgID+1, id); !errors.Is(err, repository.ErrManagementPermission) {
		t.Fatal("bound version context changed tenant")
	}
}

func runEventWaitReleased(t *testing.T, events *runEvents) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		events.mu.Lock()
		closed := events.connections == 0 && len(events.users) == 0
		events.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("disconnected stream retained handler or connection slot")
}

func TestRunEventsHeartbeatLifetimeAndConnectionLimits(t *testing.T) {
	f, cookie, csrf, org, record := runEventFixture(t)
	viewer := runAuthorizationMember(t, f, cookie, csrf, org, "events-limit-viewer", "viewer", nil)
	for _, limit := range []string{"global", "user"} {
		t.Run(limit, func(t *testing.T) {
			server, events := runEventServer(t, f, func(events *runEvents) {
				events.poll = 20 * time.Millisecond
				if limit == "global" {
					events.globalLimit = 1
				} else {
					events.userLimit = 1
				}
			})
			response, reader, stop := runEventOpen(t, server, cookie, org, record.ID, "")
			runEventProgress(t, response, reader, record.ID, 1, "QUEUED")
			secondCookie := cookie
			if limit == "global" {
				secondCookie = viewer.cookie
			}
			limited, _, end := runEventOpen(t, server, secondCookie, org, record.ID, "")
			if limited.StatusCode != 429 || limited.Header.Get("Retry-After") != "5" {
				t.Fatal("stream connection cap absent")
			}
			body, err := io.ReadAll(io.LimitReader(limited.Body, 2048))
			if err != nil || !strings.Contains(string(body), "MI_RATE_LIMITED") {
				t.Fatal("wrong limit error")
			}
			end()
			stop()
			runEventWaitReleased(t, events)
			resumed, next, cancel := runEventOpen(t, server, cookie, org, record.ID, record.ID+":1")
			runEventProgress(t, resumed, next, record.ID, 1, "QUEUED")
			cancel()
			runEventWaitReleased(t, events)
		})
	}
	t.Run("heartbeat-and-lifetime", func(t *testing.T) {
		server, events := runEventServer(t, f, func(events *runEvents) {
			events.poll = 20 * time.Millisecond
			events.heartbeat = 40 * time.Millisecond
			events.lifetime = 200 * time.Millisecond
		})
		response, reader, _ := runEventOpen(t, server, cookie, org, record.ID, "")
		runEventProgress(t, response, reader, record.ID, 1, "QUEUED")
		event, id, data := runEventFrame(t, response, reader)
		if event != "heartbeat" || id != "" || data != "" {
			t.Fatal("heartbeat disclosed data or changed cursor")
		}
		for reader.Scan() {
			if strings.HasPrefix(reader.Text(), "event: progress") {
				t.Fatal("unchanged version resent as new progress")
			}
		}
		if reader.Err() != nil {
			t.Fatal("lifetime did not close gracefully")
		}
		runEventWaitReleased(t, events)
	})
}

type runEventWriteRecorder struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	flushErr  error
}

func (w *runEventWriteRecorder) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}

func (w *runEventWriteRecorder) FlushError() error {
	w.Flush()
	return w.flushErr
}

func TestRunEventsBoundedWriteAndProjection(t *testing.T) {
	events := newRunEvents(nil)
	if events.poll > 2*time.Second || events.operation > time.Second || events.lifetime > 5*time.Minute || events.globalLimit != 64 || events.userLimit != 4 {
		t.Fatal("production bounds changed")
	}
	w := &runEventWriteRecorder{ResponseRecorder: httptest.NewRecorder()}
	start := time.Now()
	if err := events.write(w, http.NewResponseController(w), []byte(": heartbeat\n\n")); err != nil || len(w.deadlines) != 2 || w.deadlines[0].Before(start) || w.deadlines[0].After(start.Add(2*time.Second)) || !w.deadlines[1].IsZero() {
		t.Fatal("write deadline was not bounded and disarmed after flush")
	}
	w = &runEventWriteRecorder{ResponseRecorder: httptest.NewRecorder(), flushErr: io.ErrClosedPipe}
	if err := events.write(w, http.NewResponseController(w), []byte(": heartbeat\n\n")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("flush failure did not stop stream")
	}
	malicious := "<script>private-upstream-body</script>\nevent: progress"
	record := repository.RunRecord{ID: 1, ConfigSnapshot: malicious, RequestKey: malicious, ErrorSummary: &malicious}
	data, err := json.Marshal(runProgressDTO(record, runservice.Quote{}, 0, 0))
	if err != nil || strings.Contains(string(data), "private-upstream-body") || strings.Contains(string(data), "config_snapshot") || strings.Contains(string(data), "request_key") || !strings.Contains(string(data), "MI_SERVICE_UNAVAILABLE") {
		t.Fatal("public projection expanded into private data")
	}
}
