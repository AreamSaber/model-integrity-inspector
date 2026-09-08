package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	runservice "model-integrity-inspector.local/mii/internal/integrity/run"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

type pipelineDisplayWriterFunc func([]byte) (int, error)

func (fn pipelineDisplayWriterFunc) Write(data []byte) (int, error) { return fn(data) }

type pipelineDisplayGrants struct{ receipts, audits int }

// This is called by the actual TLS pipeline after publication and after the
// HTTP audit fault has been removed, before any retention-policy suppression.
// It uses the production store, authenticated cookies, key-file capability and
// actual Worker-sealed display; no handwritten envelope replaces AEAD opening.
func exercisePipelineDisplayService(t *testing.T, cfg Config, store *repository.Store, db *sql.DB, p *pipelineHTTP, selection repository.DisplaySelection) {
	t.Helper()
	orgID, err := strconv.ParseInt(p.orgID, 10, 64)
	if err != nil || orgID <= 0 {
		t.Fatal("invalid actual display organization")
	}
	identities, err := identity.NewService(t.Context(), store)
	if err != nil {
		t.Fatal("construct actual principal verifier")
	}
	key, err := secret.LoadKeyFile(cfg.MasterKeyFile, cfg.MasterKeyVersion)
	if err != nil {
		t.Fatal("load restricted production display key")
	}
	_, opener, err := key.NewDisplayCapabilities(time.Now)
	if err != nil {
		t.Fatal("derive narrow actual display opener")
	}
	service, err := runservice.NewEvidenceService(store, opener)
	if err != nil {
		t.Fatal("construct actual disclosure service")
	}
	bind := func(t *testing.T, base context.Context, client *http.Client) context.Context {
		t.Helper()
		endpoint, parseErr := url.Parse(p.endpoint)
		if parseErr != nil || client.Jar == nil {
			t.Fatal("actual cookie jar unavailable")
		}
		var token string
		for _, cookie := range client.Jar.Cookies(endpoint) {
			if cookie.Name == "mii_session" {
				token = cookie.Value
			}
		}
		principal, principalErr := identities.Principal(base, token, orgID)
		if principalErr != nil || principal.Authorize("evidence.body") != nil {
			t.Fatal("actual session principal denied")
		}
		sum := sha256.Sum256([]byte(token))
		ctx, bindErr := store.BindControlAuthority(audit.WithActor(base, audit.Actor{ActorID: principal.UserID, ReasonCode: "display.service.test"}), hex.EncodeToString(sum[:]), orgID)
		if bindErr != nil {
			t.Fatal("bind persisted actual session authority")
		}
		return ctx
	}
	prepare := func(t *testing.T, ctx context.Context) *runservice.Disclosure {
		t.Helper()
		disclosure, prepareErr := service.PrepareDisplay(ctx, orgID, selection, "bc160663df004b25bb7496ab12dd5398")
		if prepareErr != nil || disclosure == nil {
			t.Fatal("prepare actual authenticated display")
		}
		t.Cleanup(disclosure.Close)
		return disclosure
	}
	counts := func() (pipelineDisplayGrants, error) {
		var current pipelineDisplayGrants
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_evidence_disclosures WHERE organization_id=$1", orgID).Scan(&current.receipts); err != nil {
			return current, errors.New("read committed display receipts")
		}
		if err := db.QueryRowContext(t.Context(), "SELECT count(*) FROM integrity_audit_logs WHERE organization_id=$1 AND action='evidence.body.read'", orgID).Scan(&current.audits); err != nil {
			return current, errors.New("read committed display grants")
		}
		return current, nil
	}
	count := func(t *testing.T) pipelineDisplayGrants {
		t.Helper()
		current, countErr := counts()
		if countErr != nil {
			t.Fatal("read actual display grant counts")
		}
		return current
	}
	noGrant := func(t *testing.T, before pipelineDisplayGrants) {
		t.Helper()
		if count(t) != before {
			t.Fatal("rejected service disclosure left an authorized receipt or audit")
		}
	}
	// Refill every slot after a terminal path. Checking the fifth admission
	// distinguishes exact release from both leaks and copied-handle double release.
	checkSlots := func(t *testing.T, ctx context.Context) {
		t.Helper()
		before := count(t)
		var held []*runservice.Disclosure
		defer func() {
			for _, disclosure := range held {
				disclosure.Close()
			}
		}()
		for range 4 {
			held = append(held, prepare(t, ctx))
		}
		if extra, err := service.PrepareDisplay(ctx, orgID, selection, "bc160663df004b25bb7496ab12dd5398"); extra != nil || !errors.Is(err, runservice.ErrEvidenceLimit) {
			if extra != nil {
				extra.Close()
			}
			t.Fatal("service admission did not restore exactly four slots")
		}
		noGrant(t, before)
	}
	assertCommitted := func(before pipelineDisplayGrants) error {
		current, err := counts()
		if err != nil || current.receipts != before.receipts+1 || current.audits != before.audits+1 {
			return errors.New("writer called before receipt and audit committed")
		}
		var matched int
		// Independent sql.DB observes only committed rows. The audit object must
		// bind the actual receipt ID and canonical hash, not just a count increment.
		if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM integrity_evidence_disclosures d JOIN integrity_audit_logs a ON a.organization_id=d.organization_id AND a.action='evidence.body.read' AND a.object_type='evidence_disclosure' AND a.object_id=CAST(d.id AS TEXT)||':'||d.receipt_hash WHERE d.organization_id=$1`, orgID).Scan(&matched); err != nil || matched != current.receipts {
			return errors.New("committed display receipt lacks exact audit binding")
		}
		if err := store.VerifyAllAudit(t.Context(), true); err != nil {
			return errors.New("writer observed invalid committed audit chain")
		}
		return nil
	}

	t.Run("display_service_slots_and_copied_close", func(t *testing.T) {
		ctx := bind(t, t.Context(), p.client)
		before := count(t)
		held := make([]*runservice.Disclosure, 0, 4)
		for range 4 {
			held = append(held, prepare(t, ctx))
		}
		if extra, err := service.PrepareDisplay(ctx, orgID, selection, "bc160663df004b25bb7496ab12dd5398"); extra != nil || !errors.Is(err, runservice.ErrEvidenceLimit) {
			t.Fatal("fifth prepared disclosure was admitted")
		}
		copied := *held[0]
		copied.Close()
		held[0] = prepare(t, ctx)
		copied.Close()
		if extra, err := service.PrepareDisplay(ctx, orgID, selection, "bc160663df004b25bb7496ab12dd5398"); extra != nil || !errors.Is(err, runservice.ErrEvidenceLimit) {
			t.Fatal("copied Close released a second admission slot")
		}
		noGrant(t, before)
		for _, disclosure := range held {
			var output bytes.Buffer
			if n, err := disclosure.WriteTo(ctx, &output); err != nil || n == 0 || n != int64(output.Len()) {
				t.Fatal("closing a copied handle damaged another prepared disclosure")
			}
		}
		checkSlots(t, ctx)
	})
	for _, permission := range []string{"run.read", "evidence.read", "evidence.body"} {
		t.Run("display_service_revoke_"+permission, func(t *testing.T) {
			ctx := bind(t, t.Context(), p.client)
			disclosure := prepare(t, ctx)
			before := count(t)
			restore := pipelineRemoveDisplayPermission(t, db, orgID, permission)
			calls := 0
			n, err := disclosure.WriteTo(ctx, pipelineDisplayWriterFunc(func([]byte) (int, error) { calls++; return 0, nil }))
			restore()
			if err == nil || n != 0 || calls != 0 {
				t.Fatal("prepared display bypassed persisted permission revocation")
			}
			noGrant(t, before)
			checkSlots(t, ctx)
		})
	}
	t.Run("display_service_context_binding", func(t *testing.T) {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal("create independent actual session jar")
		}
		other := pipelineHTTP{client: &http.Client{Timeout: 5 * time.Second, Jar: jar}, endpoint: p.endpoint, origin: p.origin}
		other.request(t, "POST", "/api/v1/auth/login", map[string]any{"username": "admin", "password": "synthetic-app-pipeline-password-2026"}, 200, nil)
		otherCtx := bind(t, t.Context(), other.client)
		for _, mode := range []string{"cancel-original", "unbound-context", "other-session", "cancel-write"} {
			t.Run(mode, func(t *testing.T) {
				original, cancel := context.WithCancel(bind(t, t.Context(), p.client))
				defer cancel()
				disclosure := prepare(t, original)
				before := count(t)
				writeCtx := original
				switch mode {
				case "cancel-original":
					cancel()
					writeCtx = bind(t, t.Context(), p.client)
				case "unbound-context":
					writeCtx = t.Context()
				case "other-session":
					writeCtx = otherCtx
				case "cancel-write":
					var stop context.CancelFunc
					writeCtx, stop = context.WithCancel(original)
					stop()
				}
				calls := 0
				if n, err := disclosure.WriteTo(writeCtx, pipelineDisplayWriterFunc(func([]byte) (int, error) { calls++; return 0, nil })); n != 0 || err == nil || calls != 0 {
					t.Fatal("service released through canceled or replaced authority")
				}
				noGrant(t, before)
				checkSlots(t, bind(t, t.Context(), p.client))
			})
		}
	})
	for _, mode := range []string{"success", "error", "panic", "short", "invalid-negative", "invalid-oversize"} {
		t.Run("display_service_writer_"+mode, func(t *testing.T) {
			ctx := bind(t, t.Context(), p.client)
			disclosure := prepare(t, ctx)
			before := count(t)
			calls := 0
			var borrowed []byte
			var committedError error
			const sensitiveError = "synthetic-private-writer-error-never-return"
			n, err := disclosure.WriteTo(ctx, pipelineDisplayWriterFunc(func(data []byte) (int, error) {
				calls++
				borrowed = data
				if calls == 1 {
					committedError = assertCommitted(before)
					if committedError != nil {
						return 0, committedError
					}
				}
				switch mode {
				case "error":
					return 0, errors.New(sensitiveError)
				case "panic":
					panic(sensitiveError)
				case "short":
					return len(data) - 1, nil
				case "invalid-negative":
					return -1, nil
				case "invalid-oversize":
					return len(data) + 1, nil
				default:
					return len(data), nil
				}
			}))
			if calls == 0 || committedError != nil {
				t.Fatal("writer did not observe confirmed authenticated grant")
			}
			if mode == "success" {
				if err != nil || n <= 0 {
					t.Fatal("actual display write failed")
				}
			} else if err == nil || strings.Contains(err.Error(), sensitiveError) {
				t.Fatal("writer failure was not safely closed")
			} else if mode == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write did not produce fixed short-write error")
			} else if mode != "short" && !errors.Is(err, runservice.ErrEvidenceUnavailable) {
				t.Fatal("consumer error or panic escaped the fixed service error")
			}
			if len(borrowed) == 0 || !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
				t.Fatal("terminal writer retained the private encoding buffer")
			}
			if n, err := disclosure.WriteTo(ctx, io.Discard); n != 0 || err == nil {
				t.Fatal("terminal disclosure wrote twice")
			}
			checkSlots(t, ctx)
		})
	}
	for _, closeWhileWriting := range []bool{false, true} {
		t.Run("display_service_active_copy_close_"+strconv.FormatBool(closeWhileWriting), func(t *testing.T) {
			ctx := bind(t, t.Context(), p.client)
			disclosure := prepare(t, ctx)
			copied := *disclosure
			var held []*runservice.Disclosure
			for range 3 {
				held = append(held, prepare(t, ctx))
			}
			before := count(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			defer unblock()
			type writeResult struct {
				n   int64
				err error
			}
			finished := make(chan writeResult, 1)
			go func() {
				first := true
				n, err := disclosure.WriteTo(ctx, pipelineDisplayWriterFunc(func(data []byte) (int, error) {
					if err := assertCommitted(before); err != nil {
						return 0, err
					}
					if first {
						first = false
						close(entered)
						<-release
					}
					return len(data), nil
				}))
				finished <- writeResult{n, err}
			}()
			select {
			case <-entered:
			case result := <-finished:
				t.Fatalf("original writer ended before entry: success=%t", result.err == nil)
			case <-time.After(5 * time.Second):
				t.Fatal("original writer did not reach committed entry")
			}
			duplicateCalls := 0
			n, duplicateErr := copied.WriteTo(ctx, pipelineDisplayWriterFunc(func([]byte) (int, error) { duplicateCalls++; return 0, nil }))
			if closeWhileWriting {
				copied.Close()
			}
			extra, admissionErr := service.PrepareDisplay(ctx, orgID, selection, "bc160663df004b25bb7496ab12dd5398")
			if extra != nil {
				extra.Close()
			}
			unblock()
			result := <-finished
			for _, item := range held {
				item.Close()
			}
			if n != 0 || duplicateCalls != 0 || !errors.Is(duplicateErr, runservice.ErrEvidenceUnavailable) || !errors.Is(admissionErr, runservice.ErrEvidenceLimit) {
				t.Fatal("duplicate or closed active copy released the writer-owned slot")
			}
			if closeWhileWriting {
				if result.err == nil {
					t.Fatal("explicit copied Close did not cancel active writer")
				}
			} else if result.err != nil || result.n == 0 {
				t.Fatal("duplicate WriteTo canceled the original writer")
			}
			checkSlots(t, ctx)
		})
	}
}

// Test-only committed permission removal, with exact rows saved and restored.
// Neither ciphertext nor authority is fabricated; the service must re-read the
// persisted grants after successful prepare and before the first writer call.
func pipelineRemoveDisplayPermission(t *testing.T, db *sql.DB, orgID int64, permission string) func() {
	t.Helper()
	var roleIDs, memberIDs []int64
	for _, spec := range []struct {
		query string
		ids   *[]int64
	}{
		{"SELECT role_id FROM role_permissions WHERE organization_id=$1 AND permission_code=$2", &roleIDs},
		{"SELECT member_id FROM member_permissions WHERE organization_id=$1 AND permission_code=$2", &memberIDs},
	} {
		rows, err := db.QueryContext(t.Context(), spec.query, orgID, permission)
		if err != nil {
			t.Fatal("read exact permission rows before scoped fault")
		}
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				_ = rows.Close()
				t.Fatal("read scoped permission row")
			}
			*spec.ids = append(*spec.ids, id)
		}
		err = rows.Err()
		_ = rows.Close()
		if err != nil {
			t.Fatal("complete permission snapshot")
		}
	}
	if len(roleIDs)+len(memberIDs) == 0 {
		t.Fatal("permission revocation fixture had no grant")
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, id := range roleIDs {
			if _, err := db.ExecContext(ctx, "INSERT INTO role_permissions(organization_id,role_id,permission_code) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", orgID, id, permission); err != nil {
				t.Error("restore exact role permission")
			}
		}
		for _, id := range memberIDs {
			if _, err := db.ExecContext(ctx, "INSERT INTO member_permissions(organization_id,member_id,permission_code) VALUES($1,$2,$3) ON CONFLICT DO NOTHING", orgID, id, permission); err != nil {
				t.Error("restore exact member permission")
			}
		}
		restored = true
	}
	t.Cleanup(restore)
	for _, query := range []string{"DELETE FROM role_permissions WHERE organization_id=$1 AND permission_code=$2", "DELETE FROM member_permissions WHERE organization_id=$1 AND permission_code=$2"} {
		if _, err := db.ExecContext(t.Context(), query, orgID, permission); err != nil {
			t.Fatal("commit scoped permission revocation")
		}
	}
	return restore
}
