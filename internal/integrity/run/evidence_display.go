package run

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/evidencedisplay"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const evidenceDisplayFormat = repository.DisclosureFormatVersion

var (
	ErrEvidenceUnavailable = errors.New("MI_EVIDENCE_UNAVAILABLE")
	ErrEvidenceLimit       = errors.New("MI_EVIDENCE_LIMIT")
)

// EvidenceService owns only a display-purpose opener. It cannot load credentials,
// decrypt raw analysis bodies, or make upstream requests.
type EvidenceService struct {
	store  *repository.Store
	opener *secret.DisplayOpener
	slots  chan struct{}
}

func NewEvidenceService(store *repository.Store, opener *secret.DisplayOpener) (*EvidenceService, error) {
	if store == nil || opener == nil {
		return nil, ErrInvalid
	}
	return &EvidenceService{store: store, opener: opener, slots: make(chan struct{}, 4)}, nil
}

// EvidenceDisplayView is a safe header, not the decrypted evidence document.
type EvidenceDisplayView struct {
	Version          string `json:"version"`
	RunID            string `json:"run_id"`
	SampleID         string `json:"sample_id"`
	AttemptID        string `json:"attempt_id"`
	AnalysisRevision int    `json:"analysis_revision"`
	IsFinal          bool   `json:"is_final"`
	Status           string `json:"status"`
	PayloadHash      string `json:"payload_hash,omitempty"`
}

// Disclosure has no plaintext getter or public marshal representation. Prepare
// does not authorize sending: WriteTo commits the final grant before any bytes.
// Close cancels an in-flight writer; its slot stays held until the writer exits.
type Disclosure struct {
	*disclosureState
}

// The exported handle can be copied as a Go value. All copies must share the
// same ownership, cancellation and admission slot, not just the byte slice.
type disclosureState struct {
	mu      sync.Mutex
	state   int // 0 prepared, 1 writing, 2 closed
	data    []byte
	ctx     context.Context
	cancel  context.CancelFunc
	store   *repository.Store
	orgID   int64
	source  *repository.DisplayReadSource
	summary repository.DisclosureSummary
	release func()
	view    EvidenceDisplayView
}

func (Disclosure) String() string               { return "[protected evidence disclosure]" }
func (d Disclosure) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, d.String()) }
func (Disclosure) MarshalJSON() ([]byte, error) { return nil, evidencedisplay.ErrSensitive }
func (d Disclosure) LogValue() slog.Value       { return slog.StringValue(d.String()) }

func (d *Disclosure) View() EvidenceDisplayView {
	if d == nil || d.disclosureState == nil {
		return EvidenceDisplayView{}
	}
	return d.view
}

func (d *Disclosure) Close() {
	if d == nil || d.disclosureState == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cancel != nil {
		d.cancel()
	}
	if d.state == 1 { // The writer owns and clears the buffer and slot.
		return
	}
	if d.state != 2 {
		d.finishLocked()
	}
}

func (d *disclosureState) finishLocked() {
	d.state = 2
	clear(d.data)
	d.data = nil
	if d.source != nil {
		d.source.Close()
	}
	if d.release != nil {
		d.release()
		d.release = nil
	}
}

func knownDisplayStatus(status string) bool {
	switch status {
	case "available", "unavailable_policy_zero", "unavailable_not_retained", "unavailable_not_captured", "unavailable_uncertain", "unavailable_expired", "unavailable_legacy_unverified", repository.DisplayReadDeleted,
		repository.DisplayUnavailablePolicy, repository.DisplayUnavailableLimit, repository.DisplayUnavailableSource, repository.DisplayUnavailableCancelled, repository.DisplayUnavailableCapture, repository.DisplayUnavailableSeal:
		return true
	default:
		return false
	}
}

func (s *EvidenceService) PrepareDisplay(ctx context.Context, org int64, selection repository.DisplaySelection, requestID string) (*Disclosure, error) {
	if s == nil || s.store == nil || s.opener == nil || s.slots == nil || ctx == nil {
		return nil, ErrEvidenceUnavailable
	}
	decodedID, idError := hex.DecodeString(requestID)
	if idError != nil || len(decodedID) != 16 || hex.EncodeToString(decodedID) != requestID {
		return nil, ErrInvalid
	}
	if err := s.store.RequireControlAuthority(ctx, org); err != nil {
		return nil, err
	}
	select {
	case s.slots <- struct{}{}:
	default:
		return nil, ErrEvidenceLimit
	}
	life, cancel := context.WithTimeout(ctx, 10*time.Second)
	d := &Disclosure{disclosureState: &disclosureState{ctx: life, cancel: cancel, store: s.store, orgID: org, release: func() { <-s.slots }}}
	ok := false
	defer func() {
		if !ok {
			d.Close()
		}
	}()
	tenant, err := s.store.WithOrganization(life, org)
	if err != nil {
		return nil, err
	}
	d.source, err = tenant.PrepareEvidenceDisplay(selection)
	if err != nil {
		return nil, err
	}
	meta := d.source.Metadata()
	if !knownDisplayStatus(meta.Status) {
		return nil, ErrEvidenceUnavailable
	}
	d.view = EvidenceDisplayView{Version: evidenceDisplayFormat, RunID: decimal(meta.Selection.RunID), SampleID: decimal(meta.Selection.SampleID), AttemptID: decimal(meta.Selection.AttemptID), AnalysisRevision: meta.Selection.AnalysisRevision, IsFinal: meta.IsFinal, Status: meta.Status, PayloadHash: meta.PayloadHash}
	var payload json.RawMessage
	defer func() { clear(payload) }()
	if meta.Status == "available" {
		prepare, stop := context.WithTimeout(life, 2*time.Second)
		defer stop()
		err = d.source.WithEnvelope(func(envelope repository.DisplayReadEnvelope) error {
			r := envelope.Record
			binding := secret.DisplayBinding{Scope: secret.EvidenceScope{OrganizationID: r.OrganizationID, RunID: r.RunID, LogicalSampleID: r.LogicalSampleID, AttemptID: r.AttemptID, RequestHash: r.RequestHash}, SourceHash: r.SourceHash, CapturedAtMicros: r.CapturedAtMicros, ExpiresAtMicros: r.ExpiresAtMicros}
			record := secret.DisplayRecord{Version: r.Version, Policy: r.Policy, KeyVersion: r.KeyVersion, Nonce: r.Nonce, Ciphertext: r.Ciphertext, PlaintextBytes: r.PlaintextBytes, PayloadHash: r.PayloadHash}
			opened, err := s.opener.Open(prepare, binding, record)
			if err != nil {
				return ErrEvidenceUnavailable
			}
			defer opened.Close()
			return opened.WithCanonicalForDisplay(prepare, func(data []byte) error {
				payload = bytes.Clone(data) // Private encoding only; not a release.
				return nil
			})
		})
		if err != nil {
			return nil, ErrEvidenceUnavailable
		}
	}
	// The sole sensitive DTO exists only inside this codec. Null is deliberate
	// for unavailable content; an empty fabricated response is never substituted.
	d.data, err = json.Marshal(struct {
		RequestID string `json:"request_id"`
		Data      struct {
			EvidenceDisplayView
			Content json.RawMessage `json:"content"`
		} `json:"data"`
	}{RequestID: requestID, Data: struct {
		EvidenceDisplayView
		Content json.RawMessage `json:"content"`
	}{d.view, payload}})
	if err != nil || len(d.data) == 0 || len(d.data) > 8<<20 || life.Err() != nil {
		return nil, ErrEvidenceUnavailable
	}
	hash := sha256.Sum256(d.data)
	d.summary = repository.DisclosureSummary{FormatVersion: evidenceDisplayFormat, OutputHash: hex.EncodeToString(hash[:]), OutputBytes: int64(len(d.data))}
	ok = true
	return d, nil
}

// WriteTo accepts one bounded grant. Every block revalidates the persisted
// authority and retention policy. Commit and socket writes are not atomic:
// later revocation stops remaining output but cannot retract earlier bytes.
func (d *Disclosure) WriteTo(ctx context.Context, dst io.Writer) (written int64, result error) {
	if d == nil || d.disclosureState == nil || ctx == nil || dst == nil {
		return 0, ErrEvidenceUnavailable
	}
	d.mu.Lock()
	if d.state != 0 {
		d.mu.Unlock()
		return 0, ErrEvidenceUnavailable
	}
	if len(d.data) == 0 || d.ctx == nil || d.ctx.Err() != nil {
		d.mu.Unlock()
		d.Close()
		return 0, ErrEvidenceUnavailable
	}
	d.state = 1
	data := d.data
	d.data = nil
	d.mu.Unlock()
	defer func() {
		clear(data)
		d.cancel()
		d.mu.Lock()
		d.finishLocked()
		d.mu.Unlock()
		if recover() != nil {
			result = ErrEvidenceUnavailable
		}
	}()
	deadline, ok := d.ctx.Deadline()
	if !ok {
		return 0, ErrEvidenceUnavailable
	}
	operation, stop := context.WithDeadline(ctx, deadline)
	defer stop()
	detach := context.AfterFunc(d.ctx, stop)
	defer detach()
	if operation.Err() != nil {
		return 0, ErrEvidenceUnavailable
	}
	tenant, err := d.store.WithOrganization(operation, d.orgID)
	if err != nil {
		return 0, err
	}
	permit, err := tenant.CommitEvidenceDisplayRead(d.source, d.summary)
	if err != nil {
		return 0, err
	}
	defer permit.Close()
	if err := permit.Begin(operation, d.summary); err != nil {
		return 0, err
	}
	for offset := 0; offset < len(data); {
		if operation.Err() != nil {
			return written, ErrEvidenceUnavailable
		}
		if err := permit.Revalidate(operation); err != nil {
			return written, err
		}
		end := min(offset+(64<<10), len(data))
		expected := end - offset
		n, err := dst.Write(data[offset:end])
		if n < 0 || n > end-offset {
			return written, ErrEvidenceUnavailable
		}
		written += int64(n)
		offset += n
		if err != nil {
			return written, ErrEvidenceUnavailable // Do not expose a consumer error.
		}
		if n != expected {
			return written, io.ErrShortWrite
		}
	}
	if operation.Err() != nil || d.ctx.Err() != nil {
		return written, ErrEvidenceUnavailable
	}
	return written, nil
}
