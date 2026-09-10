package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"
)

type fixtureMAC struct {
	active string
	keys   map[string]string
	fail   bool
}

func (m fixtureMAC) ActiveVersion() string { return m.active }
func (m fixtureMAC) AuditMAC(version string, data []byte) ([]byte, error) {
	key, ok := m.keys[version]
	if m.fail || !ok {
		return nil, errors.New("private signer detail must not propagate")
	}
	h := hmac.New(sha256.New, []byte(key))
	_, _ = h.Write(data)
	return h.Sum(nil), nil
}

func fixtureEvent() Event {
	actorID := int64(3)
	return Event{ID: 1, OrganizationID: 2, Sequence: 1, ActorID: &actorID, Action: "target.create", ObjectType: "target", ObjectID: "4", Result: "success", IPSummary: "loopback", UserAgentSummary: "test", DiffSummary: `{"reason_code":"test"}`, CreatedAt: time.Date(2026, 9, 7, 1, 2, 3, 456789000, time.UTC)}
}

func TestCanonicalFrozenAndTamperDetection(t *testing.T) {
	signer := fixtureMAC{active: "v1", keys: map[string]string{"v1": "fixture-key"}}
	event, err := Seal(fixtureEvent(), signer)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := Canonical(event)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":"mii.audit.v1","key_version":"v1","id":1,"organization_id":2,"sequence":1,"actor_id":3,"action":"target.create","object_type":"target","object_id":"4","result":"success","ip_summary":"loopback","user_agent_summary":"test","diff_summary":"{\"reason_code\":\"test\"}","created_at_us":1788742923456789}`
	if string(canonical) != want {
		t.Fatalf("canonical contract changed:\n%s", canonical)
	}
	if err := Verify(event, signer); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Event){
		"id":             func(e *Event) { e.ID++ },
		"tenant":         func(e *Event) { e.OrganizationID++ },
		"sequence":       func(e *Event) { e.Sequence++ },
		"actor":          func(e *Event) { id := int64(99); e.ActorID = &id },
		"action":         func(e *Event) { e.Action = "target.delete" },
		"object_type":    func(e *Event) { e.ObjectType = "user" },
		"object_id":      func(e *Event) { e.ObjectID = "99" },
		"result":         func(e *Event) { e.Result = "denied" },
		"ip":             func(e *Event) { e.IPSummary = "changed" },
		"agent":          func(e *Event) { e.UserAgentSummary = "changed" },
		"diff":           func(e *Event) { e.DiffSummary = "changed" },
		"time":           func(e *Event) { e.CreatedAt = e.CreatedAt.Add(time.Microsecond) },
		"submicrosecond": func(e *Event) { e.CreatedAt = e.CreatedAt.Add(time.Nanosecond) },
		"previous":       func(e *Event) { e.PreviousHash = strings.Repeat("a", 64) },
		"hmac":           func(e *Event) { e.EventHMAC = strings.Repeat("0", 64) },
		"version":        func(e *Event) { e.CanonicalizationVersion = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			mutate(&changed)
			if err := Verify(changed, signer); !errors.Is(err, ErrIntegrity) {
				t.Fatalf("tamper accepted: %v", err)
			}
		})
	}
}

func TestKeyRotationAndUnavailableSigner(t *testing.T) {
	old := fixtureMAC{active: "old", keys: map[string]string{"old": "old-fixture"}}
	event, err := Seal(fixtureEvent(), old)
	if err != nil {
		t.Fatal(err)
	}
	rotated := fixtureMAC{active: "new", keys: map[string]string{"old": "old-fixture", "new": "new-fixture"}}
	if err := Verify(event, rotated); err != nil {
		t.Fatal("rotation invalidated historical HMAC")
	}
	newEvent, err := Seal(fixtureEvent(), rotated)
	if err != nil || newEvent.KeyVersion != "new" || newEvent.EventHMAC == event.EventHMAC {
		t.Fatal("new events did not use active key")
	}
	missing := fixtureMAC{active: "new", keys: map[string]string{"new": "new-fixture"}}
	if err := Verify(event, missing); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing retained key: %v", err)
	}
	if _, err := Seal(fixtureEvent(), fixtureMAC{fail: true, active: "test"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("signer error not sanitized: %v", err)
	}
}

func TestTrustedActorContext(t *testing.T) {
	if _, err := ActorFromContext(context.Background()); !errors.Is(err, ErrActorRequired) {
		t.Fatal("missing actor accepted")
	}
	for _, actor := range []Actor{
		{ActorID: -1, ReasonCode: "valid"},
		{ActorID: 1, ReasonCode: "arbitrary prose should not be audit data"},
		{ActorID: 1, ReasonCode: "valid", IPSummary: "inject\nheader"},
		{ActorID: 1, ReasonCode: "valid", UserAgentSummary: strings.Repeat("x", 129)},
	} {
		if _, err := ActorFromContext(WithActor(t.Context(), actor)); !errors.Is(err, ErrActorRequired) {
			t.Fatal("unsafe audit actor metadata accepted")
		}
	}
}
