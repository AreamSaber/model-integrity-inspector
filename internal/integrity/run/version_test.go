package run

import (
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestVersionRequiresBoundControlAuthority(t *testing.T) {
	// An unopened store is sufficient: rejection must occur before any query,
	// and adding a public audit actor must not manufacture a session capability.
	s := &Service{cfg: Config{Store: &repository.Store{}}}
	if _, err := s.Version(t.Context(), 1, 1); !errors.Is(err, repository.ErrManagementSession) {
		t.Fatal("unbound version read was not rejected")
	}
	ctx := audit.WithActor(t.Context(), audit.Actor{ActorID: 1, ReasonCode: "integration.test"})
	if _, err := s.Version(ctx, 1, 1); !errors.Is(err, repository.ErrManagementSession) {
		t.Fatal("an audit actor granted access")
	}
	if _, err := s.Version(ctx, 0, 1); !errors.Is(err, repository.ErrOrganizationScope) {
		t.Fatal("missing tenant was not rejected")
	}
}
