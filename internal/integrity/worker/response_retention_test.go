package worker

import (
	"context"
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestResponseRetentionHandlerNeedsCompletionAuthority(t *testing.T) {
	handler := NewResponseRetentionHandler()
	for _, execution := range []Execution{{}, {Queue: &repository.JobQueue{}}} {
		if completion, err := handler(t.Context(), execution); !errors.Is(err, repository.ErrJobInvalid) || completion != nil {
			t.Fatal("wrong job gained a retention completion")
		}
	}
	execution := Execution{Queue: &repository.JobQueue{}, Lease: repository.JobLease{Job: repository.Job{Type: string(repository.JobRetentionDelete)}}}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if completion, err := handler(ctx, execution); !errors.Is(err, context.Canceled) || completion != nil {
		t.Fatal("cancelled handler gained completion")
	}
	completion, err := handler(t.Context(), execution)
	if err != nil || completion == nil {
		t.Fatal("retention handler did not defer deletion to completion")
	}
	if !errors.Is(completion(nil), repository.ErrJobInvalid) || !errors.Is(completion(&repository.TenantTransaction{}), repository.ErrTransactionClosed) {
		t.Fatal("unfenced synthetic transaction could authorize deletion")
	}
}
