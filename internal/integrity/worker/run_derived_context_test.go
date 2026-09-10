package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

func TestRunDerivationContextDetachesOnlyBusinessJobCancellation(t *testing.T) {
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded, repository.ErrJobLeaseLost, repository.ErrUnavailable, repository.ErrJobCancelled} {
		t.Run(cause.Error(), func(t *testing.T) {
			parent, cancel := context.WithCancelCause(t.Context())
			cancel(cause)
			before := time.Now()
			ctx, stop := runDerivationContext(parent)
			defer stop()
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(before) || deadline.After(time.Now().Add(3*time.Second)) {
				t.Fatal("derived preparation missing bounded deadline")
			}
			if errors.Is(cause, repository.ErrJobCancelled) {
				if ctx.Err() != nil {
					t.Fatal("business cancellation prevents pure completion preparation")
				}
			} else if !errors.Is(context.Cause(ctx), cause) {
				t.Fatal("lost lease/shutdown/deadline unexpectedly detached")
			}
			stop()
			if ctx.Err() == nil {
				t.Fatal("preparation context cannot be stopped")
			}
		})
	}
	parent, cancel := context.WithDeadline(t.Context(), time.Now().Add(time.Second))
	defer cancel()
	ctx, stop := runDerivationContext(parent)
	defer stop()
	want, _ := parent.Deadline()
	got, _ := ctx.Deadline()
	if got != want {
		t.Fatal("shorter active parent deadline was extended")
	}
	cancel()
	if ctx.Err() == nil {
		t.Fatal("active parent cancellation not inherited")
	}
}
