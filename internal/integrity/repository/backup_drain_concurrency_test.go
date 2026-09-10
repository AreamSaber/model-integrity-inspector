package repository

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"gorm.io/gorm"
)

func TestBackupDrainLockedCandidateNeverLooksDrained(t *testing.T) {
	eachDatabase(t, func(t *testing.T, s *Store, cfg Config) {
		tenant, freeze, source := backupDrainPauseFixture(t, s)
		other, err := Open(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		held, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		ctx, cancel := context.WithCancel(tenant.ctx)
		var releaseOnce sync.Once
		var holdErr error
		go func() {
			defer close(done)
			holdErr = other.db.WithContext(ctx).Transaction(func(db *gorm.DB) error {
				// Deliberate actual row-lock barrier outside the admission gate,
				// exercising SKIP LOCKED rather than pretending its empty set is ready.
				if err := db.Exec("UPDATE integrity_jobs SET priority=priority WHERE id=?", source.job.ID).Error; err != nil {
					return err
				}
				close(held)
				select {
				case <-release:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
		}()
		releaseHolder := func() { releaseOnce.Do(func() { close(release) }) }
		// On any early failure the holder may still be acquiring its SQL lock:
		// cancellation must precede the join, not wait behind that blocked call.
		defer func() { cancel(); releaseHolder(); <-done }()
		select {
		case <-held:
		case <-done:
			t.Fatal("actual row lock failed", holdErr)
		case <-time.After(3 * time.Second):
			t.Fatal("row lock barrier not reached")
		}
		if cfg.Driver == "postgres" {
			got, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
			if err != nil || got != nil || !observation.CandidatePresent || !observation.ExpiredJobPresent || !observation.RunningJobPresent {
				t.Fatal("SKIP LOCKED masqueraded as drained", got, observation, err)
			}
		} else {
			bounded, stop := context.WithTimeout(tenant.ctx, 150*time.Millisecond)
			got, observation, err := freeze.LoadBackupDrainCandidate(bounded)
			stop()
			if (!errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, ErrUnavailable)) || got != nil || observation != (BackupDrainObservation{}) {
				t.Fatal("held SQLite writer yielded partial/no-error observation", err)
			}
		}
		// The successful proof releases the actual lock normally and verifies a
		// successful transaction; cleanup cancellation must not hide a failure.
		releaseHolder()
		<-done
		if holdErr != nil {
			t.Fatal("row holder failed", holdErr)
		}
		got, observation, err := freeze.LoadBackupDrainCandidate(tenant.ctx)
		if err != nil || got == nil || got.Kind() != BackupDrainPauseSafe || !observation.CandidatePresent {
			t.Fatal("released candidate lost", got, observation, err)
		}
	})
}
