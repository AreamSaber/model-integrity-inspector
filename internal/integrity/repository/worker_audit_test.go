package repository

import (
	"context"
	"errors"
	"testing"

	"model-integrity-inspector.local/mii/internal/integrity/audit"
)

func TestWorkerAuditContextRequiresAuthoritativeJobBinding(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		tenant, _, plan, policy := executionFixture(t, store, 1)
		run, err := tenant.CreateRun(plan, policy, "audit-binding")
		if err != nil {
			t.Fatal(err)
		}
		q, err := store.OpenJobQueue(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = q.Close(context.Background()) })
		lease := mustClaim(t, q)
		called := false
		for _, change := range []func(*JobLease){
			func(l *JobLease) { l.Job.ObjectID++ },
			func(l *JobLease) { l.Job.Type = string(JobSampleExecute) },
			func(l *JobLease) { l.Job.OrganizationID++ },
			func(l *JobLease) { l.Generation++ },
		} {
			forged := lease
			change(&forged)
			err := q.CompleteWith(context.Background(), forged, func(*TenantTransaction) error { called = true; return nil })
			if !errors.Is(err, ErrJobLeaseLost) || called {
				t.Fatal("forged lease entered audited callback")
			}
		}
		originalActor, _ := audit.ActorFromContext(tenant.ctx)
		spoofed := audit.WithActor(context.Background(), audit.Actor{ActorID: originalActor.ActorID + 1, ReasonCode: "spoof", IPSummary: "spoof", UserAgentSummary: "spoof"})
		err = q.CompleteWith(spoofed, lease, func(tx *TenantTransaction) error {
			actor, err := audit.ActorFromContext(tx.ctx)
			if err != nil || actor.ActorID != run.CreatedBy || actor.ReasonCode != "worker.run.plan" || actor.IPSummary != "" || actor.UserAgentSummary != "" {
				return ErrConflict
			}
			return tx.StartRun(run.ID)
		})
		if err != nil {
			t.Fatal(err)
		}
		current, _ := tenant.GetRun(run.ID)
		if current.Status != "RUNNING" {
			t.Fatal("authoritative run failed")
		}
		// Unsupported types and dangling typed bindings cannot inherit the
		// spoofed caller's otherwise syntactically valid audit identity.
		for _, job := range []Job{
			{ID: 1, OrganizationID: tenant.orgID, ObjectID: run.ID, Type: "unknown"},
			{ID: lease.Job.ID + 1, OrganizationID: tenant.orgID, ObjectID: run.ID, Type: string(JobRunPlan)},
			{ID: lease.Job.ID, OrganizationID: tenant.orgID + 1, ObjectID: run.ID, Type: string(JobRunPlan)},
		} {
			if _, err := workerAuditContext(spoofed, store.db, job); !errors.Is(err, ErrJobInvalid) {
				t.Fatal("unbound job received actor")
			}
		}
	})
}

func TestGenericQueueCapabilityCannotInheritBusinessAuditActor(t *testing.T) {
	eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
		initial, tenant, q := queueFixture(t, store)
		job := mustEnqueue(t, tenant, retentionJob(tenant.orgID, "actorless-queue"))
		lease := mustClaim(t, q)
		ctx := audit.WithActor(context.Background(), audit.Actor{ActorID: initial.User.ID, ReasonCode: "spoof"})
		err := q.CompleteWith(ctx, lease, func(tx *TenantTransaction) error {
			if _, err := audit.ActorFromContext(tx.ctx); !errors.Is(err, audit.ErrActorRequired) {
				return ErrConflict
			}
			return store.appendAudit(tx.ctx, tx.db, tenant.orgID, auditObject("run.start", "run", 1), nil)
		})
		if !errors.Is(err, audit.ErrActorRequired) {
			t.Fatal("generic queue primitive gained business audit authority")
		}
		unchanged, err := tenant.GetJob(job.ID)
		if err != nil || unchanged.Status != "running" {
			t.Fatal("rejected audit committed generic completion")
		}
		if err := q.Complete(context.Background(), lease); err != nil {
			t.Fatal(err)
		}
	})
}

func TestBackgroundWorkerSampleRecoveryAndAuditRollback(t *testing.T) {
	for _, dispatched := range []bool{false, true} {
		name := "not-dispatched"
		if dispatched {
			name = "uncertain-dispatched"
		}
		t.Run(name, func(t *testing.T) {
			eachDatabase(t, func(t *testing.T, store *Store, _ Config) {
				tenant, _, plan, policy := executionFixture(t, store, 1)
				run, q, samples := executionStart(t, tenant, plan, policy)
				lease := mustClaim(t, q)
				if dispatched {
					if err := q.WithLease(context.Background(), lease, func(tx *TenantTransaction) error {
						_, err := tx.ReserveAttempt(samples[0].ID, testWireSnapshot(t, samples[0]))
						return err
					}); err != nil {
						t.Fatal(err)
					}
				}
				if err := q.Fail(context.Background(), lease, "WORKER_HANDLER_UNAVAILABLE"); err != nil {
					t.Fatal(err)
				}
				signer := store.auditSigner
				store.auditSigner = nil
				err := q.ReconcileExecution(context.Background(), tenant.orgID)
				store.auditSigner = signer
				if !errors.Is(err, audit.ErrUnavailable) {
					t.Fatal("unauditable background recovery committed")
				}
				current, err := tenant.GetExecutionSampleForWorker(samples[0].ID)
				if err != nil || current.CompletedAt != nil {
					t.Fatal("failed recovery audit left business changes")
				}
				// Historical attribution remains possible after account/membership
				// disablement; it is not new request/control authorization.
				if err := store.db.Model(&User{}).Where("id = ?", run.CreatedBy).Update("status", "disabled").Error; err != nil {
					t.Fatal(err)
				}
				if err := store.db.Model(&Membership{}).Where("organization_id = ? AND user_id = ?", tenant.orgID, run.CreatedBy).Update("status", "disabled").Error; err != nil {
					t.Fatal(err)
				}
				if err := q.ReconcileExecution(context.Background(), tenant.orgID); err != nil {
					t.Fatal(err)
				}
				closed, err := tenant.GetRun(run.ID)
				if err != nil || closed.Status != "ANALYZING" || closed.ExecutionClosedAt == nil || closed.ReservedTokens != 0 {
					t.Fatal("background sample recovery did not settle")
				}
				attempts, err := tenant.ListAttempts(samples[0].ID)
				if err != nil {
					t.Fatal(err)
				}
				if dispatched && (len(attempts) != 1 || attempts[0].Status != "UNCERTAIN" || closed.RequestCount != 1) {
					t.Fatal("uncertain billing state lost")
				}
				if !dispatched && (len(attempts) != 0 || closed.RequestCount != 0) {
					t.Fatal("unattempted recovery invented requests")
				}
				var events []audit.Event
				if err := store.db.Where("organization_id = ? AND action IN ('run.attempt.finish','run.sample.reconcile','run.execution.close')", tenant.orgID).Find(&events).Error; err != nil {
					t.Fatal(err)
				}
				if len(events) != 2 {
					t.Fatal("recovery audit count incorrect")
				}
				for _, event := range events {
					if event.ActorID == nil || *event.ActorID != run.CreatedBy || event.DiffSummary != `{"reason_code":"worker.sample.execute"}` {
						t.Fatal("recovery attribution wrong")
					}
				}
				if _, err := tenant.VerifyAuditFull(); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}
