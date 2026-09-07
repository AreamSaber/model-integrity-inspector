package worker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync/atomic"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/repository"
)

var (
	ErrConfiguration       = errors.New("WORKER_CONFIGURATION_INVALID")
	ErrAlreadyRunning      = errors.New("WORKER_ALREADY_RUNNING")
	ErrHandlerFailed       = errors.New("WORKER_HANDLER_FAILED")
	ErrHandlerUnresponsive = errors.New("WORKER_HANDLER_UNRESPONSIVE")
)

type Completion func(*repository.TenantTransaction) error
type Execution struct {
	Queue *repository.JobQueue
	Lease repository.JobLease
}
type Handler func(context.Context, Execution) (Completion, error)

type Config struct {
	Store    *repository.Store
	Logger   *slog.Logger
	Handlers map[repository.JobType]Handler
	// Maintenance reconciles terminal/abandoned jobs through this consumer's
	// existing queue. It must honor context and must not open a second consumer.
	Maintenance func(context.Context, *repository.JobQueue) error
	// Trusted runtime/test settings may shorten but never lengthen safety polls.
	PollInterval      time.Duration
	HeartbeatInterval time.Duration
}

type Runner struct {
	config    Config
	ready     atomic.Bool
	running   atomic.Bool
	queueGate chan struct{}
}

func New(config Config) (*Runner, error) {
	if config.Store == nil || len(config.Handlers) == 0 {
		return nil, ErrConfiguration
	}
	if config.PollInterval == 0 {
		config.PollInterval = time.Second
	}
	if config.HeartbeatInterval == 0 {
		config.HeartbeatInterval = repository.JobHeartbeatEvery
	}
	if config.PollInterval <= 0 || config.PollInterval > time.Second || config.HeartbeatInterval <= 0 || config.HeartbeatInterval > repository.JobHeartbeatEvery {
		return nil, ErrConfiguration
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	handlers := make(map[repository.JobType]Handler, len(config.Handlers))
	for kind, handler := range config.Handlers {
		if handler == nil {
			return nil, ErrConfiguration
		}
		handlers[kind] = handler
	}
	config.Handlers = handlers
	return &Runner{config: config, queueGate: make(chan struct{}, 1)}, nil
}

// Ready is false until Run owns a real consumer and its first heartbeat succeeds.
func (runner *Runner) Ready() bool { return runner.ready.Load() }

func (runner *Runner) Run(ctx context.Context) (result error) {
	if ctx == nil {
		return ErrConfiguration
	}
	defer func() {
		// Persistence intentionally sanitizes driver cancellation to unavailable.
		// The caller's own cancelled context disambiguates that shutdown path,
		// including cancellation while committing or renewing a consumer. A live
		// caller still receives database failures; fencing and unresponsive-handler
		// failures are never reclassified as graceful shutdown.
		if ctx.Err() != nil && (errors.Is(result, repository.ErrUnavailable) || errors.Is(result, context.Canceled) || errors.Is(result, context.DeadlineExceeded)) {
			result = nil
		}
	}()
	if !runner.running.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer runner.running.Store(false)
	defer runner.ready.Store(false)
	if ctx.Err() != nil {
		return nil
	}
	queue, err := runner.config.Store.OpenJobQueue(ctx)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = queue.Close(closeCtx)
	}()
	if err := queue.HeartbeatConsumer(ctx); err != nil {
		return err
	}
	if err := runner.maintain(ctx, queue); err != nil {
		return err
	}
	runner.ready.Store(true)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeatFailure := make(chan error, 1)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(runner.config.HeartbeatInterval)
		defer ticker.Stop()
		maintenance := time.NewTicker(time.Second)
		defer maintenance.Stop()
		for {
			select {
			case <-runCtx.Done():
				runner.ready.Store(false)
				return
			case <-ticker.C:
				err := runner.withQueueGate(runCtx, func() error {
					pulseCtx, stop := context.WithTimeout(runCtx, 2*time.Second)
					defer stop()
					return queue.HeartbeatConsumer(pulseCtx)
				})
				if err != nil {
					runner.ready.Store(false)
					if runCtx.Err() != nil {
						return
					}
					runner.logQueueFailure(runCtx, "consumer_heartbeat")
					heartbeatFailure <- err
					cancel()
					return
				}
			case <-maintenance.C:
				if err := runner.maintain(runCtx, queue); err != nil {
					runner.ready.Store(false)
					if runCtx.Err() != nil {
						return
					}
					runner.logQueueFailure(runCtx, "maintenance")
					heartbeatFailure <- err
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-heartbeatDone }()
	err = runner.loop(runCtx, queue)
	select {
	case failure := <-heartbeatFailure:
		return failure
	default:
	}
	return err
}

func (runner *Runner) maintain(ctx context.Context, queue *repository.JobQueue) error {
	if runner.config.Maintenance == nil {
		return nil
	}
	return runner.withQueueGate(ctx, func() error {
		bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		return runner.config.Maintenance(bounded, queue)
	})
}

// Background pulses must not time out waiting for this Runner's own terminal
// transaction on SQLite's single connection. The pulse's existing two-second
// SQL deadline starts after this cancellable gate; completion still has its
// original ten-second total deadline, including gate wait. Both remain well
// within the sixty-second lease, which the repository rechecks before and after
// completion. This grants no dispatch/commit authority and performs no retries.
func (runner *Runner) withQueueGate(ctx context.Context, operation func() error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case runner.queueGate <- struct{}{}:
	}
	defer func() { <-runner.queueGate }()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return operation()
}

// Only internal, fixed operation labels enter logs: database/handler errors can
// contain protected values and must never be logged here. Normal shutdown is
// not an outage; a live parent with a failed bounded SQL operation still is.
func (runner *Runner) logQueueFailure(ctx context.Context, operation string) {
	if ctx.Err() == nil {
		runner.config.Logger.Error("worker queue operation failed", "operation", operation)
	}
}

func (runner *Runner) loop(ctx context.Context, queue *repository.JobQueue) error {
	for ctx.Err() == nil {
		claimCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		lease, err := queue.Claim(claimCtx)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			runner.ready.Store(false)
			runner.logQueueFailure(ctx, "claim")
			return err
		}
		if lease == nil {
			timer := time.NewTimer(runner.config.PollInterval)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-timer.C:
			}
			continue
		}
		handler := runner.config.Handlers[repository.JobType(lease.Job.Type)]
		if handler == nil {
			if err := queue.Fail(ctx, *lease, "WORKER_HANDLER_UNREGISTERED"); err != nil {
				return err
			}
			continue
		}
		if err := runner.execute(ctx, queue, *lease, handler); err != nil {
			return err
		}
	}
	return nil
}

type handlerResult struct {
	completion Completion
	err        error
}

func invokeHandler(ctx context.Context, execution Execution, handler Handler) (result handlerResult) {
	defer func() {
		if recover() != nil {
			result = handlerResult{err: ErrHandlerFailed}
		}
	}()
	result.completion, result.err = handler(ctx, execution)
	return result
}

func (runner *Runner) execute(ctx context.Context, queue *repository.JobQueue, lease repository.JobLease, handler Handler) error {
	jobCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	results := make(chan handlerResult, 1)
	go func() { results <- invokeHandler(jobCtx, Execution{queue, lease}, handler) }()
	checks := time.NewTicker(runner.config.PollInterval)
	defer checks.Stop()
	heartbeats := time.NewTicker(runner.config.HeartbeatInterval)
	defer heartbeats.Stop()
	checkC, heartbeatC, stopC := checks.C, heartbeats.C, ctx.Done()
	var grace *time.Timer
	var graceC <-chan time.Time
	defer func() {
		if grace != nil {
			grace.Stop()
		}
	}()
	var lost error
	beginCancel := func(cause error) {
		cancel(cause)
		checkC = nil
		heartbeatC = nil
		stopC = nil
		if grace == nil {
			grace = time.NewTimer(5 * time.Second)
			graceC = grace.C
		}
	}
	for {
		select {
		case result := <-results:
			if ctx.Err() != nil {
				return nil
			}
			if lost != nil {
				runner.ready.Store(false)
				return lost
			}
			commitCtx, stop := context.WithTimeout(ctx, 10*time.Second)
			defer stop()
			return runner.withQueueGate(commitCtx, func() error {
				if result.err != nil {
					// Handler errors can contain arbitrary diagnostics. Never log or store
					// them. Only the fixed classification crosses this boundary.
					runner.config.Logger.Warn("worker handler failed", "code", "WORKER_HANDLER_FAILED")
					if errors.Is(result.err, repository.ErrUnavailable) {
						return queue.Retry(commitCtx, lease, "WORKER_STORAGE_UNAVAILABLE", 3*time.Second)
					}
					return queue.Fail(commitCtx, lease, "WORKER_HANDLER_FAILED")
				}
				err := queue.CompleteWith(commitCtx, lease, result.completion)
				if repository.JobType(lease.Job.Type) == repository.JobReportGenerate && errors.Is(err, repository.ErrManagementPermission) {
					// The file may exist, but publication was rolled back. Only this
					// typed report authorization rejection becomes a failed Job; audit,
					// database and fencing failures still stop this consumer.
					err = queue.FailReportGeneration(commitCtx, lease)
					if err != nil {
						runner.logQueueFailure(ctx, "fail_report")
					}
					return err
				}
				if err != nil {
					runner.logQueueFailure(ctx, "complete")
				}
				return err
			})
		case <-stopC:
			runner.ready.Store(false)
			beginCancel(context.Canceled)
		case <-graceC:
			return ErrHandlerUnresponsive
		case <-checkC:
			checkCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			err := queue.CheckLease(checkCtx, lease)
			stop()
			if err != nil {
				if !errors.Is(err, repository.ErrJobCancelled) && !errors.Is(err, repository.ErrPrecheckStale) {
					runner.logQueueFailure(ctx, "check_lease")
					lost = err
					runner.ready.Store(false)
				}
				beginCancel(err)
			}
		case <-heartbeatC:
			pulseCtx, stop := context.WithTimeout(ctx, 2*time.Second)
			renewed, err := queue.Renew(pulseCtx, lease)
			stop()
			if err != nil {
				runner.logQueueFailure(ctx, "renew")
				lost = err
				runner.ready.Store(false)
				beginCancel(err)
			} else {
				lease = renewed
			}
		}
	}
}
