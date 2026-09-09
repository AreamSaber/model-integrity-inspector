//go:build linux

package pgbackup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func executeNative(ctx context.Context, spec nativeProcessSpec) (result error) {
	if err := validateNativeProcess(ctx, spec); err != nil {
		return err
	}
	closeFile := func(file *os.File) {
		if err := file.Close(); err != nil && result == nil {
			result = ErrProcess
		}
	}
	stdout, stdoutWrite, err := os.Pipe()
	if err != nil {
		return ErrProcess
	}
	defer closeFile(stdout)
	defer func() {
		if stdoutWrite != nil {
			closeFile(stdoutWrite)
		}
	}()
	stderr, stderrWrite, err := os.Pipe()
	if err != nil {
		return ErrProcess
	}
	defer closeFile(stderr)
	defer func() {
		if stderrWrite != nil {
			closeFile(stderrWrite)
		}
	}()
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		return ErrProcess
	}
	defer closeFile(stdin)
	//nolint:noctx // Cancellation is implemented below for the owned process group before reaping, not just the parent PID.
	command := exec.Command(spec.path, spec.args...) // #nosec G204 -- Private validated absolute executable/argv from trusted pinned-tool configuration; no shell.
	command.Env = append([]string{}, spec.env...)
	command.Dir = spec.dir
	command.Stdin, command.Stdout, command.Stderr = stdin, stdoutWrite, stderrWrite
	// Go's fork/exec performs setpgid in the child before exec, never afterwards.
	// This contains trusted pg_dump descendants, not arbitrary hostile programs
	// deliberately invoking setsid/setpgid to escape (that requires a cgroup).
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if ctx.Err() != nil {
		return ErrCanceled
	}
	if err = command.Start(); err != nil {
		return nativeResult(ctx, ErrProcess)
	}
	pid := command.Process.Pid
	closeFile(stdoutWrite)
	stdoutWrite = nil
	closeFile(stderrWrite)
	stderrWrite = nil
	streams := make(chan error, 2)
	go pumpNativeStream(stdout, spec.stdout, streams)
	go pumpNativeStream(stderr, spec.stderr, streams)
	pending := 2
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for result == nil {
		// WNOWAIT pins the zombie leader, preventing PID/PGID reuse before the
		// one group signal. Only command.Wait below is allowed to reap it.
		var info unix.Siginfo
		err = unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT|unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			result = ErrProcess
			break
		}
		if info.Signo != 0 {
			break
		}
		select {
		case <-ctx.Done():
			result = ErrCanceled
		case streamErr := <-streams:
			pending--
			if streamErr != nil {
				result = streamErr
			}
		case <-ticker.C:
		}
	}
	if err = unix.Kill(-pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) && result == nil {
		result = ErrProcess
	}
	if err = command.Wait(); err != nil && result == nil {
		result = ErrProcess
	}
	// No signals after reaping: a recycled numeric PGID must never be killed.
	// Orphan zombies can delay disappearance under a non-reaping init; that is
	// a cleanup failure, never evidence of a successfully empty process group.
	until := time.Now().Add(nativeCleanupTimeout)
	confirmedEmpty := false
	for {
		err = unix.Kill(-pid, 0)
		if errors.Is(err, unix.ESRCH) {
			confirmedEmpty = true
			break
		}
		if err != nil || time.Now().After(until) {
			if result == nil {
				result = ErrProcess
			}
			break
		}
		<-ticker.C
	}
	closeReads := func() { closeFile(stdout); closeFile(stderr) }
	if !confirmedEmpty {
		closeReads()
	}
	result = joinNativeStreams(streams, pending, result, closeReads)
	return nativeResult(ctx, result)
}
