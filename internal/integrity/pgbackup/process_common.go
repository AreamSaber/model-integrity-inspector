package pgbackup

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

const nativeCleanupTimeout = 5 * time.Second

func validateNativeProcess(ctx context.Context, spec nativeProcessSpec) error {
	if ctx == nil || !filepath.IsAbs(spec.path) || !filepath.IsAbs(spec.dir) ||
		strings.ContainsAny(spec.path, "\x00\"") || strings.ContainsRune(spec.dir, 0) ||
		spec.env == nil || nilNativeWriter(spec.stdout) || nilNativeWriter(spec.stderr) {
		return ErrConfiguration
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 24*time.Hour {
		return ErrConfiguration
	}
	if ctx.Err() != nil {
		return ErrCanceled
	}
	if len(spec.args) > 256 || len(spec.env) > 256 {
		return ErrConfiguration
	}
	bytes := len(spec.path) + len(spec.dir)
	for _, arg := range spec.args {
		if strings.ContainsRune(arg, 0) {
			return ErrConfiguration
		}
		bytes += len(arg)
	}
	seen := make(map[string]bool, len(spec.env))
	for _, entry := range spec.env {
		name, _, ok := strings.Cut(entry, "=")
		name = strings.ToUpper(name)
		if !ok || name == "" || strings.ContainsRune(entry, 0) || seen[name] {
			return ErrConfiguration
		}
		seen[name] = true
		bytes += len(entry)
	}
	if bytes > 1<<20 {
		return ErrConfiguration
	}
	return nil
}

func nilNativeWriter(writer io.Writer) bool {
	if writer == nil {
		return true
	}
	value := reflect.ValueOf(writer)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// Exactly one pump owns each writer. A writer must return promptly; Go cannot
// interrupt arbitrary blocked user code. The executor joins both pumps before
// returning. Neither writer errors nor panic values cross this boundary.
func pumpNativeStream(reader io.Reader, writer io.Writer, result chan<- error) {
	var failure error
	defer func() {
		if recover() != nil {
			failure = ErrOutput
		}
		result <- failure
	}()
	buffer := make([]byte, 32<<10)
	emptyReads := 0
	for {
		n, readErr := reader.Read(buffer)
		if n < 0 || n > len(buffer) {
			failure = ErrProcess
			return
		}
		if n > 0 {
			emptyReads = 0
			written, writeErr := writer.Write(buffer[:n])
			if writeErr != nil || written != n {
				failure = ErrOutput
				if errors.Is(writeErr, ErrLimit) {
					failure = ErrLimit
				}
				return
			}
		} else {
			emptyReads++
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				failure = ErrProcess
			}
			return
		}
		if emptyReads >= 100 {
			failure = ErrProcess
			return
		}
	}
}

func nativeResult(ctx context.Context, failure error) error {
	if ctx.Err() != nil {
		return ErrCanceled
	}
	return failure
}

func joinNativeStreams(streams <-chan error, pending int, failure error, closeReads func()) error {
	timer := time.NewTimer(nativeCleanupTimeout)
	defer timer.Stop()
	for pending > 0 {
		select {
		case streamErr := <-streams:
			pending--
			if streamErr != nil && (failure == nil || errors.Is(streamErr, ErrLimit) || errors.Is(streamErr, ErrOutput)) {
				failure = streamErr
			}
		case <-timer.C:
			if failure == nil {
				failure = ErrProcess
			}
			// File.Close interrupts pending pipe reads. This cannot interrupt an
			// arbitrary stuck writer; writers are trusted prompt-return callbacks.
			closeReads()
			for pending > 0 {
				<-streams
				pending--
			}
		}
	}
	return failure
}
