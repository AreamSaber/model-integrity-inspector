// Package pgbackup runs the pinned PostgreSQL backup tools with explicit
// connection settings and bounded streams. It is trusted infrastructure, not
// a user-selected command runner, authorization check, or complete backup API.
package pgbackup

import (
	"errors"
	"io"
)

var (
	ErrConfiguration = errors.New("MI_PG_BACKUP_CONFIGURATION_INVALID")
	ErrProcess       = errors.New("MI_PG_BACKUP_PROCESS_FAILED")
	ErrCanceled      = errors.New("MI_PG_BACKUP_CANCELED")
	ErrLimit         = errors.New("MI_PG_BACKUP_LIMIT")
	ErrOutput        = errors.New("MI_PG_BACKUP_OUTPUT_FAILED")
	ErrVersion       = errors.New("MI_PG_BACKUP_TOOL_VERSION")
)

// nativeProcessSpec never comes from HTTP, arbitrary plugins, or shell text.
// path is an absolute trusted executable; args exclude argv[0]. env is complete,
// never appended to os.Environ. stdout/stderr are bounded synchronous writers.
// The caller must not supply a writer that indefinitely blocks in user code.
type nativeProcessSpec struct {
	path   string
	args   []string
	env    []string
	dir    string
	stdout io.Writer
	stderr io.Writer
}

// executeNative(ctx, spec) is implemented per supported OS. It must start the
// child in owned containment without a pre-assignment escape window, keep only
// the explicitly required inherited handles, drain both streams concurrently,
// terminate owned descendants on cancellation/I/O failure, and wait for their
// exit before returning success. Errors are closed values, not OS diagnostics.
