//go:build !windows && !linux

package pgbackup

import "context"

func executeNative(context.Context, nativeProcessSpec) error { return ErrConfiguration }
