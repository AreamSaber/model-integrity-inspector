//go:build !linux && !windows

package privatefile

import "context"

func newBackupWorkspaceNative(context.Context, string) (backupWorkspaceNative, error) {
	return nil, ErrFilesystem
}
