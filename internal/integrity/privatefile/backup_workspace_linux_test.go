//go:build linux

package privatefile

import (
	"path/filepath"
	"testing"
)

func backupWorkspaceNativeTestPath(n backupWorkspaceNative) string {
	s := n.(*linuxBackupWorkspace).guard
	return filepath.Join(s.parentPath, s.workName)
}
func backupWorkspaceNativeTestBreakClose(t *testing.T, n backupWorkspaceNative) {
	t.Helper()
	if err := n.(*linuxBackupWorkspace).guard.work.Close(); err != nil {
		t.Fatal("close fault setup failed")
	}
}
