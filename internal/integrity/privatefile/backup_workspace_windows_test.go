//go:build windows

package privatefile

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func backupWorkspaceNativeTestPath(n backupWorkspaceNative) string {
	return n.(*windowsBackupWorkspace).guard.workspacePath()
}
func backupWorkspaceNativeTestBreakClose(t *testing.T, n backupWorkspaceNative) {
	t.Helper()
	if err := n.(*windowsBackupWorkspace).guard.work.Close(); err != nil {
		t.Fatal("close fault setup failed")
	}
}

func TestBackupWorkspaceWindowsExclusiveReopen(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	receipt, err := WithBackupWorkspace(t.Context(), parent, backupWorkspaceTestLimits(), func(_ context.Context, w *BackupWorkspace) error {
		object, err := w.Put(BackupObjectLimits{MaxBytes: 7}, backupWorkspaceProduce([]byte("content")))
		if err != nil {
			return err
		}
		path := filepath.Join(backupWorkspaceNativeTestPath(w.state.native), object.entry.name)
		_, err = w.Read(object, func(_ context.Context, r io.Reader) error {
			// #nosec G304 -- intentional exclusive-access probe of the exact owned test object.
			if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
				_ = f.Close()
				return ErrUnsafe
			}
			if err := os.Rename(path, path+"-replaced"); err == nil {
				return ErrUnsafe
			}
			_, err := io.Copy(io.Discard, r)
			return err
		})
		return err
	})
	if err != nil || receipt.Objects != 1 {
		t.Fatalf("exclusive read: %v", err)
	}
	assertSQLiteParentEmpty(t, parent)
}
