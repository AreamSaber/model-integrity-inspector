//go:build windows

package privatefile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

type windowsBackupWorkspace struct {
	guard *sqliteWindowsStaging
	ctx   context.Context
}

func newBackupWorkspaceNative(ctx context.Context, parent string) (_ backupWorkspaceNative, finalErr error) {
	s := &sqliteWindowsStaging{}
	defer func() {
		if finalErr != nil {
			_ = s.cleanup()
		}
	}()
	if err := s.openChain(parent); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	s.workName = ".mii-backup-" + hex.EncodeToString(nonce[:])
	var err error
	s.work, err = sqliteWindowsOpen(windows.Handle(s.parent().file.Fd()), s.workName,
		sqliteWindowsOpenOptions{directory: true, create: true, delete: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
	if err != nil {
		return nil, err
	}
	s.workID, err = sqliteWindowsFileID(s.work)
	if err != nil {
		return nil, err
	}
	if err := s.inspectDirectories(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	return &windowsBackupWorkspace{guard: s, ctx: ctx}, nil
}

func (n *windowsBackupWorkspace) create(name string) (*os.File, error) {
	return createTemp(n.guard.work, name)
}
func (n *windowsBackupWorkspace) open(name string, deleting bool) (*os.File, error) {
	return sqliteWindowsOpen(windows.Handle(n.guard.work.Fd()), name, sqliteWindowsOpenOptions{write: deleting, delete: deleting})
}
func (n *windowsBackupWorkspace) check(f *os.File, name string, expected os.FileInfo) error {
	if expected == nil {
		return ErrUnsafe
	}
	if err := validateFile(f); err != nil {
		return err
	}
	if err := sqliteWindowsACL(f, ""); err != nil {
		return err
	}
	actual, err := canonicalName(f)
	if err != nil || !strings.EqualFold(actual, filepath.Join(n.guard.workspacePath(), name)) {
		return ErrUnsafe
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(expected, info) {
		return ErrUnsafe
	}
	return nil
}
func (n *windowsBackupWorkspace) names(entries map[string]*backupWorkspaceEntry) (finalErr error) {
	s := n.guard
	dir, err := sqliteWindowsOpen(windows.Handle(s.parent().file.Fd()), s.workName,
		sqliteWindowsOpenOptions{directory: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE})
	if err != nil {
		return err
	}
	defer func() {
		if err := dir.Close(); err != nil && finalErr == nil {
			finalErr = ErrUnavailable
		}
	}()
	if err := sqliteWindowsMatches(dir, s.workID); err != nil {
		return err
	}
	return backupWorkspaceNames(dir, entries)
}
func (n *windowsBackupWorkspace) inspect(entries map[string]*backupWorkspaceEntry, maxBytes int64) error {
	if err := n.guard.inspectDirectories(); err != nil {
		return err
	}
	if err := n.names(entries); err != nil {
		return err
	}
	return backupWorkspaceInspect(n.ctx, n, entries, maxBytes)
}
func (n *windowsBackupWorkspace) remove(f *os.File, name string) error {
	return removeTemp(n.guard.work, f, name)
}
func (n *windowsBackupWorkspace) cleanup(entries map[string]*backupWorkspaceEntry) (finalErr error) {
	defer func() {
		if err := n.guard.cleanup(); err != nil && finalErr == nil {
			finalErr = err
		}
	}()
	if err := n.guard.inspectDirectories(); err != nil {
		// Ensure guard.cleanup closes pins without deleting this unverified dir.
		n.guard.cleanupErr = err
		return err
	}
	namesErr := n.names(entries)
	removeErr := backupWorkspaceRemoveOwned(n, entries)
	if namesErr != nil {
		n.guard.cleanupErr = namesErr
		return namesErr
	}
	if removeErr != nil {
		n.guard.cleanupErr = removeErr
		return removeErr
	}
	return nil
}
