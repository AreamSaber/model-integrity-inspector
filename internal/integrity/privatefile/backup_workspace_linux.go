//go:build linux

package privatefile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"

	"golang.org/x/sys/unix"
)

type linuxBackupWorkspace struct {
	guard *linuxSQLiteStaging
	ctx   context.Context
}

func newBackupWorkspaceNative(ctx context.Context, parent string) (_ backupWorkspaceNative, finalErr error) {
	p, err := openLinuxSQLiteParent(parent)
	if err != nil {
		return nil, err
	}
	s := &linuxSQLiteStaging{parent: p, parentPath: parent}
	defer func() {
		if finalErr != nil {
			_ = s.cleanup()
		}
	}()
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrUnavailable
	}
	s.workName = ".mii-backup-" + hex.EncodeToString(nonce[:])
	if err := unix.Mkdirat(int(p.Fd()), s.workName, 0o700); err != nil {
		return nil, ErrUnavailable
	}
	fd, err := unix.Openat(int(p.Fd()), s.workName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	s.work = os.NewFile(uintptr(fd), "private-backup-workspace")
	s.workID, err = s.work.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := s.verifyDirectories(); err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ErrCanceled
	}
	return &linuxBackupWorkspace{guard: s, ctx: ctx}, nil
}
func (n *linuxBackupWorkspace) create(name string) (*os.File, error) {
	return createTemp(n.guard.work, name)
}
func (n *linuxBackupWorkspace) open(name string, _ bool) (*os.File, error) {
	return openInput(n.guard.work, name)
}
func (n *linuxBackupWorkspace) check(f *os.File, name string, expected os.FileInfo) error {
	if expected == nil {
		return ErrUnsafe
	}
	if err := validateFile(f); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil || !os.SameFile(expected, info) {
		return ErrUnsafe
	}
	return linuxSQLiteEntry(n.guard.work, name, expected, false)
}
func (n *linuxBackupWorkspace) names(entries map[string]*backupWorkspaceEntry) (finalErr error) {
	fd, err := unix.Openat(int(n.guard.work.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	dir := os.NewFile(uintptr(fd), "private-backup-enumeration")
	defer func() {
		if err := dir.Close(); err != nil && finalErr == nil {
			finalErr = ErrUnavailable
		}
	}()
	info, err := dir.Stat()
	if err != nil || !os.SameFile(n.guard.workID, info) {
		return ErrUnsafe
	}
	return backupWorkspaceNames(dir, entries)
}
func (n *linuxBackupWorkspace) inspect(entries map[string]*backupWorkspaceEntry, maxBytes int64) error {
	if err := n.guard.verifyDirectories(); err != nil {
		return err
	}
	if err := n.names(entries); err != nil {
		return err
	}
	return backupWorkspaceInspect(n.ctx, n, entries, maxBytes)
}
func (n *linuxBackupWorkspace) remove(f *os.File, name string) error {
	return removeTemp(n.guard.work, f, name)
}
func (n *linuxBackupWorkspace) cleanup(entries map[string]*backupWorkspaceEntry) (finalErr error) {
	defer func() {
		if err := n.guard.cleanup(); err != nil && finalErr == nil {
			finalErr = err
		}
	}()
	if err := n.guard.verifyDirectories(); err != nil {
		return err
	}
	namesErr := n.names(entries)
	removeErr := backupWorkspaceRemoveOwned(n, entries)
	if namesErr != nil {
		return namesErr
	}
	return removeErr
}
