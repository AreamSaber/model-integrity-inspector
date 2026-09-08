//go:build linux

package privatefile

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type linuxSQLiteStaging struct {
	parent     *os.File
	parentPath string
	work       *os.File
	workName   string
	workID     os.FileInfo
	main       *os.File
	mainID     os.FileInfo
	sidecars   map[string]unix.Stat_t
	closed     bool
}

// Unlike ordinary handle-relative privatefile operations, SQLite reopens an
// absolute pathname. Every ancestor must therefore exclude cross-UID replacement.
// Holding a Linux dirfd does NOT prevent rename. Sticky writable ancestors are
// allowed only when both the directory and each next child have a trusted owner.
func openLinuxSQLiteParent(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 256 {
		_ = unix.Close(fd)
		return nil, ErrLimit
	}
	for _, name := range parts {
		if err := linuxSQLiteAncestor(fd); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		if name == "" {
			continue
		}
		next, openErr := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			_ = unix.Close(fd)
			return nil, ErrUnsafe
		}
		var handle, entry unix.Stat_t
		valid := unix.Fstat(next, &handle) == nil && unix.Fstatat(fd, name, &entry, unix.AT_SYMLINK_NOFOLLOW) == nil &&
			handle.Dev == entry.Dev && handle.Ino == entry.Ino && entry.Mode&unix.S_IFMT == unix.S_IFDIR
		closeErr := unix.Close(fd)
		if !valid || closeErr != nil {
			_ = unix.Close(next)
			return nil, ErrUnsafe
		}
		fd = next
	}
	if err := linuxSQLiteAncestor(fd); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "sqlite-private-parent")
	if err := validateDirectory(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		_ = f.Close()
		return nil, ErrPermissions
	}
	return f, nil
}

func linuxSQLiteAncestor(fd int) error {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		return ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafe
	}
	if st.Uid != 0 && int64(st.Uid) != int64(os.Geteuid()) {
		return ErrPermissions
	}
	if st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
		return ErrPermissions
	}
	return nil
}

func newSQLiteStaging(parent string) (_ sqliteStagingNative, finalErr error) {
	p, err := openLinuxSQLiteParent(parent)
	if err != nil {
		return nil, err
	}
	s := &linuxSQLiteStaging{parent: p, parentPath: parent, sidecars: make(map[string]unix.Stat_t)}
	defer func() {
		if finalErr != nil {
			_ = s.cleanup()
		}
	}()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, ErrUnavailable
	}
	s.workName = ".mii-sqlite-" + hex.EncodeToString(random[:])
	if err := unix.Mkdirat(int(p.Fd()), s.workName, 0o700); err != nil {
		return nil, ErrUnavailable
	}
	fd, err := unix.Openat(int(p.Fd()), s.workName, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		// Without an acquired identity, do not delete a name speculatively.
		return nil, ErrUnsafe
	}
	s.work = os.NewFile(uintptr(fd), "sqlite-private-workspace")
	s.workID, err = s.work.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := validateDirectory(s.work); err != nil {
		return nil, err
	}
	s.main, err = createTemp(s.work, "snapshot.db")
	if err != nil {
		return nil, err
	}
	s.mainID, err = s.main.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := s.inspect(MaxBytes, MaxSQLiteWorkspaceBytes, false); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *linuxSQLiteStaging) databasePath() string {
	return filepath.Join(s.parentPath, s.workName, "snapshot.db")
}

func (s *linuxSQLiteStaging) verifyDirectories() error {
	if s.parent == nil || s.work == nil || s.workID == nil {
		return ErrUnsafe
	}
	current, err := openLinuxSQLiteParent(s.parentPath)
	if err != nil {
		return err
	}
	oldInfo, oldErr := s.parent.Stat()
	nowInfo, nowErr := current.Stat()
	closeErr := current.Close()
	if oldErr != nil || nowErr != nil || closeErr != nil || !os.SameFile(oldInfo, nowInfo) {
		return ErrUnsafe
	}
	if err := validateDirectory(s.work); err != nil {
		return err
	}
	info, err := s.work.Stat()
	if err != nil || info.Mode().Perm() != 0o700 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || !os.SameFile(s.workID, info) {
		return ErrUnsafe
	}
	return linuxSQLiteEntry(s.parent, s.workName, s.workID, true)
}

func linuxSQLiteEntry(dir *os.File, name string, expected os.FileInfo, directory bool) error {
	if expected == nil {
		return ErrUnsafe
	}
	var st unix.Stat_t
	if unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return ErrUnsafe
	}
	original, ok := expected.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrUnsafe
	}
	kind := uint32(unix.S_IFREG)
	if directory {
		kind = unix.S_IFDIR
	}
	if st.Dev != original.Dev || st.Ino != original.Ino || st.Mode&unix.S_IFMT != kind || !directory && st.Nlink != 1 {
		return ErrUnsafe
	}
	return nil
}

func (s *linuxSQLiteStaging) entries() ([]os.DirEntry, error) {
	fd, err := unix.Openat(int(s.work.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "sqlite-workspace-list")
	entries, readErr := f.ReadDir(5)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
		return nil, ErrUnavailable
	}
	if len(entries) > 4 {
		return nil, ErrUnsafe
	}
	return entries, nil
}

func (s *linuxSQLiteStaging) inspect(maxDatabase, maxWorkspace int64, sealed bool) error {
	if s.main == nil || s.mainID == nil {
		return ErrUnsafe
	}
	if err := s.verifyDirectories(); err != nil {
		return err
	}
	if err := validateFile(s.main); err != nil {
		return err
	}
	if err := linuxSQLiteEntry(s.work, "snapshot.db", s.mainID, false); err != nil {
		return err
	}
	mainInfo, err := s.main.Stat()
	if err != nil || !os.SameFile(s.mainID, mainInfo) {
		return ErrUnsafe
	}
	if mainInfo.Size() < 0 || mainInfo.Size() > maxDatabase || sealed && mainInfo.Size() == 0 {
		return ErrLimit
	}
	entries, err := s.entries()
	if err != nil {
		return err
	}
	var total int64
	var foundMain, foundSidecar bool
	for _, entry := range entries {
		name := entry.Name()
		if name == "snapshot.db" {
			foundMain = true
			if mainInfo.Size() > maxWorkspace-total {
				return ErrLimit
			}
			total += mainInfo.Size()
			continue
		}
		if name != "snapshot.db-journal" && name != "snapshot.db-wal" && name != "snapshot.db-shm" {
			return ErrUnsafe
		}
		foundSidecar = true
		info, err := s.observeSidecar(name)
		if err != nil {
			return err
		}
		if info.Size < 0 || info.Size > maxWorkspace-total {
			return ErrLimit
		}
		total += info.Size
	}
	if !foundMain {
		return ErrUnsafe
	}
	if sealed && foundSidecar {
		return ErrIncomplete
	}
	// SQLite DELETE journals may legitimately be recreated. Retire a previous
	// generation only after this complete successful inspection observed its
	// absence. A different inode without such an observation is still rejected.
	for name := range s.sidecars {
		present := false
		for _, entry := range entries {
			if entry.Name() == name {
				present = true
				break
			}
		}
		if !present {
			delete(s.sidecars, name)
		}
	}
	return nil
}

func (s *linuxSQLiteStaging) observeSidecar(name string) (unix.Stat_t, error) {
	// Never open and close an auxiliary fd to a live SQLite file: closing any
	// same-inode fd can release this process's SQLite POSIX locks. Metadata-only
	// fstatat also avoids interfering with shared-memory sidecar lock ownership.
	var info, directory unix.Stat_t
	if unix.Fstatat(int(s.work.Fd()), name, &info, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(int(s.work.Fd()), &directory) != nil {
		return unix.Stat_t{}, ErrUnavailable
	}
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Nlink != 1 || info.Dev != directory.Dev {
		return unix.Stat_t{}, ErrUnsafe
	}
	if info.Uid != 0 && int64(info.Uid) != int64(os.Geteuid()) || info.Mode&0o7777 != 0o600 && info.Mode&0o7777 != 0o400 {
		return unix.Stat_t{}, ErrPermissions
	}
	if old, ok := s.sidecars[name]; ok && (old.Dev != info.Dev || old.Ino != info.Ino) {
		return unix.Stat_t{}, ErrUnsafe
	}
	s.sidecars[name] = info
	return info, nil
}

func (s *linuxSQLiteStaging) seal() (*os.File, error) {
	if s.main == nil || s.main.Sync() != nil {
		return nil, ErrUnavailable
	}
	if _, err := s.main.Seek(0, io.SeekStart); err != nil {
		return nil, ErrUnavailable
	}
	return s.main, nil
}

func (s *linuxSQLiteStaging) cleanup() (finalErr error) {
	if s.closed {
		return nil
	}
	s.closed = true
	defer func() {
		for _, f := range []*os.File{s.main, s.work, s.parent} {
			if f != nil {
				if err := f.Close(); finalErr == nil && err != nil {
					finalErr = ErrUnavailable
				}
			}
		}
		s.main, s.work, s.parent = nil, nil, nil
	}()
	if s.work == nil {
		return nil
	}
	if s.main != nil {
		// Unknown entries, changed identities, or changed ancestors are never
		// guessed away. Leave a private orphan instead of deleting by a new name.
		if err := s.inspect(MaxBytes, MaxSQLiteWorkspaceBytes, false); err != nil {
			return err
		}
		for name, id := range s.sidecars {
			var st unix.Stat_t
			if err := unix.Fstatat(int(s.work.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
				continue
			} else if err != nil {
				return ErrUnavailable
			}
			if st.Dev != id.Dev || st.Ino != id.Ino || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
				return ErrUnsafe
			}
			if err := unix.Unlinkat(int(s.work.Fd()), name, 0); err != nil {
				return ErrUnavailable
			}
		}
		if err := removeTemp(s.work, s.main, "snapshot.db"); err != nil {
			return err
		}
	}
	if err := s.verifyDirectories(); err != nil {
		return err
	}
	if s.work.Sync() != nil {
		return ErrUnavailable
	}
	if err := unix.Unlinkat(int(s.parent.Fd()), s.workName, unix.AT_REMOVEDIR); err != nil {
		return ErrUnavailable
	}
	if s.parent.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
