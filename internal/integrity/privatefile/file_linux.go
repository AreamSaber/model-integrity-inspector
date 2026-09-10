//go:build linux

package privatefile

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

func validatePath(path string) error {
	if strings.HasPrefix(path, "//") || strings.Contains(path, "\\") {
		return ErrUnsafe
	}
	return nil
}

func openDirectory(path string) (*os.File, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if part == "" {
			continue
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, ErrUnsafe
		}
		fd = next
	}
	f := os.NewFile(uintptr(fd), "private-directory")
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	if err := validateDirectory(f); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

func validateDirectory(f *os.File) error {
	if err := validateLocalFilesystem(int(f.Fd())); err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafe
	}
	if st.Mode&0o077 != 0 || int64(st.Uid) != int64(os.Geteuid()) && st.Uid != 0 {
		return ErrPermissions
	}
	return nil
}

func openInput(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(fd), "private-input"), nil
}

func createTemp(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrUnavailable
	}
	// Creation is already restrictive even with a restrictive umask. Do not
	// broaden it later; validateFile accepts owner-read/write or owner-read only.
	return os.NewFile(uintptr(fd), "private-output"), nil
}

func validateFile(f *os.File) error {
	if err := validateLocalFilesystem(int(f.Fd())); err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Fstat(int(f.Fd()), &st) != nil {
		return ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return ErrUnsafe
	}
	if int64(st.Uid) != int64(os.Geteuid()) && st.Uid != 0 || st.Mode&0o7777 != 0o400 && st.Mode&0o7777 != 0o600 {
		return ErrPermissions
	}
	return nil
}

func validateLocalFilesystem(fd int) error {
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil {
		return ErrUnavailable
	}
	if !supportedFilesystem(fs.Type) {
		return ErrFilesystem
	}
	return nil
}

// Overlay and FUSE are deliberately not accepted: this boundary cannot inspect
// their backing stores. This is a local filesystem policy, not a network sandbox.
func supportedFilesystem(kind int64) bool {
	switch kind {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC, unix.F2FS_SUPER_MAGIC:
		return true
	default:
		return false
	}
}

func sameTemp(dir, f *os.File, name string) bool {
	var handle, entry unix.Stat_t
	if unix.Fstat(int(f.Fd()), &handle) != nil || unix.Fstatat(int(dir.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return handle.Dev == entry.Dev && handle.Ino == entry.Ino && entry.Mode&unix.S_IFMT == unix.S_IFREG && entry.Nlink == 1
}

func removeTemp(dir, f *os.File, name string) error {
	if !sameTemp(dir, f, name) {
		return ErrUnsafe
	}
	if unix.Unlinkat(int(dir.Fd()), name, 0) != nil {
		return ErrUnavailable
	}
	return nil
}

func publish(dir, f *os.File, temp, name string) error {
	if !sameTemp(dir, f, temp) {
		return ErrUnsafe
	}
	err := unix.Renameat2(int(dir.Fd()), temp, int(dir.Fd()), name, unix.RENAME_NOREPLACE)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, unix.EEXIST):
		return ErrExists
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.EINVAL):
		return ErrFilesystem
	default:
		return ErrUnavailable
	}
}

func syncDirectory(dir *os.File) error {
	if dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
