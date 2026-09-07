//go:build linux

package localfile

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

func openDirectory(path string, private bool) (*os.File, error) {
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
	f := os.NewFile(uintptr(fd), "replay-local-directory")
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	if err := validateLocalFilesystem(fd); err != nil {
		_ = f.Close()
		return nil, err
	}
	if private {
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o077 != 0 || (int64(st.Uid) != int64(os.Geteuid()) && st.Uid != 0) {
			_ = f.Close()
			return nil, ErrPermissions
		}
	}
	return f, nil
}

func openInput(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(fd), "replay-local-input")
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	return f, nil
}

func createTemp(dir *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := unix.Fchmod(fd, 0o600); err != nil {
		_ = unix.Close(fd)
		_ = unix.Unlinkat(int(dir.Fd()), name, 0)
		return nil, ErrPermissions
	}
	f := os.NewFile(uintptr(fd), "replay-local-output")
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrUnavailable
	}
	return f, nil
}

func validateFile(f *os.File) error {
	if err := validateLocalFilesystem(int(f.Fd())); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return ErrUnavailable
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		return ErrUnsafe
	}
	if int64(st.Uid) != int64(os.Geteuid()) && st.Uid != 0 {
		return ErrPermissions
	}
	if st.Mode&0o7777 != 0o400 && st.Mode&0o7777 != 0o600 {
		return ErrPermissions
	}
	return nil
}

// A filesystem magic allowlist is only a conservative input policy, not an OS
// network-denial proof (overlay may itself have backing configuration). Unknown
// types, NFS/CIFS/9P/FUSE and pseudo-filesystems fail closed.
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

func supportedFilesystem(kind int64) bool {
	switch kind {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC, unix.RAMFS_MAGIC, unix.F2FS_SUPER_MAGIC:
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
	return handle.Dev == entry.Dev && handle.Ino == entry.Ino && entry.Mode&unix.S_IFMT == unix.S_IFREG
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
	if err := unix.Linkat(int(dir.Fd()), temp, int(dir.Fd()), name, 0); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrExists
		}
		return ErrUnavailable
	}
	// The final file is already complete. A cleanup failure never unlinks it.
	return removeTemp(dir, f, temp)
}

func syncDirectory(dir *os.File) error {
	if dir.Sync() != nil {
		return ErrUnavailable
	}
	return nil
}
