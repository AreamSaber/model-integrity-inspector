//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package secret

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openRestrictedKeyFile(path string, create bool) (*os.File, error) {
	if path == "" || strings.ContainsRune(path, 0) {
		return nil, ErrKeyFileUnsafe
	}
	absolute, err := filepath.Abs(path)
	if err != nil || absolute == "/" {
		return nil, ErrKeyFileUnsafe
	}
	components := strings.Split(strings.TrimPrefix(absolute, "/"), "/")
	directory, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = unix.Close(directory) }()
	// Resolve each directory relative to an already-open directory descriptor;
	// O_NOFOLLOW applies to every component, not merely the final basename.
	for _, component := range components[:len(components)-1] {
		next, err := unix.Openat(directory, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrKeyFileUnsafe
		}
		_ = unix.Close(directory)
		directory = next
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	if create {
		flags = unix.O_RDWR | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	}
	descriptor, err := unix.Openat(directory, components[len(components)-1], flags, 0o600)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrKeyFileExists
		}
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EISDIR) {
			return nil, ErrKeyFileUnsafe
		}
		if errors.Is(err, unix.EACCES) {
			return nil, ErrKeyFilePermissions
		}
		return nil, ErrUnavailable
	}
	file := os.NewFile(uintptr(descriptor), "master-key")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrUnavailable
	}
	if create {
		if err := unix.Fchmod(descriptor, 0o600); err != nil {
			_ = file.Close()
			return nil, ErrKeyFilePermissions
		}
	}
	return file, nil
}

func validateKeyHandle(file *os.File) error {
	if err := regularKeyFile(file); err != nil {
		return err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		return ErrUnavailable
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Nlink != 1 {
		return ErrKeyFileUnsafe
	}
	if int64(stat.Uid) != int64(os.Geteuid()) && stat.Uid != 0 {
		return ErrKeyFilePermissions
	}
	mode := stat.Mode & 0o7777
	if mode != 0o400 && mode != 0o600 {
		return ErrKeyFilePermissions
	}
	return nil
}
