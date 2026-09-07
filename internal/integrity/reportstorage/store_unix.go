//go:build !windows

package reportstorage

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafe
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		return nil, ErrUnsafe
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && i == len(parts)-1 {
			if e := unix.Mkdirat(fd, part, 0700); e != nil && !errors.Is(e, unix.EEXIST) {
				_ = unix.Close(fd)
				return nil, ErrUnavailable
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		_ = unix.Close(fd)
		if err != nil {
			return nil, ErrUnsafe
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "report-directory"), nil
}
func validateHandle(file *os.File, directory bool) error {
	if file == nil {
		return ErrUnsafe
	}
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil {
		return ErrUnavailable
	}
	if int64(stat.Uid) != int64(os.Geteuid()) && stat.Uid != 0 {
		return ErrUnsafe
	}
	if directory {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Mode&077 != 0 {
			return ErrUnsafe
		}
	} else {
		if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0177 != 0 || stat.Nlink != 1 {
			return ErrUnsafe
		}
	}
	return nil
}
func syncDirectory(file *os.File) error { return file.Sync() }

func openArtifact(directory *os.File, name string) (*os.File, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	return os.NewFile(uintptr(fd), "report-artifact"), nil
}
