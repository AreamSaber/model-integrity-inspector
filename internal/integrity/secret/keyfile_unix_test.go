//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package secret

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKeyFileUnixModes(t *testing.T) {
	for _, mode := range []os.FileMode{0o400, 0o600, 0o644, 0o640, 0o660, 0o700, 0o777} {
		path := filepath.Join(t.TempDir(), "master.key")
		if _, err := CreateKeyFile(path, "v1"); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := LoadKeyFile(path, "v1")
		if mode == 0o400 || mode == 0o600 {
			if err != nil {
				t.Fatal(err)
			}
		} else if !errors.Is(err, ErrKeyFilePermissions) {
			t.Fatal("overpermissive Unix key accepted")
		}
	}
}

func TestKeyFileUnixFIFORejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipe")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path, "v1"); !errors.Is(err, ErrKeyFileUnsafe) {
		t.Fatal("FIFO accepted")
	}
}

func TestKeyFileUnixOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("wrong-owner fixture needs root in isolated CI")
	}
	path := filepath.Join(t.TempDir(), "master.key")
	if _, err := CreateKeyFile(path, "v1"); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyFile(path, "v1"); !errors.Is(err, ErrKeyFilePermissions) {
		t.Fatal("untrusted Unix owner accepted")
	}
}
