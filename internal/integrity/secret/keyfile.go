package secret

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
)

var (
	ErrKeyFileInvalid     = errors.New("MI_KEYFILE_INVALID")
	ErrKeyFileUnsafe      = errors.New("MI_KEYFILE_UNSAFE_PATH")
	ErrKeyFilePermissions = errors.New("MI_KEYFILE_PERMISSIONS")
	ErrKeyFileExists      = errors.New("MI_KEYFILE_ALREADY_EXISTS")
)

// LoadKeyFile loads exactly 32 raw bytes from a restricted regular file and
// derives purpose-separated keys. The version is validated configuration, not
// plaintext metadata stored alongside the key. Hex/base64 text and newlines are
// intentionally not accepted. Errors never include the path, OS error or bytes.
// Unix accepts owner/root-owned 0400/0600 files; Windows accepts only the current
// user, SYSTEM and trusted local Administrators as data/control-capable trustees.
// Administrators/root are trusted host operators and cannot be excluded by ACLs.
func LoadKeyFile(path, version string) (*KeyRing, error) {
	if !versionPattern.MatchString(version) {
		return nil, ErrKeyFileInvalid
	}
	file, err := openRestrictedKeyFile(path, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if err := validateKeyHandle(file); err != nil {
		return nil, err
	}
	master := make([]byte, 33)
	defer clear(master)
	n, err := io.ReadFull(file, master)
	if n != 32 || !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, ErrKeyFileInvalid
	}
	if err := validateKeyHandle(file); err != nil {
		return nil, err
	}
	return NewKeyRing(version, map[string][]byte{version: master[:32]})
}

// CreateKeyFile atomically creates a new restricted regular file and never
// opens or overwrites an existing name. OS permissions are applied before any
// random key bytes are written. Parent directories must already exist. A failed
// write can leave a protected incomplete file; it is not silently removed or
// overwritten, avoiding deletion races and accidental loss of a user's master.
func CreateKeyFile(path, version string) (*KeyRing, error) {
	if !versionPattern.MatchString(version) {
		return nil, ErrKeyFileInvalid
	}
	file, err := openRestrictedKeyFile(path, true)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	if err := validateKeyHandle(file); err != nil {
		return nil, err
	}
	master := make([]byte, 32)
	defer clear(master)
	if _, err := rand.Read(master); err != nil {
		return nil, ErrUnavailable
	}
	if n, err := file.Write(master); err != nil || n != len(master) {
		return nil, ErrUnavailable
	}
	if err := file.Sync(); err != nil {
		return nil, ErrUnavailable
	}
	if err := validateKeyHandle(file); err != nil {
		return nil, err
	}
	return NewKeyRing(version, map[string][]byte{version: master})
}

func regularKeyFile(file *os.File) error {
	info, err := file.Stat()
	if err != nil {
		return ErrUnavailable
	}
	if !info.Mode().IsRegular() {
		return ErrKeyFileUnsafe
	}
	return nil
}
