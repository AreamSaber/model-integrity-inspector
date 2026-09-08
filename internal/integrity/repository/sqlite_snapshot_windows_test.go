//go:build windows

package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
)

const snapshotWindowsFixturePrefix = ".mii-snapshot-test-"

var errSnapshotWindowsFixture = errors.New("snapshot Windows fixture failed")

type snapshotWindowsFileID struct {
	volume, high, low uint32
}

type snapshotWindowsFixture struct {
	profile        *os.File
	profilePath    string
	profileID      snapshotWindowsFileID
	child          *os.File
	name           string
	path           string
	id             snapshotWindowsFileID
	created        bool
	idKnown        bool
	childCanDelete bool
}

// The default Windows Temp may have writable ancestors. Create only a new
// profile child with a private inheritable DACL, then use the real production
// staging boundary to admit it before any test database is created there.
func snapshotPrivateTestDir(t *testing.T) string {
	t.Helper()
	f := &snapshotWindowsFixture{}
	ready := false
	defer func() {
		if !ready {
			if err := f.abort(); err != nil {
				t.Error("snapshot fixture stage=failed_setup_cleanup")
			}
		}
	}()
	profile, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("snapshot fixture stage=profile")
	}
	f.profilePath = profile
	f.profile, err = snapshotWindowsOpenProfile(profile)
	if err != nil {
		t.Fatal("snapshot fixture stage=profile_handle")
	}
	f.profileID, err = snapshotWindowsDirectoryID(f.profile, profile)
	if err != nil {
		t.Fatal("snapshot fixture stage=profile_identity")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("snapshot fixture stage=nonce")
	}
	f.name = snapshotWindowsFixturePrefix + hex.EncodeToString(nonce[:])
	f.path = filepath.Join(profile, f.name)
	f.child, err = snapshotWindowsOpenDirectory(windows.Handle(f.profile.Fd()), f.name, true, true)
	if err != nil {
		t.Fatal("snapshot fixture stage=private_create")
	}
	f.created, f.childCanDelete = true, true
	f.id, err = snapshotWindowsDirectoryID(f.child, f.path)
	if err != nil {
		t.Fatal("snapshot fixture stage=created_identity")
	}
	f.idKnown = true
	// Production's ancestor handles deliberately do not share DELETE. Release
	// the creator's DELETE access, then reacquire and identify a READ guard.
	closeErr := f.child.Close()
	f.child, f.childCanDelete = nil, false
	if closeErr != nil {
		t.Fatal("snapshot fixture stage=creator_close")
	}
	f.child, err = snapshotWindowsOpenDirectory(windows.Handle(f.profile.Fd()), f.name, false, false)
	if err != nil || f.check() != nil {
		t.Fatal("snapshot fixture stage=read_guard")
	}
	if !snapshotWindowsAdmission(f.path) || f.check() != nil {
		t.Fatal("snapshot fixture stage=production_admission")
	}
	t.Cleanup(func() {
		if err := f.cleanup(); err != nil {
			t.Error("snapshot fixture stage=owned_cleanup")
		}
	})
	ready = true
	return f.path
}

func snapshotWindowsOpenProfile(path string) (_ *os.File, finalErr error) {
	volume := filepath.VolumeName(path)
	if !utf8.ValidString(path) || len(path) < 4 || len(path) > 4096 || !filepath.IsAbs(path) ||
		filepath.Clean(path) != path || len(volume) != 2 || volume[1] != ':' || path[2] != '\\' ||
		strings.ContainsAny(path[2:], ":/") {
		return nil, errSnapshotWindowsFixture
	}
	rootPath := volume + `\`
	encoded, err := windows.UTF16PtrFromString(rootPath)
	if err != nil || windows.GetDriveType(encoded) != windows.DRIVE_FIXED {
		return nil, errSnapshotWindowsFixture
	}
	handle, err := windows.CreateFile(encoded, windows.FILE_GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, errSnapshotWindowsFixture
	}
	root := os.NewFile(uintptr(handle), "snapshot-fixture-volume")
	if root == nil {
		_ = windows.CloseHandle(handle)
		return nil, errSnapshotWindowsFixture
	}
	defer func() {
		if err := root.Close(); err != nil {
			finalErr = errSnapshotWindowsFixture
		}
	}()
	if _, err := snapshotWindowsDirectoryID(root, rootPath); err != nil {
		return nil, err
	}
	// OBJ_DONT_REPARSE rejects a reparse point in any component of this
	// root-relative walk. Canonical identity is checked before child creation.
	profile, err := snapshotWindowsOpenDirectory(handle, path[3:], false, false)
	if err != nil {
		return nil, err
	}
	if _, err := snapshotWindowsDirectoryID(profile, path); err != nil {
		_ = profile.Close()
		return nil, err
	}
	return profile, nil
}

func snapshotWindowsOpenDirectory(root windows.Handle, name string, create, deleteAccess bool) (*os.File, error) {
	nativeName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, errSnapshotWindowsFixture
	}
	attrs := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: root, ObjectName: nativeName,
		Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	access := uint32(windows.FILE_GENERIC_READ)
	if deleteAccess {
		access |= windows.DELETE
	}
	disposition := uint32(windows.FILE_OPEN)
	if create {
		user, err := windows.GetCurrentProcessToken().GetTokenUser()
		if err != nil {
			return nil, errSnapshotWindowsFixture
		}
		security, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)")
		if err != nil {
			return nil, errSnapshotWindowsFixture
		}
		attrs.SecurityDescriptor = security
		disposition = windows.FILE_CREATE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, disposition,
		windows.FILE_DIRECTORY_FILE|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	runtime.KeepAlive(attrs)
	if err != nil {
		return nil, errSnapshotWindowsFixture
	}
	f := os.NewFile(uintptr(handle), "snapshot-test-owned-directory")
	if f == nil {
		_ = windows.CloseHandle(handle)
		return nil, errSnapshotWindowsFixture
	}
	return f, nil
}

func snapshotWindowsDirectoryID(f *os.File, path string) (snapshotWindowsFileID, error) {
	var info windows.ByHandleFileInformation
	if f == nil || windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) != nil ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return snapshotWindowsFileID{}, errSnapshotWindowsFixture
	}
	var filesystem [32]uint16
	var flags uint32
	if windows.GetVolumeInformationByHandle(windows.Handle(f.Fd()), nil, 0, nil, nil, &flags,
		&filesystem[0], uint32(len(filesystem))) != nil || windows.UTF16ToString(filesystem[:]) != "NTFS" || flags&0x8 == 0 {
		return snapshotWindowsFileID{}, errSnapshotWindowsFixture
	}
	var canonical [4096]uint16
	n, err := windows.GetFinalPathNameByHandle(windows.Handle(f.Fd()), &canonical[0], uint32(len(canonical)), 0)
	if err != nil || n == 0 || n >= uint32(len(canonical)) ||
		!strings.EqualFold(windows.UTF16ToString(canonical[:n]), `\\?\`+path) {
		return snapshotWindowsFileID{}, errSnapshotWindowsFixture
	}
	return snapshotWindowsFileID{info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow}, nil
}

// No SQLite connection is opened. The synchronous build callback intentionally
// fails after production has checked its entire native ancestor/ACL boundary.
// A fresh context also works during t.Cleanup, when t.Context is already done.
func snapshotWindowsAdmission(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var built, consumed bool
	intentional := errors.New("intentional snapshot fixture admission abort")
	receipt, err := privatefile.WithSQLiteStaging(ctx, path,
		privatefile.SQLiteLimits{MaxDatabaseBytes: 1, MaxWorkspaceBytes: 2, Timeout: 5 * time.Second},
		func(context.Context, *privatefile.SQLiteTarget) error {
			built = true
			return intentional
		}, func(context.Context, io.Reader) error {
			consumed = true
			return intentional
		})
	return built && !consumed && errors.Is(err, privatefile.ErrCallback) && receipt == (privatefile.Receipt{})
}

func (f *snapshotWindowsFixture) check() error {
	if !f.created || !f.idKnown || !filepath.IsAbs(f.path) || filepath.Clean(f.path) != f.path ||
		filepath.Dir(f.path) != f.profilePath || filepath.Base(f.path) != f.name ||
		!strings.HasPrefix(f.name, snapshotWindowsFixturePrefix) || len(f.name) != len(snapshotWindowsFixturePrefix)+32 {
		return errSnapshotWindowsFixture
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(f.name, snapshotWindowsFixturePrefix)); err != nil {
		return errSnapshotWindowsFixture
	}
	profileID, err := snapshotWindowsDirectoryID(f.profile, f.profilePath)
	if err != nil || profileID != f.profileID {
		return errSnapshotWindowsFixture
	}
	id, err := snapshotWindowsDirectoryID(f.child, f.path)
	if err != nil || id != f.id {
		return errSnapshotWindowsFixture
	}
	return nil
}

func (f *snapshotWindowsFixture) close() error {
	var result error
	if f.child != nil {
		if f.child.Close() != nil {
			result = errSnapshotWindowsFixture
		}
		f.child = nil
	}
	if f.profile != nil {
		if f.profile.Close() != nil {
			result = errSnapshotWindowsFixture
		}
		f.profile = nil
	}
	return result
}

func (f *snapshotWindowsFixture) cleanup() (finalErr error) {
	defer func() {
		if err := f.close(); finalErr == nil && err != nil {
			finalErr = err
		}
	}()
	if f.check() != nil || !snapshotWindowsAdmission(f.path) || f.check() != nil {
		return errSnapshotWindowsFixture
	}
	closeErr := f.child.Close()
	f.child = nil
	if closeErr != nil {
		return errSnapshotWindowsFixture
	}
	// This exact random root, its original native identity, its absolute scope,
	// and the production ancestor/ACL admission were verified immediately above.
	// The profile remains pinned. Only this test's own source/snapshot files are
	// recursively reclaimed; a malicious same-SID owner is not a sandbox target.
	if err := os.RemoveAll(f.path); err != nil {
		return errSnapshotWindowsFixture
	}
	return nil
}

func (f *snapshotWindowsFixture) abort() (finalErr error) {
	defer func() {
		if err := f.close(); finalErr == nil && err != nil {
			finalErr = err
		}
	}()
	if !f.created {
		return nil
	}
	if !f.childCanDelete {
		if f.child != nil {
			closeErr := f.child.Close()
			f.child = nil
			if closeErr != nil {
				return errSnapshotWindowsFixture
			}
		}
		if !f.idKnown || f.profile == nil {
			return errSnapshotWindowsFixture
		}
		var err error
		f.child, err = snapshotWindowsOpenDirectory(windows.Handle(f.profile.Fd()), f.name, false, true)
		if err != nil || f.check() != nil {
			return errSnapshotWindowsFixture
		}
	}
	// Failed admission has not authorized recursive cleanup. Delete only the
	// exact created/reidentified empty directory handle; orphans remain on error.
	var status windows.IO_STATUS_BLOCK
	deleteDirectory := byte(1)
	if windows.NtSetInformationFile(windows.Handle(f.child.Fd()), &status, &deleteDirectory, 1, 13) != nil {
		return errSnapshotWindowsFixture
	}
	return nil
}
