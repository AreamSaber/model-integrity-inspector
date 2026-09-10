//go:build windows

package privatefile

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// The default Windows Temp may grant other users namespace mutation rights.
// This test-only fixture creates a private directory below the profile after
// validating the profile as an ancestor, not as the private child. It never
// repairs an existing ACL or moves production data.
func newSQLiteTestDirectory(t *testing.T) string {
	t.Helper()
	profile, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("SQLite fixture stage=profile")
	}
	return newSQLiteTestDirectoryBelow(t, profile)
}

func newSQLiteTestDirectoryBelow(t *testing.T, profile string) string {
	t.Helper()
	s := &sqliteWindowsStaging{}
	defer func() {
		if err := s.cleanup(); err != nil {
			t.Error("SQLite fixture stage=profile_close", err)
		}
	}()
	if _, _, err := splitPath(profile); err != nil {
		t.Fatal("SQLite fixture stage=profile_path", err)
	}
	if err := openSQLiteTestProfileAncestors(s, profile); err != nil {
		logSQLiteProfileAncestryFailure(t, s, profile, false, err)
		t.Fatal("SQLite fixture stage=profile_ancestry", err)
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal("SQLite fixture stage=nonce")
	}
	name := ".mii-sqlite-test-" + hex.EncodeToString(nonce[:])
	f, err := sqliteWindowsOpen(windows.Handle(s.parent().file.Fd()), name,
		sqliteWindowsOpenOptions{directory: true, create: true, delete: true,
			share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
	if err != nil {
		t.Fatal("SQLite fixture stage=create", err)
	}
	path := filepath.Join(profile, name)
	id, err := sqliteWindowsFileID(f)
	if err != nil {
		_ = removeTemp(nil, f, "")
		_ = f.Close()
		t.Fatal("SQLite fixture stage=created_identity")
	}
	t.Cleanup(func() { sqliteWindowsCleanupTestDirectory(t, profile, name, id) })
	checkErr := sqliteWindowsCheckDirectory(f, path, true)
	if checkErr == nil {
		checkErr = revalidateSQLiteTestProfileAncestors(s, profile)
	}
	closeErr := f.Close()
	if checkErr != nil || closeErr != nil {
		t.Fatal("SQLite fixture stage=created_check")
	}
	return path
}

func sqliteWindowsCleanupTestDirectory(t *testing.T, profile, name string, id sqliteWindowsIdentity) {
	t.Helper()
	const prefix = ".mii-sqlite-test-"
	path := filepath.Join(profile, name)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) != profile ||
		!strings.HasPrefix(name, prefix) || len(name) != len(prefix)+32 {
		t.Error("SQLite fixture stage=cleanup_scope")
		return
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(name, prefix)); err != nil {
		t.Error("SQLite fixture stage=cleanup_name")
		return
	}
	s := &sqliteWindowsStaging{}
	defer func() {
		if err := s.cleanup(); err != nil {
			t.Error("SQLite fixture stage=cleanup_chain_close", err)
		}
	}()
	if err := openSQLiteTestProfileAncestors(s, profile); err != nil {
		t.Error("SQLite fixture stage=cleanup_ancestry", err)
		return
	}
	f, err := sqliteWindowsOpen(windows.Handle(s.parent().file.Fd()), name,
		sqliteWindowsOpenOptions{directory: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
	if err != nil {
		t.Error("SQLite fixture stage=cleanup_root_open", err)
		return
	}
	checkErr := sqliteWindowsMatches(f, id)
	if checkErr == nil {
		checkErr = sqliteWindowsCheckDirectory(f, path, true)
	}
	closeErr := f.Close()
	if checkErr != nil || closeErr != nil {
		t.Error("SQLite fixture stage=cleanup_root_identity")
		return
	}
	// Only this invocation's validated random child is recursive cleanup scope.
	// Keep every verified ancestor pinned through the operation. Only the
	// random owned child is required to satisfy the strict private policy.
	if err := revalidateSQLiteTestProfileAncestors(s, profile); err != nil {
		t.Error("SQLite fixture stage=cleanup_ancestry_recheck")
		return
	}
	if err := os.RemoveAll(path); err != nil {
		t.Error("SQLite fixture stage=owned_cleanup")
	}
}

func openSQLiteTestProfileAncestors(stage *sqliteWindowsStaging, profile string) error {
	if stage == nil || stage.closed || len(stage.chain) != 0 {
		return ErrUnsafe
	}
	if _, _, err := splitPath(profile); err != nil {
		return err
	}
	if len(strings.Split(profile[3:], `\`)) > 256 {
		return ErrLimit
	}
	rootPath := filepath.VolumeName(profile) + `\`
	rootName, err := windows.UTF16PtrFromString(rootPath)
	if err != nil {
		return ErrUnsafe
	}
	handle, err := windows.CreateFile(rootName, windows.FILE_GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ErrUnavailable
	}
	root := os.NewFile(uintptr(handle), "test-sqlite-ancestor")
	if root == nil {
		_ = windows.CloseHandle(handle)
		return ErrUnavailable
	}
	stage.chain = append(stage.chain, sqliteWindowsDirectory{file: root, path: rootPath})
	for index := 0; ; index++ {
		entry := &stage.chain[index]
		entry.id, err = sqliteWindowsFileID(entry.file)
		if err != nil {
			return err
		}
		// Including the final profile: it will contain a newly private child,
		// and is not itself the production private staging parent.
		if err := sqliteWindowsCheckDirectory(entry.file, entry.path, false); err != nil {
			return err
		}
		if strings.EqualFold(entry.path, profile) {
			return revalidateSQLiteTestProfileAncestors(stage, profile)
		}
		relative := strings.TrimPrefix(profile[len(entry.path):], `\`)
		name, _, _ := strings.Cut(relative, `\`)
		if name == "" {
			return ErrUnsafe
		}
		next, err := sqliteWindowsOpen(windows.Handle(entry.file.Fd()), name,
			sqliteWindowsOpenOptions{directory: true, share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE})
		if err != nil {
			return err
		}
		stage.chain = append(stage.chain, sqliteWindowsDirectory{file: next, path: filepath.Join(entry.path, name)})
	}
}

func revalidateSQLiteTestProfileAncestors(stage *sqliteWindowsStaging, profile string) error {
	if stage == nil || stage.closed || len(stage.chain) == 0 || len(stage.chain) > 257 ||
		!strings.EqualFold(stage.parent().path, profile) {
		return ErrUnsafe
	}
	for _, entry := range stage.chain {
		if entry.file == nil {
			return ErrUnsafe
		}
		if err := sqliteWindowsMatches(entry.file, entry.id); err != nil {
			return err
		}
		if err := sqliteWindowsCheckDirectory(entry.file, entry.path, false); err != nil {
			return err
		}
	}
	return nil
}

func sqliteWindowsTestStage(t *testing.T, parent string) *sqliteWindowsStaging {
	t.Helper()
	native, err := newSQLiteStaging(parent)
	if err != nil {
		t.Fatal("SQLite native stage=create", err)
	}
	s, ok := native.(*sqliteWindowsStaging)
	if !ok {
		t.Fatal("SQLite native stage=type")
	}
	t.Cleanup(func() { _ = s.cleanup() })
	return s
}

// Capture identity eagerly from a live native metadata handle. os.FileInfo on
// Windows may otherwise defer a file-ID lookup until after this path is reused.
func sqliteTestSidecarID(t *testing.T, target *SQLiteTarget, name string) [3]uint64 {
	t.Helper()
	if target == nil || target.state == nil {
		t.Fatal("SQLite sidecar fixture stage=target")
	}
	target.state.mu.Lock()
	defer target.state.mu.Unlock()
	s, ok := target.state.native.(*sqliteWindowsStaging)
	if !ok || s.closed || s.work == nil {
		t.Fatal("SQLite sidecar fixture stage=native")
	}
	switch name {
	case sqliteWindowsMain + "-journal", sqliteWindowsMain + "-wal", sqliteWindowsMain + "-shm":
	default:
		t.Fatal("SQLite sidecar fixture stage=closed_name")
	}
	f, err := sqliteWindowsOpen(windows.Handle(s.work.Fd()), name,
		sqliteWindowsOpenOptions{metadata: true,
			share: windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE})
	if err != nil {
		t.Fatal("SQLite sidecar fixture stage=metadata_open")
	}
	id, identityErr := sqliteWindowsFileID(f)
	closeErr := f.Close()
	if identityErr != nil || closeErr != nil {
		t.Fatal("SQLite sidecar fixture stage=identity_close")
	}
	return [3]uint64{uint64(id.volume), uint64(id.high), uint64(id.low)}
}

// Only fixed filenames below newSQLiteTestDirectory are supplied by tests.
// Capture the original object identity before removing a test-owned pin.
func sqliteTestFileID(t *testing.T, path string) [3]uint64 {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("SQLite pin fixture stage=name")
	}
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		t.Fatal("SQLite pin fixture stage=metadata_open")
	}
	f := os.NewFile(uintptr(handle), "sqlite-test-owned-pin")
	if f == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("SQLite pin fixture stage=file")
	}
	validationErr := validateFile(f)
	id, identityErr := sqliteWindowsFileID(f)
	closeErr := f.Close()
	if validationErr != nil || identityErr != nil || closeErr != nil {
		t.Fatal("SQLite pin fixture stage=identity_close")
	}
	return [3]uint64{uint64(id.volume), uint64(id.high), uint64(id.low)}
}

// This opens only a synthetic regular file with the exact desired/share flags
// used by modernc's Windows main VFS. It does not invoke SQLite or create a DB.
func sqliteWindowsVFSHandle(t *testing.T, path string, write bool) *os.File {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal("SQLite native fixture stage=name")
	}
	access := uint32(windows.GENERIC_READ)
	if write {
		access |= windows.GENERIC_WRITE
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal("SQLite native fixture stage=vfs_open")
	}
	f := os.NewFile(uintptr(handle), "sqlite-vfs-synthetic-fixture")
	if f == nil {
		_ = windows.CloseHandle(handle)
		t.Fatal("SQLite native fixture stage=vfs_file")
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func sqliteWindowsSyntheticMain(t *testing.T, s *sqliteWindowsStaging, data []byte) {
	t.Helper()
	f := sqliteWindowsVFSHandle(t, s.databasePath(), true)
	if _, err := f.Write(data); err != nil {
		t.Fatal("SQLite native fixture stage=write")
	}
	if err := f.Close(); err != nil {
		t.Fatal("SQLite native fixture stage=close")
	}
}

func TestSQLiteWindowsNativeStageLifecycle(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	s := sqliteWindowsTestStage(t, parent)
	if err := s.inspect(128, 256, false); err != nil {
		t.Fatal("empty staging rejected", err)
	}
	if err := s.inspect(128, 256, true); !errors.Is(err, ErrLimit) {
		t.Fatal("empty sealed file accepted", err)
	}
	data := []byte("synthetic native bytes, not a SQLite database")
	f := sqliteWindowsVFSHandle(t, s.databasePath(), true)
	if _, err := f.Write(data); err != nil {
		t.Fatal("synthetic write failed")
	}
	if err := s.inspect(128, 256, false); err != nil {
		t.Fatal("inspection conflicted with VFS-compatible writer", err)
	}
	if err := os.Rename(s.databasePath(), s.databasePath()+"-moved"); err == nil {
		t.Fatal("main guard permitted rename")
	}
	if err := f.Close(); err != nil {
		t.Fatal("synthetic writer close failed")
	}
	sealed, err := s.seal()
	if err != nil {
		t.Fatal("seal failed", err)
	}
	if err := s.inspect(128, 256, true); err != nil {
		t.Fatal("sealed inspection failed", err)
	}
	if concurrent, err := os.Open(s.databasePath()); err == nil {
		_ = concurrent.Close()
		t.Fatal("sealed main admitted another reader")
	}
	got, err := io.ReadAll(sealed)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("sealed stream changed synthetic contents")
	}
	if err := s.cleanup(); err != nil {
		t.Fatal("cleanup failed", err)
	}
	if err := s.cleanup(); err != nil {
		t.Fatal("cleanup not idempotent", err)
	}
	if err := s.inspect(128, 256, true); !errors.Is(err, ErrClosed) || s.databasePath() != "" {
		t.Fatal("closed native capability remained usable")
	}
	assertEntries(t, parent, 0)
}

func TestSQLiteWindowsNativeSealRejectsLiveHandles(t *testing.T) {
	for _, write := range []bool{false, true} {
		name := "reader"
		if write {
			name = "writer"
		}
		t.Run(name, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			s := sqliteWindowsTestStage(t, parent)
			sqliteWindowsSyntheticMain(t, s, []byte("synthetic"))
			live := sqliteWindowsVFSHandle(t, s.databasePath(), write)
			if sealed, err := s.seal(); sealed != nil || !errors.Is(err, ErrUnavailable) {
				t.Fatal("live VFS-compatible handle did not prevent exclusive seal", err)
			}
			if err := live.Close(); err != nil {
				t.Fatal("live fixture close failed")
			}
			if err := s.cleanup(); err != nil {
				t.Fatal("cleanup after failed seal failed", err)
			}
			assertEntries(t, parent, 0)
		})
	}
}

func TestSQLiteWindowsNativeSidecarAccounting(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	s := sqliteWindowsTestStage(t, parent)
	sqliteWindowsSyntheticMain(t, s, bytes.Repeat([]byte{0x63}, 65))
	journal := filepath.Join(s.workspacePath(), sqliteWindowsMain+"-journal")
	if err := os.WriteFile(journal, bytes.Repeat([]byte{0x37}, 100), 0o600); err != nil {
		t.Fatal("synthetic journal creation failed")
	}
	live := sqliteWindowsVFSHandle(t, journal, true)
	if err := s.inspect(65, 165, false); err != nil {
		t.Fatal("metadata observation conflicted with live journal", err)
	}
	if err := s.inspect(64, 165, false); !errors.Is(err, ErrLimit) {
		t.Fatal("database-only budget ignored", err)
	}
	if err := s.inspect(65, 164, false); !errors.Is(err, ErrLimit) {
		t.Fatal("cumulative workspace budget ignored", err)
	}
	if err := s.inspect(65, 165, true); !errors.Is(err, ErrIncomplete) {
		t.Fatal("sidecar permitted at sealed boundary", err)
	}
	if err := live.Close(); err != nil {
		t.Fatal("synthetic journal close failed")
	}
	if err := os.Remove(journal); err != nil {
		t.Fatal("synthetic journal consolidation failed")
	}
	if err := s.inspect(65, 165, true); err != nil {
		t.Fatal("consolidated synthetic main rejected", err)
	}
	if _, err := s.seal(); err != nil {
		t.Fatal("consolidated seal failed", err)
	}
	if err := s.cleanup(); err != nil {
		t.Fatal("consolidated cleanup failed", err)
	}
	assertEntries(t, parent, 0)
}

func TestSQLiteWindowsNativeSidecarReplacementIsNotDeleted(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	s := sqliteWindowsTestStage(t, parent)
	sqliteWindowsSyntheticMain(t, s, []byte("main"))
	journal := filepath.Join(s.workspacePath(), sqliteWindowsMain+"-journal")
	if err := os.WriteFile(journal, []byte("original"), 0o600); err != nil {
		t.Fatal("original sidecar creation failed")
	}
	if err := s.inspect(64, 128, false); err != nil {
		t.Fatal("first sidecar observation failed", err)
	}
	saved := filepath.Join(parent, "saved-original")
	if err := os.Rename(journal, saved); err != nil {
		t.Fatal("test-owned original move failed")
	}
	if err := os.WriteFile(journal, []byte("replacement"), 0o600); err != nil {
		t.Fatal("replacement sidecar creation failed")
	}
	if err := s.inspect(64, 128, false); !errors.Is(err, ErrUnsafe) {
		t.Fatal("replaced sidecar accepted", err)
	}
	if err := s.cleanup(); !errors.Is(err, ErrUnsafe) {
		t.Fatal("replaced sidecar cleanup was not fail-closed", err)
	}
	// #nosec G304 -- Fixed synthetic sidecar inside this test's newly created private workspace.
	if got, err := os.ReadFile(journal); err != nil || string(got) != "replacement" {
		t.Fatal("cleanup removed or changed replacement")
	}
	// #nosec G304 -- Fixed saved-original filename inside this test's newly created private parent.
	if got, err := os.ReadFile(saved); err != nil || string(got) != "original" {
		t.Fatal("cleanup changed saved original")
	}
}

func TestSQLiteWindowsNativeUnknownEntryIsNotDeleted(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	s := sqliteWindowsTestStage(t, parent)
	sqliteWindowsSyntheticMain(t, s, []byte("main"))
	unknown := filepath.Join(s.workspacePath(), "unrecognized")
	if err := os.WriteFile(unknown, []byte("preserve"), 0o600); err != nil {
		t.Fatal("unknown synthetic entry creation failed")
	}
	if err := s.inspect(64, 128, false); !errors.Is(err, ErrUnsafe) {
		t.Fatal("unknown entry accepted", err)
	}
	if err := s.cleanup(); !errors.Is(err, ErrUnsafe) {
		t.Fatal("unknown entry cleanup accepted", err)
	}
	// #nosec G304 -- Fixed unknown-entry canary inside this test's newly created private workspace.
	if got, err := os.ReadFile(unknown); err != nil || string(got) != "preserve" {
		t.Fatal("cleanup deleted unknown entry")
	}
}

func sqliteWindowsTestChild(t *testing.T, parent, name string) string {
	t.Helper()
	path := filepath.Join(parent, name)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal("private child creation failed")
	}
	if err := protectTestDirectory(path); err != nil {
		t.Fatal("private child protection failed")
	}
	return path
}

func TestSQLiteWindowsNativePinsEveryOwnedAncestor(t *testing.T) {
	base := newSQLiteTestDirectory(t)
	ancestor := sqliteWindowsTestChild(t, base, "ancestor")
	parent := sqliteWindowsTestChild(t, ancestor, "parent")
	s := sqliteWindowsTestStage(t, parent)
	for _, path := range []string{base, ancestor, parent, s.workspacePath()} {
		if err := os.Rename(path, path+"-moved"); err == nil {
			// Only this test's directories are attempted; restore on failure.
			_ = os.Rename(path+"-moved", path)
			t.Fatal("owned ancestor rename succeeded while pinned")
		}
	}
	if err := s.cleanup(); err != nil {
		t.Fatal("pinned chain cleanup failed", err)
	}
	assertEntries(t, parent, 0)
}

func TestSQLiteWindowsNativeAncestorACLPolicy(t *testing.T) {
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, outsiders string
		allowed         bool
	}{
		{"read_and_add_only", "(A;;FR;;;WD)(A;;0x6;;;WD)", true},
		{"delete", "(A;;0x10000;;;WD)", false},
		{"delete_child", "(A;;0x40;;;WD)", false},
		{"write_dacl", "(A;;0x40000;;;WD)", false},
		{"write_owner", "(A;;0x80000;;;WD)", false},
		{"write_attributes", "(A;;0x100;;;WD)", false},
		{"write_ea", "(A;;0x10;;;WD)", false},
		{"generic_write", "(A;;GW;;;WD)", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := newSQLiteTestDirectory(t)
			ancestor := sqliteWindowsTestChild(t, base, "ancestor")
			parent := sqliteWindowsTestChild(t, ancestor, "parent")
			if err := setTestDACL(ancestor, "D:P(A;;FA;;;"+sid.String()+")(A;;FA;;;SY)"+tc.outsiders); err != nil {
				t.Fatal("test-owned ancestor DACL setup failed")
			}
			native, err := newSQLiteStaging(parent)
			if tc.allowed {
				if err != nil {
					t.Fatal("read/add-only ancestor rejected", err)
				}
				if err := native.cleanup(); err != nil {
					t.Fatal("permitted ancestor cleanup failed", err)
				}
			} else {
				if native != nil {
					_ = native.cleanup()
				}
				if !errors.Is(err, ErrPermissions) {
					t.Fatal("unsafe ancestor was not rejected", err)
				}
			}
			assertEntries(t, parent, 0)
		})
	}
}

func TestSQLiteWindowsNativeRejectsInheritableWorkspaceLeak(t *testing.T) {
	parent := newSQLiteTestDirectory(t)
	s := sqliteWindowsTestStage(t, parent)
	sid, err := currentSID()
	if err != nil {
		t.Fatal(err)
	}
	path := s.workspacePath()
	if err := setTestDACL(path, "D:P(A;OICI;FA;;;"+sid.String()+")(A;OICI;FA;;;SY)(A;OIIO;FR;;;WD)"); err != nil {
		t.Fatal("test-owned inheritable DACL setup failed")
	}
	if err := s.inspect(64, 128, false); !errors.Is(err, ErrPermissions) {
		t.Fatal("inherit-only sidecar disclosure permission accepted", err)
	}
	if err := protectTestDirectory(path); err != nil {
		t.Fatal("test-owned DACL restoration failed")
	}
	if err := s.cleanup(); err != nil {
		t.Fatal("cleanup after restoring test-owned ACL failed", err)
	}
	assertEntries(t, parent, 0)
}

func TestSQLiteWindowsNativeTrustedInstallerOwnerScope(t *testing.T) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	if err != nil || sid == nil || sid.String() != sqliteWindowsInstallerSID {
		t.Fatal("fixed local TrustedInstaller SID resolution failed")
	}
	systemPath, err := windows.GetWindowsDirectory()
	if err != nil {
		t.Fatal("actual OS volume lookup failed")
	}
	root := filepath.VolumeName(systemPath) + `\`
	if !sqliteWindowsInstallerOwner(sid, root) {
		t.Fatal("exact system-volume root exception rejected")
	}
	otherRoot := `D:\`
	if strings.EqualFold(root, otherRoot) {
		otherRoot = `C:\`
	}
	for _, path := range []string{"", otherRoot, filepath.Join(root, "not-the-root")} {
		if sqliteWindowsInstallerOwner(sid, path) {
			t.Fatal("TrustedInstaller exception expanded beyond actual OS root")
		}
	}
	otherSID, err := windows.StringToSid("S-1-5-80-1-2-3-4-5")
	if err != nil || sqliteWindowsInstallerOwner(otherSID, root) {
		t.Fatal("another service SID accepted as TrustedInstaller")
	}
}

func TestSQLiteWindowsNativeBoundsAncestorCountBeforeOpening(t *testing.T) {
	profile, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("profile unavailable")
	}
	path := profile + strings.Repeat(`\a`, 257)
	if native, err := newSQLiteStaging(path); native != nil || !errors.Is(err, ErrLimit) {
		if native != nil {
			_ = native.cleanup()
		}
		t.Fatal("excessive directory-handle chain accepted", err)
	}
}
