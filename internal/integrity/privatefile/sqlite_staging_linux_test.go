//go:build linux

package privatefile

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func newSQLiteTestDirectory(t *testing.T) string {
	t.Helper()
	return privateDir(t)
}

func sqliteTestSidecarID(t *testing.T, target *SQLiteTarget, name string) [3]uint64 {
	t.Helper()
	s, ok := target.state.native.(*linuxSQLiteStaging)
	if !ok {
		t.Fatal("wrong platform fixture")
	}
	var st unix.Stat_t
	if err := unix.Fstatat(int(s.work.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		t.Fatal("sidecar identity setup failed")
	}
	return [3]uint64{st.Dev, st.Ino, 0}
}

func sqliteTestFileID(t *testing.T, path string) [3]uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 {
		t.Fatal("test-owned retained identity lookup failed")
	}
	return [3]uint64{st.Dev, st.Ino, 0}
}

func TestLinuxSQLiteStagingAncestorPolicy(t *testing.T) {
	base := privateDir(t)
	ancestor := filepath.Join(base, "ancestor")
	parent := filepath.Join(ancestor, "parent")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Intentionally unsafe test-owned ancestor must be rejected.
	if err := os.Chmod(ancestor, 0o777); err != nil {
		t.Fatal(err)
	}
	called := false
	r, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(context.Context, *SQLiteTarget) error { called = true; return nil }, func(context.Context, io.Reader) error { called = true; return nil })
	if !errors.Is(err, ErrPermissions) || called || r != (Receipt{}) {
		t.Fatal("cross-UID replaceable ancestor accepted")
	}
	if err := os.Chmod(ancestor, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	_, err = WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), buildSQLiteTestDatabase, func(_ context.Context, r io.Reader) error { _, err := io.Copy(io.Discard, r); return err })
	if err != nil {
		t.Fatalf("trusted sticky ancestor failed: %v", err)
	}
	assertSQLiteParentEmpty(t, parent)
}

func TestLinuxSQLiteStagingParentAndMainReplacement(t *testing.T) {
	for _, replacement := range []string{"parent", "main"} {
		t.Run(replacement, func(t *testing.T) {
			parent := newSQLiteTestDirectory(t)
			var replacementFile string
			consumed := false
			receipt, err := WithSQLiteStaging(context.Background(), parent, sqliteTestLimits(), func(ctx context.Context, target *SQLiteTarget) error {
				if err := buildSQLiteTestDatabase(ctx, target); err != nil {
					return err
				}
				main := target.state.native.databasePath()
				if replacement == "main" {
					if err := os.Rename(main, main+".retained"); err != nil {
						t.Fatal(err)
					}
					replacementFile = main
				} else {
					// Same-UID mutation is outside the adversary model, but a
					// detected change must never produce a success or wrong deletion.
					moved := parent + "-retained"
					if err := os.Rename(parent, moved); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() {
						_ = os.Remove(replacementFile)
						_ = os.Remove(parent)
						_ = os.Rename(moved, parent)
					})
					if err := os.Mkdir(parent, 0o700); err != nil {
						t.Fatal(err)
					}
					replacementFile = filepath.Join(parent, "replacement")
				}
				if err := os.WriteFile(replacementFile, []byte("preserve-replacement"), 0o600); err != nil {
					t.Fatal(err)
				}
				return nil
			}, func(context.Context, io.Reader) error { consumed = true; return nil })
			if err == nil || consumed || receipt != (Receipt{}) {
				t.Fatal("replacement accepted")
			}
			// #nosec G304 -- Fixed canary path created by this test in its own fixture.
			content, err := os.ReadFile(replacementFile)
			if err != nil || string(content) != "preserve-replacement" {
				t.Fatal("replacement was deleted")
			}
		})
	}
}
