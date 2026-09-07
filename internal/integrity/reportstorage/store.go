// Package reportstorage owns a confined, immutable local S1 artifact store.
package reportstorage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

var ErrUnsafe = errors.New("MI_REPORT_STORAGE_UNSAFE")
var ErrUnavailable = errors.New("MI_REPORT_STORAGE_UNAVAILABLE")
var ErrIntegrity = errors.New("MI_REPORT_FILE_INVALID")

const MaxBytes = 16 << 20

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Store struct {
	root      *os.Root
	directory *os.File
}
type Reference struct {
	OrganizationID int64
	Hash, Format   string
	Size           int64
}

func (s *Store) String() string { return "[confined report storage]" }
func (r Reference) Name() string {
	if r.OrganizationID <= 0 || len(r.Hash) != 64 || !digestPattern.MatchString(r.Hash) || r.Format != "json" && r.Format != "html" || r.Size < 1 || r.Size > MaxBytes {
		return ""
	}
	return "org-" + strconv.FormatInt(r.OrganizationID, 10) + "-" + r.Hash + "." + r.Format
}

// Open creates only the final directory when absent, with restrictive rights
// before use. Its parent must exist; broad existing directories are rejected.
// A native no-symlink walk pins/validates the directory before os.Root is opened;
// identity comparison prevents path-replacement races between those operations.
func Open(directory string) (*Store, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) == filepath.VolumeName(directory)+string(filepath.Separator) {
		return nil, ErrUnsafe
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	closeDir := true
	defer func() {
		if closeDir {
			_ = dir.Close()
		}
	}()
	if err := validateHandle(dir, true); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrUnavailable
	}
	probe, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, ErrUnavailable
	}
	a, ae := dir.Stat()
	b, be := probe.Stat()
	_ = probe.Close()
	if ae != nil || be != nil || !os.SameFile(a, b) {
		_ = root.Close()
		return nil, ErrUnsafe
	}
	closeDir = false
	return &Store{root, dir}, nil
}
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.root != nil {
		err = s.root.Close()
	}
	if s.directory != nil {
		if e := s.directory.Close(); e != nil {
			err = e
		}
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}
func (s *Store) ready(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	if s == nil || s.root == nil || s.directory == nil {
		return ErrUnsafe
	}
	return validateHandle(s.directory, true)
}
func hashBytes(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

// Put stages a restricted file, then atomically links it into its content-
// addressed name without replacement. A verified existing artifact is a retry.
// Temp cleanup concerns only the exact random file this invocation created.
// Crash or DB rollback can leave inaccessible orphans; no directory-wide delete.
func (s *Store) Put(ctx context.Context, org int64, format string, data []byte) (Reference, error) {
	if org <= 0 || format != "json" && format != "html" || len(data) < 1 || len(data) > MaxBytes {
		return Reference{}, ErrUnsafe
	}
	if err := s.ready(ctx); err != nil {
		return Reference{}, err
	}
	ref := Reference{org, hashBytes(data), format, int64(len(data))}
	name := ref.Name()
	if name == "" {
		return Reference{}, ErrUnsafe
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Reference{}, ErrUnavailable
	}
	tmp := ".tmp-" + hex.EncodeToString(nonce[:])
	file, err := s.root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return Reference{}, ErrUnavailable
	}
	defer func() { _ = file.Close(); _ = s.root.Remove(tmp) }()
	if err := validateHandle(file, false); err != nil {
		return Reference{}, err
	}
	for offset := 0; offset < len(data); {
		if ctx.Err() != nil {
			return Reference{}, ErrUnavailable
		}
		end := min(offset+64*1024, len(data))
		n, err := file.Write(data[offset:end])
		if err != nil || n == 0 {
			return Reference{}, ErrUnavailable
		}
		offset += n
	}
	if err := file.Sync(); err != nil {
		return Reference{}, ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return Reference{}, ErrUnavailable
	}
	if ctx.Err() != nil {
		return Reference{}, ErrUnavailable
	}
	if err := s.root.Link(tmp, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return Reference{}, ErrUnavailable
		}
		if _, err := s.Read(ctx, ref); err != nil {
			return Reference{}, err
		}
		return ref, nil
	}
	if err := s.root.Remove(tmp); err != nil {
		return Reference{}, ErrUnavailable
	}
	if err := syncDirectory(s.directory); err != nil {
		return Reference{}, ErrUnavailable
	}
	if _, err := s.Read(ctx, ref); err != nil {
		return Reference{}, err
	}
	return ref, nil
}

// Read verifies the opened handle, length and independent file hash before any
// bytes can reach an HTTP response. It never accepts storage_path or user paths.
func (s *Store) Read(ctx context.Context, ref Reference) ([]byte, error) {
	if err := s.ready(ctx); err != nil {
		return nil, err
	}
	name := ref.Name()
	if name == "" {
		return nil, ErrUnsafe
	}
	info, err := s.root.Lstat(name)
	if err != nil {
		return nil, ErrUnavailable
	}
	if !info.Mode().IsRegular() {
		return nil, ErrUnsafe
	}
	file, err := openArtifact(s.directory, name)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() { _ = file.Close() }()
	if err := validateHandle(file, false); err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, ErrUnsafe
	}
	if opened.Size() != ref.Size {
		return nil, ErrIntegrity
	}
	data := make([]byte, int(ref.Size))
	for offset := 0; offset < len(data); {
		if ctx.Err() != nil {
			return nil, ErrUnavailable
		}
		end := min(offset+64*1024, len(data))
		n, err := io.ReadFull(file, data[offset:end])
		if err != nil {
			return nil, ErrIntegrity
		}
		offset += n
	}
	var extra [1]byte
	n, err := file.Read(extra[:])
	if n != 0 || !errors.Is(err, io.EOF) || hashBytes(data) != ref.Hash {
		return nil, ErrIntegrity
	}
	if err := validateHandle(file, false); err != nil {
		return nil, err
	}
	return data, nil
}
