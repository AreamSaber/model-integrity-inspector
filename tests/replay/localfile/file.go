// Package localfile is the offline development replay CLI's confined file boundary.
// It accepts explicit absolute local paths, never URLs or arbitrary Readers.
package localfile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var (
	ErrUnsafe      = errors.New("MI_REPLAY_FILE_UNSAFE")
	ErrPermissions = errors.New("MI_REPLAY_FILE_PERMISSIONS")
	ErrUnavailable = errors.New("MI_REPLAY_FILE_UNAVAILABLE")
	ErrExists      = errors.New("MI_REPLAY_OUTPUT_EXISTS")
	ErrLimit       = errors.New("MI_REPLAY_FILE_LIMIT")
	ErrCanceled    = errors.New("MI_REPLAY_CANCELED")
	ErrFilesystem  = errors.New("MI_REPLAY_FILESYSTEM_UNSUPPORTED")
)

const MaxFileBytes = 24 << 20

func canceled(ctx context.Context) bool { return ctx == nil || ctx.Err() != nil }

func splitPath(path string) (string, string, error) {
	if path == "" || len(path) > 4096 || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", "", ErrUnsafe
	}
	for _, r := range path {
		if r < 32 || r == 127 {
			return "", "", ErrUnsafe
		}
	}
	if strings.Contains(path, "://") {
		return "", "", ErrUnsafe
	}
	if err := validatePath(path); err != nil {
		return "", "", err
	}
	parent, name := filepath.Dir(path), filepath.Base(path)
	if name == "." || name == ".." || parent == path {
		return "", "", ErrUnsafe
	}
	return parent, name, nil
}

// Read returns a finite snapshot from one no-follow regular-file handle. OS I/O
// cannot be force-interrupted; devices, pipes and remote paths are not accepted.
func Read(ctx context.Context, path string, limit int) ([]byte, error) {
	if canceled(ctx) {
		return nil, ErrCanceled
	}
	if limit < 1 || limit > MaxFileBytes {
		return nil, ErrLimit
	}
	parent, name, err := splitPath(path)
	if err != nil {
		return nil, err
	}
	dir, err := openDirectory(parent, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	f, err := openInput(dir, name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if err := validateFile(f); err != nil {
		return nil, err
	}
	before, err := f.Stat()
	if err != nil {
		return nil, ErrUnavailable
	}
	if before.Size() < 1 || before.Size() > int64(limit) {
		return nil, ErrLimit
	}
	data := make([]byte, before.Size())
	keep := false
	defer func() {
		if !keep {
			clear(data)
		}
	}()
	for off := 0; off < len(data); {
		if canceled(ctx) {
			return nil, ErrCanceled
		}
		end := min(off+64*1024, len(data))
		n, err := io.ReadFull(f, data[off:end])
		if err != nil || n != end-off {
			return nil, ErrUnavailable
		}
		off += n
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); n != 0 || err != io.EOF {
		return nil, ErrUnsafe
	}
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, ErrUnsafe
	}
	if err := validateFile(f); err != nil {
		return nil, err
	}
	if canceled(ctx) {
		return nil, ErrCanceled
	}
	keep = true
	return data, nil
}

// WriteNew publishes only a complete, synced file. The output parent must already
// be private. Atomic no-replace publication never mutates an existing destination.
// A post-publication durability error may leave a COMPLETE output; no rollback
// deletes the destination. Callers must not assume any error means it is absent.
func WriteNew(ctx context.Context, path string, data []byte, limit int) error {
	return writeNew(ctx, path, data, limit, nil)
}

func writeNew(ctx context.Context, path string, data []byte, limit int, beforePublish func()) error {
	if canceled(ctx) {
		return ErrCanceled
	}
	if limit < 1 || limit > MaxFileBytes || len(data) < 1 || len(data) > limit {
		return ErrLimit
	}
	parent, name, err := splitPath(path)
	if err != nil {
		return err
	}
	dir, err := openDirectory(parent, true)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrUnavailable
	}
	tempName := ".mii-replay-" + hex.EncodeToString(random[:]) + ".tmp"
	f, err := createTemp(dir, tempName)
	if err != nil {
		return err
	}
	published := false
	defer func() {
		if !published {
			_ = removeTemp(dir, f, tempName)
		}
		_ = f.Close()
	}()
	if err := validateFile(f); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		if canceled(ctx) {
			return ErrCanceled
		}
		end := min(off+64*1024, len(data))
		n, err := f.Write(data[off:end])
		if err != nil || n != end-off {
			return ErrUnavailable
		}
		off += n
	}
	if err := f.Sync(); err != nil {
		return ErrUnavailable
	}
	if err := validateFile(f); err != nil {
		return err
	}
	if beforePublish != nil {
		beforePublish()
	}
	if canceled(ctx) {
		return ErrCanceled
	}
	if err := publish(dir, f, tempName, name); err != nil {
		return err
	}
	published = true
	return syncDirectory(dir)
}
