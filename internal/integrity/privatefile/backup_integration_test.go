//go:build windows || linux

package privatefile_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/privatefile"
	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

// These tests compose public crypto/file capabilities only. They are not a
// production snapshot/restore coordinator and never execute a database image.
// The external test package avoids a secret -> repository -> privatefile test
// import cycle. Go links it into the SAME privatefile test binary, preserving
// serial execution with the other large fixtures (no t.Parallel).
func integrationBackupKeys(t testing.TB, value byte) (*secret.BackupSealer, *secret.BackupOpener) {
	t.Helper()
	master := bytes.Repeat([]byte{value}, 32)
	defer clear(master)
	ring, err := secret.NewKeyRing("fixture-v1", map[string][]byte{"fixture-v1": master})
	if err != nil {
		t.Fatal("derive integration fixture keys")
	}
	s, o, err := ring.NewBackupCapabilities()
	if err != nil {
		t.Fatal("derive integration backup capabilities")
	}
	return s, o
}

func integrationBackupScope() secret.BackupScope {
	return secret.BackupScope{BackupID: 83, ManifestHash: strings.Repeat("c", 64)}
}
func integrationCryptoLimits(size int64) secret.BackupLimits {
	return secret.BackupLimits{MaxBytes: size, MaxEntries: 1, Timeout: time.Minute}
}

func integrationSeal(ctx context.Context, s *secret.BackupSealer, scope secret.BackupScope, limits secret.BackupLimits, path string, fileLimit int64, produce func(context.Context, io.Writer) error) (privatefile.Receipt, secret.BackupReceipt, error) {
	var sealed secret.BackupReceipt
	file, err := privatefile.WriteNew(ctx, path, privatefile.BackupIntegrationTestLimits(fileLimit), func(ctx context.Context, w io.Writer) error {
		var err error
		sealed, err = s.Seal(ctx, scope, limits, w, func(_ context.Context, archive *secret.BackupArchiveWriter) error {
			return archive.WriteEntry(secret.BackupEntry{Kind: "database", ID: "database-snapshot"}, produce)
		})
		return err
	})
	return file, sealed, err
}

type integrationOpened struct {
	plain, cipher privatefile.Receipt
	archive       secret.BackupReceipt
	sourceErr     error
}

// The plaintext writer owns the outer staging boundary. The trusted callback
// MUST propagate Open and privatefile.Read errors; privatefile cannot detect a caller that
// deliberately ignores authentication failure. Even a complete Open receipt is
// insufficient until the enclosing privatefile.Read finishes its native identity checks.
func integrationOpen(ctx context.Context, o *secret.BackupOpener, scope secret.BackupScope, limits secret.BackupLimits, cipherPath, plainPath string, inputLimit, outputLimit int64, consume func(context.Context, io.Reader, io.Writer) error, checkpoint func(string)) (integrationOpened, error) {
	var result integrationOpened
	var err error
	result.plain, err = privatefile.WriteNew(ctx, plainPath, privatefile.BackupIntegrationTestLimits(outputLimit), func(ctx context.Context, w io.Writer) error {
		var readErr error
		result.cipher, readErr = privatefile.Read(ctx, cipherPath, privatefile.BackupIntegrationTestLimits(inputLimit), func(ctx context.Context, r io.Reader) error {
			var openErr error
			result.archive, openErr = o.Open(ctx, scope, limits, r, func(ctx context.Context, entry secret.BackupEntry, r io.Reader) error {
				if entry.Kind != "database" || entry.ID != "database-snapshot" {
					return secret.ErrBackupInvalid
				}
				return consume(ctx, r, w)
			})
			if openErr != nil {
				return openErr
			}
			if checkpoint != nil {
				checkpoint("crypto_complete")
			}
			return nil
		})
		result.sourceErr = readErr
		if readErr != nil {
			return readErr
		}
		if result.archive.Version != secret.BackupFormatVersion || result.archive.Entries != 1 || result.archive.ArchiveBytes != result.cipher.Size || result.archive.ArchiveSHA256 != result.cipher.SHA256 || result.cipher.Published {
			return secret.ErrBackupInvalid
		}
		if checkpoint != nil {
			checkpoint("source_complete")
		}
		return nil
	})
	return result, err
}

func integrationCopy(_ context.Context, r io.Reader, w io.Writer) error {
	_, err := io.Copy(w, r)
	return err
}

func integrationMissing(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("uncommitted plaintext destination became visible")
	}
}

type integrationPatternReader struct{ remaining int64 }

func (r *integrationPatternReader) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	n := min(int64(len(p)), r.remaining)
	for i := range p[:n] {
		p[i] = byte(i % 251)
	}
	r.remaining -= n
	return int(n), nil
}

func TestBackupPrivateFileLargeAuthenticatedPublication(t *testing.T) {
	dir := privatefile.BackupIntegrationTestDir(t)
	cipherPath, plainPath := filepath.Join(dir, "encrypted.backup"), filepath.Join(dir, "restored-synthetic.data")
	const size = int64(25<<20) + 17 // >24 MiB, but two files still fit a 64 MiB tmpfs.
	const cipherLimit = size + (1 << 20)
	s, o := integrationBackupKeys(t, 0x37)
	scope, limits := integrationBackupScope(), integrationCryptoLimits(size)
	want := sha256.New()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	file, sealed, err := integrationSeal(t.Context(), s, scope, limits, cipherPath, cipherLimit, func(_ context.Context, w io.Writer) error {
		_, err := io.Copy(io.MultiWriter(w, want), &integrationPatternReader{remaining: size})
		return err
	})
	if err != nil || !file.Published || file.Size != sealed.ArchiveBytes || file.SHA256 != sealed.ArchiveSHA256 || sealed.PlaintextBytes != size || sealed.ArchiveBytes <= size {
		t.Fatal("private encrypted publication or dual receipt mismatch", err)
	}
	checkpoints, chunks := 0, 0
	opened, err := integrationOpen(t.Context(), o, scope, limits, cipherPath, plainPath, cipherLimit, size, func(_ context.Context, r io.Reader, w io.Writer) error {
		var chunk [64 << 10]byte
		defer clear(chunk[:])
		for {
			n, err := r.Read(chunk[:])
			if n > 0 {
				integrationMissing(t, plainPath)
				written, writeErr := w.Write(chunk[:n])
				if writeErr != nil {
					return writeErr
				}
				if written != n {
					return io.ErrShortWrite
				}
				chunks++
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
		}
	}, func(string) { integrationMissing(t, plainPath); checkpoints++ })
	if err != nil || !opened.plain.Published || opened.plain.Size != size || opened.plain.SHA256 != hex.EncodeToString(want.Sum(nil)) || opened.archive != sealed || opened.cipher.Size != file.Size || opened.cipher.SHA256 != file.SHA256 || opened.cipher.Published || checkpoints != 2 || chunks <= 384 {
		t.Fatal("complete authentication did not gate private plaintext publication", err)
	}
	verified := sha256.New()
	plain, err := privatefile.Read(t.Context(), plainPath, privatefile.BackupIntegrationTestLimits(size), func(_ context.Context, r io.Reader) error { _, err := io.Copy(verified, r); return err })
	runtime.ReadMemStats(&after)
	if err != nil || plain.Size != size || plain.SHA256 != opened.plain.SHA256 || hex.EncodeToString(verified.Sum(nil)) != opened.plain.SHA256 || after.TotalAlloc-before.TotalAlloc > 12<<20 {
		t.Fatal("published plaintext changed or streaming allocated the complete archive", err)
	}
	privatefile.BackupIntegrationTestEntries(t, dir, 2)
}

func integrationSmallArchive(t *testing.T, dir string) (*secret.BackupSealer, *secret.BackupOpener, secret.BackupScope, []byte) {
	t.Helper()
	s, o := integrationBackupKeys(t, 0x37)
	scope := integrationBackupScope()
	path := filepath.Join(dir, "source.backup")
	if _, _, err := integrationSeal(t.Context(), s, scope, integrationCryptoLimits(257), path, 4096, privatefile.BackupIntegrationTestProduce(bytes.Repeat([]byte{0x39}, 257))); err != nil {
		t.Fatal("write small authenticated private archive", err)
	}
	encoded, err := privatefile.BackupIntegrationTestRead(t.Context(), path, 4096)
	if err != nil {
		t.Fatal("read small encrypted fixture", err)
	}
	return s, o, scope, encoded
}

func TestBackupPrivateFileAuthenticationFailuresNeverPublish(t *testing.T) {
	for _, mode := range []string{"trailing", "truncated_final", "truncated_data_swallowed", "wrong_key", "wrong_scope", "swallowed_output_limit", "swallowed_cancel", "cancel_after_crypto", "cancel_after_source"} {
		t.Run(mode, func(t *testing.T) {
			dir := privatefile.BackupIntegrationTestDir(t)
			_, o, scope, encoded := integrationSmallArchive(t, dir)
			input, output := filepath.Join(dir, "input.backup"), filepath.Join(dir, "never-visible.data")
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			outputLimit := int64(4096)
			swallow, cancelDuring := false, false
			switch mode {
			case "trailing":
				encoded = append(encoded, 1)
			case "truncated_final":
				encoded = encoded[:len(encoded)-1]
			case "truncated_data_swallowed":
				encoded = encoded[:208+104+20+100] // Authenticated header/Begin, incomplete Data tag.
				swallow = true
			case "wrong_key":
				_, o = integrationBackupKeys(t, 0x71)
			case "wrong_scope":
				scope.BackupID++
			case "swallowed_output_limit":
				outputLimit, swallow = 1, true
			case "swallowed_cancel":
				swallow, cancelDuring = true, true
			}
			if err := privatefile.BackupIntegrationTestWrite(t.Context(), input, encoded, 4096); err != nil {
				t.Fatal("write deliberately invalid encrypted fixture", err)
			}
			consumerCalls := 0
			result, err := integrationOpen(ctx, o, scope, integrationCryptoLimits(257), input, output, 4096, outputLimit, func(_ context.Context, r io.Reader, w io.Writer) error {
				consumerCalls++
				if cancelDuring {
					var first [1]byte
					if _, err := io.ReadFull(r, first[:]); err != nil {
						return err
					}
					if _, err := w.Write(first[:]); err != nil {
						return err
					}
					clear(first[:])
					cancel()
				}
				_, err := io.Copy(w, r)
				if swallow {
					return nil
				}
				return err
			}, func(phase string) {
				integrationMissing(t, output)
				if mode == "cancel_after_crypto" && phase == "crypto_complete" || mode == "cancel_after_source" && phase == "source_complete" {
					cancel()
				}
			})
			if err == nil || result.plain.Published {
				t.Fatal("failed authentication/cancellation published plaintext")
			}
			integrationMissing(t, output)
			if (mode == "wrong_key" || mode == "wrong_scope") && consumerCalls != 0 {
				t.Fatal("untrusted key/scope reached plaintext consumer")
			}
			if strings.HasPrefix(mode, "cancel_after_") && result.archive.Entries != 1 {
				t.Fatal("post-authentication cancellation did not reach intended barrier")
			}
			if mode == "cancel_after_source" && result.cipher.Size != int64(len(encoded)) {
				t.Fatal("post-native-read cancellation did not reach intended barrier")
			}
			if mode == "swallowed_output_limit" && (result.archive.Entries != 1 || !errors.Is(err, privatefile.ErrLimit)) {
				t.Fatal("swallowed staging error did not survive successful full authentication", err)
			}
			privatefile.BackupIntegrationTestEntries(t, dir, 2) // Input files remain; no abandoned plaintext staging.
		})
	}
}

func TestBackupPrivateFileSourceRecheckFailureAfterAuthentication(t *testing.T) {
	dir := privatefile.BackupIntegrationTestDir(t)
	_, o, scope, encoded := integrationSmallArchive(t, dir)
	input, output := filepath.Join(dir, "source.backup"), filepath.Join(dir, "never-visible.data")
	before, err := os.Stat(input)
	if err != nil {
		t.Fatal("inspect test-owned source before authenticated read")
	}
	// No context is canceled and the output directory/ACL stays unchanged. This
	// real metadata mutation occurs only AFTER authenticated Final and EOF, but
	// before privatefile.Read's native final Stat. It cannot be mistaken for outer privatefile.WriteNew
	// cancellation or authentication failure and needs no production hook.
	cryptoComplete, sourceComplete := false, false
	var consumed int64
	result, err := integrationOpen(t.Context(), o, scope, integrationCryptoLimits(257), input, output, 4096, 4096, func(_ context.Context, r io.Reader, w io.Writer) error {
		var err error
		consumed, err = io.Copy(w, r)
		return err
	}, func(phase string) {
		integrationMissing(t, output)
		if phase == "source_complete" {
			sourceComplete = true
			return
		}
		cryptoComplete = true
		changed := before.ModTime().Add(-time.Hour)
		if err := os.Chtimes(input, changed, changed); err != nil {
			t.Fatal("native source metadata mutation rejected")
		}
		after, err := os.Stat(input)
		if err != nil || after.ModTime().Equal(before.ModTime()) {
			t.Fatal("native source metadata did not change")
		}
	})
	if !cryptoComplete || sourceComplete || consumed != 257 || t.Context().Err() != nil {
		t.Fatal("source recheck failure did not reach the intended non-cancellation barrier")
	}
	if !errors.Is(result.sourceErr, privatefile.ErrUnsafe) || !errors.Is(err, privatefile.ErrCallback) || result.cipher != (privatefile.Receipt{}) || result.plain.Published {
		t.Fatal("native source recheck failure was ignored after successful authentication", err)
	}
	want := sha256.Sum256(encoded)
	if result.archive.Entries != 1 || result.archive.PlaintextBytes != 257 || result.archive.ArchiveBytes != int64(len(encoded)) || result.archive.ArchiveSHA256 != hex.EncodeToString(want[:]) {
		t.Fatal("native rejection happened before full archive authentication")
	}
	integrationMissing(t, output)
	unchanged, err := privatefile.BackupIntegrationTestRead(t.Context(), input, 4096)
	if err != nil || !bytes.Equal(unchanged, encoded) {
		t.Fatal("metadata-only rejection changed encrypted source bytes", err)
	}
	privatefile.BackupIntegrationTestEntries(t, dir, 1)
}

func TestBackupPrivateFileNoReplacePreservesCipherAndPlaintext(t *testing.T) {
	dir := privatefile.BackupIntegrationTestDir(t)
	s, o, scope, encoded := integrationSmallArchive(t, dir)
	cipherPath, plainPath := filepath.Join(dir, "source.backup"), filepath.Join(dir, "existing.data")
	file, _, err := integrationSeal(t.Context(), s, scope, integrationCryptoLimits(10), cipherPath, 4096, privatefile.BackupIntegrationTestProduce([]byte("different")))
	if !errors.Is(err, privatefile.ErrExists) || file.Published {
		t.Fatal("existing encrypted destination replaced", err)
	}
	after, err := privatefile.BackupIntegrationTestRead(t.Context(), cipherPath, 4096)
	if err != nil || !bytes.Equal(after, encoded) {
		t.Fatal("failed encrypted publication changed original", err)
	}
	original := []byte("existing-synthetic-plaintext-canary")
	if err := privatefile.BackupIntegrationTestWrite(t.Context(), plainPath, original, 4096); err != nil {
		t.Fatal("write existing private target", err)
	}
	result, err := integrationOpen(t.Context(), o, scope, integrationCryptoLimits(257), cipherPath, plainPath, 4096, 4096, integrationCopy, nil)
	if !errors.Is(err, privatefile.ErrExists) || result.plain.Published || result.archive.Entries != 1 {
		t.Fatal("complete authenticated plaintext replaced existing target", err)
	}
	after, err = privatefile.BackupIntegrationTestRead(t.Context(), plainPath, 4096)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("failed plaintext publication changed original", err)
	}
	privatefile.BackupIntegrationTestEntries(t, dir, 2)
}

func TestBackupPrivateFilePlaintextAndCiphertextLimitsAreDistinct(t *testing.T) {
	dir := privatefile.BackupIntegrationTestDir(t)
	s, _ := integrationBackupKeys(t, 0x37)
	scope, limits := integrationBackupScope(), integrationCryptoLimits(1024)
	if privatefile.MaxBytes != 1<<40 || secret.BackupMaxBytes != 1<<40 {
		t.Fatal("review hard-limit changes before changing integration expectations")
	}
	tooSmall := filepath.Join(dir, "cipher-budget-too-small.backup")
	file, sealed, err := integrationSeal(t.Context(), s, scope, limits, tooSmall, 1024, privatefile.BackupIntegrationTestProduce(make([]byte, 1024)))
	if !errors.Is(err, privatefile.ErrLimit) || file.Published || sealed != (secret.BackupReceipt{}) {
		t.Fatal("plaintext bytes incorrectly treated as sufficient ciphertext budget", err)
	}
	integrationMissing(t, tooSmall)
	path := filepath.Join(dir, "adequate-cipher-budget.backup")
	file, sealed, err = integrationSeal(t.Context(), s, scope, limits, path, 4096, privatefile.BackupIntegrationTestProduce(make([]byte, 1024)))
	if err != nil || !file.Published || sealed.PlaintextBytes != 1024 || file.Size <= 1024 || sealed.ArchiveBytes != file.Size || sealed.ArchiveSHA256 != file.SHA256 {
		t.Fatal("separate explicit ciphertext budget rejected", err)
	}
	called := false
	if file, err := privatefile.WriteNew(t.Context(), filepath.Join(dir, "beyond-file-cap"), privatefile.BackupIntegrationTestLimits(privatefile.MaxBytes+1), func(context.Context, io.Writer) error { called = true; return nil }); !errors.Is(err, privatefile.ErrLimit) || file.Published || called {
		t.Fatal("file hard ceiling bypassed")
	}
	limits.MaxBytes = secret.BackupMaxBytes + 1
	if file, sealed, err := integrationSeal(t.Context(), s, scope, limits, filepath.Join(dir, "beyond-crypto-cap"), 4096, privatefile.BackupIntegrationTestProduce([]byte("x"))); err == nil || file.Published || sealed != (secret.BackupReceipt{}) {
		t.Fatal("crypto plaintext hard ceiling bypassed")
	}
	privatefile.BackupIntegrationTestEntries(t, dir, 1)
}
