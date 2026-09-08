package secret_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
)

const (
	backupFuzzInputLimit = 256 << 10
	backupFuzzChunk      = 64 << 10
	backupFuzzVersion    = "fuzz-v1"
)

type backupFuzzEntry struct {
	kind byte
	id   string
	data []byte
}

type backupFuzzExpected struct {
	entries int
	bytes   int64
	digest  [32]byte
}

// Every worker constructs the same corpus. The independent v1 encoder below
// uses public synthetic keys and deterministic fixture labels, never production
// randomness or a replacement opener. This is parser evidence, not a restore.
func FuzzBackupOpenArchive(f *testing.F) {
	master := bytes.Repeat([]byte{0x63}, 32)
	ring, err := secret.NewKeyRing(backupFuzzVersion, map[string][]byte{backupFuzzVersion: master})
	clear(master)
	if err != nil {
		f.Fatal("synthetic backup ring unavailable")
	}
	_, opener, err := ring.NewBackupCapabilities()
	if err != nil {
		f.Fatal("synthetic backup opener unavailable")
	}
	scope := secret.BackupScope{BackupID: 73, ManifestHash: strings.Repeat("a", 64)}
	known := make(map[[32]byte]backupFuzzExpected)
	rejected := make(map[[32]byte]struct{})
	addValid := func(label string, entries []backupFuzzEntry) []byte {
		encoded := encodeBackupFuzzFixture(f, label, entries)
		h := sha256.New()
		var size int64
		for _, entry := range entries {
			_, _ = h.Write(entry.data)
			size += int64(len(entry.data))
		}
		var digest [32]byte
		copy(digest[:], h.Sum(nil))
		known[sha256.Sum256(encoded)] = backupFuzzExpected{entries: len(entries), bytes: size, digest: digest}
		f.Add(encoded, uint8(0))
		return encoded
	}
	addInvalid := func(encoded []byte) {
		rejected[sha256.Sum256(encoded)] = struct{}{}
		f.Add(encoded, uint8(0))
	}
	addValid("empty", nil)
	small := addValid("small", []backupFuzzEntry{{1, "database", []byte("synthetic-backup-fuzz-content-canary")}})
	multi := addValid("multiple-chunks", []backupFuzzEntry{
		{1, "database", bytes.Repeat([]byte{0x5a}, 2*backupFuzzChunk+17)},
		{2, "manifest", []byte("synthetic manifest")},
		{5, "config", nil},
	})
	// Valid authentication must not bypass stricter plaintext/entry budgets.
	f.Add(small, uint8(1))
	f.Add(multi, uint8(2))
	f.Add(multi, uint8(3))
	tooMany := make([]backupFuzzEntry, 17)
	for i := range tooMany {
		tooMany[i] = backupFuzzEntry{kind: 3, id: "report-" + string(rune('a'+i))}
	}
	addValid("too-many-entries", tooMany)
	addInvalid(nil)
	addInvalid(bytes.Clone(small[:207]))
	addInvalid(bytes.Clone(small[:len(small)-1]))
	addInvalid(append(bytes.Clone(small), 0))
	addInvalid(append(bytes.Clone(small), small...))
	for _, offset := range []int{0, 160, 208 + 20, len(small) - 1} {
		mutated := bytes.Clone(small)
		mutated[offset] ^= 0x80
		addInvalid(mutated)
	}
	oversizedFrame := bytes.Clone(small)
	// The begin record occupies 20 + 68 + 16 bytes; the next frame advertises
	// an impossible data length, which must be rejected before allocation.
	binary.BigEndian.PutUint32(oversizedFrame[208+104+4:208+104+8], ^uint32(0))
	addInvalid(oversizedFrame)

	f.Fuzz(func(t *testing.T, encoded []byte, selector uint8) {
		if len(encoded) > backupFuzzInputLimit {
			t.Skip("archive exceeds bounded fuzz input")
		}
		limits := secret.BackupLimits{MaxBytes: 192 << 10, MaxEntries: 16, Timeout: 2 * time.Second}
		switch selector % 4 {
		case 1:
			limits.MaxBytes = 1
		case 2:
			limits.MaxEntries = 1
		case 3:
			limits.MaxBytes = backupFuzzChunk
		}
		before := sha256.Sum256(encoded)
		expected, isKnown := known[before]
		_, mustReject := rejected[before]
		mustPass := isKnown && expected.entries <= limits.MaxEntries && expected.bytes <= limits.MaxBytes
		seen := make(map[string]struct{})
		contentHash := sha256.New()
		var consumed int64
		source := bytes.NewReader(encoded)
		receipt, openErr := opener.Open(t.Context(), scope, limits, source, func(_ context.Context, entry secret.BackupEntry, r io.Reader) error {
			if !validBackupFuzzEntry(entry) || len(seen) >= limits.MaxEntries {
				t.Error("consumer received invalid or excessive entries")
				return errors.New("synthetic-backup-fuzz-callback-canary")
			}
			if _, duplicate := seen[entry.ID]; duplicate {
				t.Error("consumer received a duplicate entry")
				return errors.New("synthetic-backup-fuzz-callback-canary")
			}
			seen[entry.ID] = struct{}{}
			var buffer [4096]byte
			defer clear(buffer[:])
			for {
				n, readErr := r.Read(buffer[:])
				if n < 0 || n > len(buffer) || int64(n) > limits.MaxBytes-consumed {
					t.Error("consumer byte budget or Reader contract exceeded")
					return errors.New("synthetic-backup-fuzz-callback-canary")
				}
				_, _ = contentHash.Write(buffer[:n])
				consumed += int64(n)
				if readErr != nil {
					if errors.Is(readErr, io.EOF) {
						return nil
					}
					return readErr
				}
				if n == 0 {
					t.Error("nonempty consumer read made no progress")
					return errors.New("synthetic-backup-fuzz-callback-canary")
				}
			}
		})
		if sha256.Sum256(encoded) != before {
			t.Fatal("opener modified its source bytes")
		}
		if openErr != nil {
			if receipt != (secret.BackupReceipt{}) {
				t.Fatal("failed archive returned a receipt")
			}
			// Exact sentinel identity also rejects wrapped errors containing any
			// original input, callback detail, path or other uncontrolled text.
			//nolint:errorlint // Exact sentinel identity is the tested redaction contract; accepting wrapped errors would weaken it.
			switch openErr {
			case secret.ErrBackupInvalid, secret.ErrBackupUnavailable, secret.ErrBackupLimit, secret.ErrBackupCanceled, secret.ErrBackupConsumer, secret.ErrBackupClosed, secret.ErrBackupIncomplete:
			default:
				t.Fatal("archive error escaped the fixed classification set")
			}
			if mustPass {
				t.Fatal("known valid archive was rejected within its budgets")
			}
			return
		}
		if mustReject || isKnown && !mustPass {
			t.Fatal("known malformed or over-budget archive was accepted")
		}
		if receipt.Version != secret.BackupFormatVersion || receipt.KeyVersion != backupFuzzVersion || receipt.Entries != len(seen) || receipt.PlaintextBytes != consumed || receipt.ArchiveBytes != int64(len(encoded)) || receipt.ArchiveSHA256 != hex.EncodeToString(before[:]) || source.Len() != 0 {
			t.Fatal("successful archive receipt disagrees with consumed input")
		}
		if isKnown && (receipt.Entries != expected.entries || consumed != expected.bytes || !bytes.Equal(contentHash.Sum(nil), expected.digest[:])) {
			t.Fatal("known authenticated plaintext changed")
		}
	})
}

func validBackupFuzzEntry(entry secret.BackupEntry) bool {
	switch entry.Kind {
	case "database", "manifest", "report", "rule", "config":
	default:
		return false
	}
	if len(entry.ID) < 1 || len(entry.ID) > 64 {
		return false
	}
	for i, value := range []byte(entry.ID) {
		if value >= 'a' && value <= 'z' || value >= '0' && value <= '9' || i > 0 && (value == '_' || value == '-') {
			continue
		}
		return false
	}
	return true
}

// This frozen binary-v1 fixture encoder intentionally does not call Seal or any
// unexported secret helper. Distinct labels select distinct public synthetic
// DEKs/nonces; no global RNG override or random startup corpus is involved.
func encodeBackupFuzzFixture(t testing.TB, label string, entries []backupFuzzEntry) []byte {
	t.Helper()
	header := make([]byte, 208)
	copy(header, []byte{'M', 'I', 'I', 'B', 'K', 'P', 0, 1})
	header[8] = 7
	binary.BigEndian.PutUint64(header[12:20], 73)
	copy(header[20:52], bytes.Repeat([]byte{0xaa}, 32))
	archiveNonce := sha256.Sum256([]byte("backup-fuzz-archive/" + label))
	wrapNonce := sha256.Sum256([]byte("backup-fuzz-wrap/" + label))
	dek := sha256.Sum256([]byte("backup-fuzz-dek/" + label))
	defer clear(dek[:])
	copy(header[52:84], archiveNonce[:])
	copy(header[84:96], wrapNonce[:12])
	copy(header[96:160], backupFuzzVersion)
	wrapKey, err := hkdf.Key(sha256.New, bytes.Repeat([]byte{0x63}, 32), nil, "mii/v1/backup-archive-wrap/"+backupFuzzVersion, 32)
	if err != nil {
		t.Fatal("synthetic wrapping key unavailable")
	}
	defer clear(wrapKey)
	wrapAAD := append([]byte("mii/backup-wrap/v1\x00"), header[:160]...)
	copy(header[160:], backupFuzzAEAD(t, wrapKey).Seal(nil, header[84:96], dek[:], wrapAAD))
	headerHash := sha256.Sum256(header)
	var epoch [8]byte // These bounded fixtures cannot reach the 4096-record epoch.
	info := append([]byte("mii/backup-data-epoch/v1\x00"), headerHash[:]...)
	info = append(info, epoch[:]...)
	dataKey, err := hkdf.Key(sha256.New, dek[:], nil, string(info), 32)
	if err != nil {
		t.Fatal("synthetic data key unavailable")
	}
	defer clear(dataKey)
	aead := backupFuzzAEAD(t, dataKey)
	out := bytes.NewBuffer(header)
	var sequence uint64
	frame := func(kind byte, ordinal uint32, plaintext []byte) {
		if len(plaintext) > backupFuzzChunk || sequence >= 4096 {
			t.Fatal("fixture encoder exceeded its fixed bounds")
		}
		var encoded [20]byte
		encoded[0] = kind
		// #nosec G115 -- Fixed 64 KiB fixture guard above.
		binary.BigEndian.PutUint32(encoded[4:8], uint32(len(plaintext)))
		binary.BigEndian.PutUint64(encoded[8:16], sequence)
		binary.BigEndian.PutUint32(encoded[16:], ordinal)
		var nonce [12]byte
		copy(nonce[:4], []byte{'B', 'K', 'P', 1})
		binary.BigEndian.PutUint64(nonce[4:], sequence)
		aad := append([]byte("mii/backup-record/v1\x00"), headerHash[:]...)
		aad = append(aad, encoded[:]...)
		_, _ = out.Write(encoded[:])
		_, _ = out.Write(aead.Seal(nil, nonce[:], plaintext, aad))
		sequence++
	}
	var total uint64
	for i, entry := range entries {
		if i >= 17 || len(entry.id) < 1 || len(entry.id) > 64 {
			t.Fatal("fixture entry exceeded its fixed bounds")
		}
		var begin [68]byte
		begin[0] = entry.kind
		// #nosec G115 -- Fixed 1..64 identifier guard above.
		begin[1] = byte(len(entry.id))
		copy(begin[4:], entry.id)
		// #nosec G115 -- Fixture entry index is bounded to 0..16 above.
		ordinal := uint32(i + 1)
		frame(1, ordinal, begin[:])
		remaining := entry.data
		for len(remaining) > 0 {
			n := min(len(remaining), backupFuzzChunk)
			frame(2, ordinal, remaining[:n])
			remaining = remaining[n:]
		}
		var end [8]byte
		binary.BigEndian.PutUint64(end[:], uint64(len(entry.data)))
		frame(3, ordinal, end[:])
		total += uint64(len(entry.data))
	}
	var final [12]byte
	if len(entries) > 17 {
		t.Fatal("fixture final entry count exceeded its bound")
	}
	// #nosec G115 -- Fixture entry count is bounded to 0..17 above.
	binary.BigEndian.PutUint32(final[:4], uint32(len(entries)))
	binary.BigEndian.PutUint64(final[4:], total)
	frame(4, 0, final[:])
	if out.Len() > backupFuzzInputLimit {
		t.Fatal("fixture exceeded bounded fuzz input")
	}
	return out.Bytes()
}

func backupFuzzAEAD(t testing.TB, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal("synthetic AES key unavailable")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal("synthetic GCM unavailable")
	}
	return aead
}
