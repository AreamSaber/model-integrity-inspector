package secret

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
)

const (
	backupHeaderPrefix = 160
	backupHeaderBytes  = 208
	backupFrameHeader  = 20
	backupBegin        = byte(1)
	backupData         = byte(2)
	backupEnd          = byte(3)
	backupFinal        = byte(4)
	backupEpochRecords = 4096
)

var backupMagic = [8]byte{'M', 'I', 'I', 'B', 'K', 'P', 0, 1}

type backupCipher struct {
	dek        [32]byte
	headerHash [32]byte
	seq, epoch uint64
	aead       cipher.AEAD
	buffer     [backupChunkBytes + 16]byte
}

func (c *backupCipher) destroy() { clear(c.dek[:]); clear(c.buffer[:]); c.aead = nil }

// Header prefix is the wrapping AAD. Only AFTER wrapping do we hash the full
// header for record authentication, avoiding circular AAD dependencies.
func (s *BackupSealer) backupHeader(scope BackupScope) ([]byte, *backupCipher, error) {
	if len(s.version) < 1 || len(s.version) > 64 || scope.BackupID <= 0 {
		return nil, nil, ErrBackupInvalid
	}
	header := make([]byte, backupHeaderBytes)
	copy(header, backupMagic[:])
	// #nosec G115 -- Explicit 1..64 length guard above; version is immutable.
	header[8] = byte(len(s.version))
	binary.BigEndian.PutUint64(header[12:20], uint64(scope.BackupID))
	manifest, err := hex.DecodeString(scope.ManifestHash)
	if err != nil {
		return nil, nil, ErrBackupInvalid
	}
	copy(header[20:52], manifest)
	copy(header[96:160], s.version)
	c := &backupCipher{}
	if _, err := rand.Read(c.dek[:]); err != nil {
		c.destroy()
		return nil, nil, ErrBackupUnavailable
	}
	if _, err := rand.Read(header[52:96]); err != nil {
		c.destroy()
		return nil, nil, ErrBackupUnavailable
	}
	aead, err := gcm(s.key[:])
	if err != nil {
		c.destroy()
		return nil, nil, ErrBackupUnavailable
	}
	aad := append([]byte("mii/backup-wrap/v1\x00"), header[:backupHeaderPrefix]...)
	wrapped := aead.Seal(header[backupHeaderPrefix:backupHeaderPrefix], header[84:96], c.dek[:], aad)
	if len(wrapped) != 48 {
		c.destroy()
		return nil, nil, ErrBackupUnavailable
	}
	c.headerHash = sha256.Sum256(header)
	return header, c, nil
}

func (o *BackupOpener) openBackupHeader(scope BackupScope, header []byte) (*backupCipher, string, error) {
	if scope.BackupID <= 0 {
		return nil, "", ErrBackupInvalid
	}
	if len(header) != backupHeaderBytes || !bytes.Equal(header[:8], backupMagic[:]) || header[8] < 1 || header[8] > 64 || !bytes.Equal(header[9:12], []byte{0, 0, 0}) || binary.BigEndian.Uint64(header[12:20]) != uint64(scope.BackupID) || hex.EncodeToString(header[20:52]) != scope.ManifestHash {
		return nil, "", ErrBackupInvalid
	}
	n := int(header[8])
	version := string(header[96 : 96+n])
	if !versionPattern.MatchString(version) || !bytes.Equal(header[96+n:160], make([]byte, 64-n)) {
		return nil, "", ErrBackupInvalid
	}
	key, ok := o.keys[version]
	if !ok {
		return nil, "", ErrBackupUnavailable
	}
	aead, err := gcm(key[:])
	clear(key[:])
	if err != nil {
		return nil, "", ErrBackupUnavailable
	}
	aad := append([]byte("mii/backup-wrap/v1\x00"), header[:backupHeaderPrefix]...)
	dek, err := aead.Open(nil, header[84:96], header[backupHeaderPrefix:], aad)
	if err != nil || len(dek) != 32 {
		clear(dek)
		return nil, "", ErrBackupInvalid
	}
	c := &backupCipher{headerHash: sha256.Sum256(header)}
	copy(c.dek[:], dek)
	clear(dek)
	return c, version, nil
}

func (c *backupCipher) recordCipher() (cipher.AEAD, error) {
	epoch := c.seq / backupEpochRecords
	if c.aead != nil && c.epoch == epoch {
		return c.aead, nil
	}
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], epoch)
	info := append([]byte("mii/backup-data-epoch/v1\x00"), c.headerHash[:]...)
	info = append(info, encoded[:]...)
	key, err := hkdf.Key(sha256.New, c.dek[:], nil, string(info), 32)
	if err != nil {
		return nil, ErrBackupUnavailable
	}
	defer clear(key)
	c.aead, err = gcm(key)
	c.epoch = epoch
	if err != nil {
		return nil, ErrBackupUnavailable
	}
	return c.aead, nil
}

func (c *backupCipher) aad(frame []byte) []byte {
	aad := append([]byte("mii/backup-record/v1\x00"), c.headerHash[:]...)
	return append(aad, frame...)
}
func (c *backupCipher) nonce() []byte {
	var nonce [12]byte
	copy(nonce[:4], []byte{'B', 'K', 'P', 1})
	binary.BigEndian.PutUint64(nonce[4:], c.seq)
	return nonce[:]
}

// Limits also bound control records and per-entry partial final chunks.
func backupMaxFrames(l BackupLimits) uint64 {
	if l.MaxBytes < 0 || l.MaxBytes > BackupMaxBytes || l.MaxEntries < 0 || l.MaxEntries > BackupMaxEntries {
		return 0
	}
	return uint64(l.MaxBytes/backupChunkBytes) + uint64(l.MaxEntries)*3 + 1
}
func backupWireLimit(l BackupLimits) int64 {
	return backupHeaderBytes + l.MaxBytes + (l.MaxBytes/backupChunkBytes+int64(l.MaxEntries)*3+1)*(backupFrameHeader+16) + int64(l.MaxEntries)*76 + 12
}

type backupIO struct {
	ctx         context.Context
	reader      io.Reader
	writer      io.Writer
	sum         hash.Hash
	size, limit int64
	err         error
	eof         bool
}

func (s *backupIO) check() error {
	if s.err != nil {
		return s.err
	}
	if s.ctx.Err() != nil {
		s.err = ErrBackupCanceled
	}
	return s.err
}
func (s *backupIO) fail(err error) error {
	if s.err == nil {
		s.err = err
	}
	return s.err
}

func (s *backupIO) write(data []byte) (result error) {
	defer func() {
		if recover() != nil {
			result = s.fail(ErrBackupConsumer)
		}
	}()
	if err := s.check(); err != nil {
		return err
	}
	if int64(len(data)) > s.limit-s.size {
		return s.fail(ErrBackupLimit)
	}
	for len(data) > 0 {
		part := data[:min(len(data), backupChunkBytes)]
		n, err := s.writer.Write(part)
		if n < 0 || n > len(part) {
			return s.fail(ErrBackupUnavailable)
		}
		if n > 0 {
			_, _ = s.sum.Write(part[:n])
			s.size += int64(n)
		}
		if e := s.check(); e != nil {
			return e
		}
		if err != nil || n != len(part) {
			return s.fail(ErrBackupUnavailable)
		}
		data = data[n:]
	}
	return nil
}

func (s *backupIO) readFull(data []byte) (result error) {
	defer func() {
		if recover() != nil {
			result = s.fail(ErrBackupConsumer)
		}
	}()
	if err := s.check(); err != nil {
		return err
	}
	if int64(len(data)) > s.limit-s.size {
		return s.fail(ErrBackupLimit)
	}
	for len(data) > 0 {
		if s.eof {
			return s.fail(ErrBackupInvalid)
		}
		part := data[:min(len(data), backupChunkBytes)]
		n, err := s.reader.Read(part)
		if n < 0 || n > len(part) {
			return s.fail(ErrBackupUnavailable)
		}
		if n > 0 {
			_, _ = s.sum.Write(part[:n])
			s.size += int64(n)
			data = data[n:]
		}
		if e := s.check(); e != nil {
			return e
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return s.fail(ErrBackupUnavailable)
			}
			s.eof = true
			if len(data) > 0 {
				return s.fail(ErrBackupInvalid)
			}
		} else if n == 0 {
			return s.fail(ErrBackupUnavailable)
		}
	}
	return nil
}

func (s *backupIO) requireEOF() (result error) {
	defer func() {
		if recover() != nil {
			result = s.fail(ErrBackupConsumer)
		}
	}()
	if err := s.check(); err != nil {
		return err
	}
	if s.eof {
		return nil
	}
	var extra [1]byte
	n, err := s.reader.Read(extra[:])
	clear(extra[:])
	if e := s.check(); e != nil {
		return e
	}
	if n != 0 {
		return s.fail(ErrBackupInvalid)
	}
	if !errors.Is(err, io.EOF) {
		return s.fail(ErrBackupUnavailable)
	}
	s.eof = true
	return nil
}

func (c *backupCipher) writeFrame(stream *backupIO, kind byte, entry uint32, data []byte, maxFrames uint64) error {
	if len(data) > backupChunkBytes || c.seq >= maxFrames {
		return stream.fail(ErrBackupLimit)
	}
	var frame [backupFrameHeader]byte
	frame[0] = kind
	// #nosec G115 -- len(data) was checked against the fixed 65536-byte frame ceiling above.
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(data)))
	binary.BigEndian.PutUint64(frame[8:16], c.seq)
	binary.BigEndian.PutUint32(frame[16:20], entry)
	aead, err := c.recordCipher()
	if err != nil {
		return stream.fail(err)
	}
	sealed := aead.Seal(c.buffer[:0], c.nonce(), data, c.aad(frame[:]))
	if err := stream.write(frame[:]); err != nil {
		return err
	}
	if err := stream.write(sealed); err != nil {
		return err
	}
	clear(c.buffer[:])
	c.seq++
	return nil
}

func (c *backupCipher) readFrame(stream *backupIO, maxFrames uint64) (byte, uint32, []byte, error) {
	if c.seq >= maxFrames {
		return 0, 0, nil, stream.fail(ErrBackupLimit)
	}
	var frame [backupFrameHeader]byte
	if err := stream.readFull(frame[:]); err != nil {
		return 0, 0, nil, err
	}
	kind, size, entry := frame[0], binary.BigEndian.Uint32(frame[4:8]), binary.BigEndian.Uint32(frame[16:20])
	if !bytes.Equal(frame[1:4], []byte{0, 0, 0}) || binary.BigEndian.Uint64(frame[8:16]) != c.seq || size > backupChunkBytes || (kind == backupBegin && size != 68) || (kind == backupData && (size == 0 || entry == 0)) || (kind == backupEnd && size != 8) || (kind == backupFinal && (size != 12 || entry != 0)) || kind < backupBegin || kind > backupFinal {
		return 0, 0, nil, stream.fail(ErrBackupInvalid)
	}
	sealed := c.buffer[:int(size)+16]
	if err := stream.readFull(sealed); err != nil {
		return 0, 0, nil, err
	}
	aead, err := c.recordCipher()
	if err != nil {
		return 0, 0, nil, stream.fail(err)
	}
	data, err := aead.Open(sealed[:0], c.nonce(), sealed, c.aad(frame[:]))
	if err != nil {
		clear(c.buffer[:])
		return 0, 0, nil, stream.fail(ErrBackupInvalid)
	}
	c.seq++
	return kind, entry, data, nil
}
