package bundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"sync"
)

type backupDependencyReadState struct {
	mu             sync.Mutex
	ctx            context.Context
	cancel         context.CancelFunc
	source         BackupDependencySource
	called, closed bool
	active         chan struct{}
	err            error
	body           []byte
}

func backupDependencyCall(fn func() error) (err error) {
	returned := false
	defer func() {
		if !returned {
			_ = recover()
			err = ErrBackupDependencyRead
		}
	}()
	err = fn()
	returned = true
	return err
}

func readBackupDependencySource(ctx context.Context, cancel context.CancelFunc, source BackupDependencySource, read func(context.Context, func(io.Reader) error) error) ([]byte, error) {
	s := &backupDependencyReadState{ctx: ctx, cancel: cancel, source: source}
	outer := backupDependencyCall(func() error { return read(ctx, s.consume) })
	s.mu.Lock()
	s.closed = true
	active := s.active
	if outer != nil || !s.called || active != nil || ctx.Err() != nil {
		s.err = ErrBackupDependencyRead
	}
	if active != nil {
		cancel()
	}
	s.mu.Unlock()
	if active != nil {
		<-active
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil || ctx.Err() != nil {
		clear(s.body)
		s.body = nil
		return nil, ErrBackupDependencyRead
	}
	body := s.body
	s.body = nil
	return body, nil
}

func (s *backupDependencyReadState) consume(r io.Reader) (err error) {
	s.mu.Lock()
	if s.closed || s.called || s.ctx.Err() != nil {
		s.err = ErrBackupDependencyRead
		s.cancel()
		s.mu.Unlock()
		return ErrBackupDependencyClosed
	}
	s.called = true
	s.active = make(chan struct{})
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if err != nil || s.ctx.Err() != nil {
			s.err = ErrBackupDependencyRead
			clear(s.body)
			s.body = nil
		}
		close(s.active)
		s.active = nil
		s.mu.Unlock()
	}()
	err = backupDependencyCall(func() error {
		if r == nil {
			return ErrBackupDependencyRead
		}
		var buffer [64 << 10]byte
		defer clear(buffer[:])
		var body []byte
		if s.source.Bytes <= MaxArtifactBytes {
			body = make([]byte, 0, int(s.source.Bytes))
		}
		defer func() { clear(body) }()
		h := sha256.New()
		var total int64
		for {
			if s.ctx.Err() != nil {
				return ErrBackupDependencyRead
			}
			// Read at most the exact remaining bytes plus one EOF/overflow probe.
			n, readErr := r.Read(buffer[:min(int64(len(buffer)), s.source.Bytes-total+1)])
			if n < 0 || n > len(buffer) || int64(n) > s.source.Bytes-total {
				return ErrBackupDependencyRead
			}
			if n > 0 {
				_, _ = h.Write(buffer[:n])
				if body != nil {
					body = append(body, buffer[:n]...)
				}
				total += int64(n)
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					return ErrBackupDependencyRead
				}
				break
			}
			if n == 0 {
				return ErrBackupDependencyRead
			}
		}
		if s.ctx.Err() != nil || total != s.source.Bytes || hex.EncodeToString(h.Sum(nil)) != s.source.SHA256 {
			return ErrBackupDependencyRead
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.err != nil || s.closed {
			return ErrBackupDependencyRead
		}
		s.body = body
		body = nil
		return nil
	})
	return err
}
