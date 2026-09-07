package safehttp

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (conn *idleConn) Read(buffer []byte) (int, error) {
	if err := conn.SetReadDeadline(time.Now().Add(conn.timeout)); err != nil {
		return 0, err
	}
	return conn.Conn.Read(buffer)
}

type limitedBody struct {
	reader    io.Reader
	closer    io.Closer
	remaining int64
	cancel    context.CancelFunc
	ctx       context.Context
	once      sync.Once
	terminal  error
}

func (body *limitedBody) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	if body.terminal != nil {
		return 0, body.terminal
	}
	if body.ctx != nil && body.ctx.Err() != nil {
		return body.finish(0, body.ctx.Err())
	}
	if body.remaining == 0 {
		// Read one byte to distinguish exactly-at-limit EOF from truncated data.
		var probe [1]byte
		n, err := body.reader.Read(probe[:])
		if n > 0 {
			body.terminal = ErrSafetyLimit
			_ = body.Close()
			return 0, ErrSafetyLimit
		}
		if err != nil {
			return body.finish(0, err)
		}
		return 0, nil
	}
	if int64(len(buffer)) > body.remaining {
		buffer = buffer[:body.remaining]
	}
	n, err := body.reader.Read(buffer)
	body.remaining -= int64(n)
	if err != nil {
		return body.finish(n, err)
	}
	return n, nil
}

func (body *limitedBody) finish(n int, err error) (int, error) {
	if body.ctx != nil && body.ctx.Err() != nil && !errors.Is(err, ErrSafetyLimit) {
		err = body.ctx.Err()
	}
	if errors.Is(err, io.EOF) {
		body.terminal = io.EOF
	} else {
		body.terminal = sanitized(err)
	}
	_ = body.Close()
	return n, body.terminal
}

func (body *limitedBody) Close() error {
	body.once.Do(func() {
		_ = body.closer.Close()
		body.cancel()
	})
	return nil
}

type gzipBody struct {
	*gzip.Reader
	raw io.Closer
}

func (body *gzipBody) Close() error {
	_ = body.Reader.Close()
	return body.raw.Close()
}
