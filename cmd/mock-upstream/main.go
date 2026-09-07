// mock-upstream is a development-only synthetic server, not a production proxy.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"time"

	mockupstream "model-integrity-inspector.local/mii/tests/mock-upstream"
)

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return runWithContext(ctx, args, output)
}

func runWithContext(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("mock-upstream", flag.ContinueOnError)
	flags.SetOutput(output)
	addr := flags.String("addr", "127.0.0.1:8090", "literal loopback address only")
	configPath := flags.String("config", "", "test-controller scenario JSON file (never expose to detector)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := validateAddress(*addr); err != nil {
		return err
	}
	for _, name := range []string{"APP_ENV", "MII_ENV"} {
		if strings.EqualFold(os.Getenv(name), "production") {
			return errors.New("mock upstream is disabled in production")
		}
	}
	config := mockupstream.Config{Seed: 1}
	if *configPath != "" {
		file, err := os.Open(*configPath)
		if err != nil {
			return errors.New("cannot open scenario configuration")
		}
		defer func() { _ = file.Close() }()
		encoded, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		if readErr != nil || len(encoded) > 64<<10 {
			return errors.New("scenario configuration exceeds the 64 KiB limit")
		}
		decoder := json.NewDecoder(bytes.NewReader(encoded))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&config); err != nil {
			return errors.New("invalid scenario configuration")
		}
		if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
			return errors.New("scenario configuration must contain one JSON object")
		}
	}
	handler, err := mockupstream.NewHandler(config)
	if err != nil {
		return fmt.Errorf("scenario configuration: %w", err)
	}
	listenerConfig := net.ListenConfig{}
	listener, err := listenerConfig.Listen(ctx, "tcp", *addr)
	if err != nil {
		return errors.New("cannot bind mock loopback listener")
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	_, _ = fmt.Fprintf(output, "Synthetic test server listening on %s; no real model calls or HTTP control endpoints.\n", listener.Addr())
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}

func validateAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("addr must be a literal loopback IP and port")
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("mock upstream refuses non-loopback listeners")
	}
	return nil
}
