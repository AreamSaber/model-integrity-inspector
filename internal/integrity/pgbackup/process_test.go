//go:build windows || linux

package pgbackup

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const nativeHelperMode = "MII_NATIVE_PROCESS_TEST_MODE"

func nativeTestSpec(t *testing.T, mode string) nativeProcessSpec {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return nativeProcessSpec{path: executable, args: []string{"-test.run=^TestNativeProcessHelper$", "--"},
		env: []string{nativeHelperMode + "=" + mode}, dir: t.TempDir(), stdout: io.Discard, stderr: io.Discard}
}

func TestNativeProcessHelper(t *testing.T) {
	mode := os.Getenv(nativeHelperMode)
	if mode == "" {
		return
	}
	switch mode {
	case "inspect":
		input, err := io.ReadAll(io.LimitReader(os.Stdin, 1))
		if err != nil || len(input) != 0 {
			os.Exit(23)
		}
		dir, err := os.Getwd()
		if err != nil {
			os.Exit(24)
		}
		value := struct {
			Args        []string
			Canary, Dir string
		}{os.Args[3:], os.Getenv("MII_NATIVE_PARENT_CANARY"), dir}
		if json.NewEncoder(os.Stdout).Encode(value) != nil {
			os.Exit(25)
		}
	case "streams":
		var wait sync.WaitGroup
		for i, writer := range []io.Writer{os.Stdout, os.Stderr} {
			wait.Go(func() {
				block := bytes.Repeat([]byte{[]byte("AB")[i]}, 4096)
				for range 64 {
					if _, err := writer.Write(block); err != nil {
						os.Exit(26)
					}
				}
			})
		}
		wait.Wait()
	case "nonzero":
		_, _ = fmt.Fprintln(os.Stderr, "MII_NATIVE_DIAGNOSTIC_SECRET_CANARY")
		os.Exit(27)
	case "flood":
		go func() {
			block := bytes.Repeat([]byte("E"), 65536)
			for {
				if _, err := os.Stderr.Write(block); err != nil {
					os.Exit(28)
				}
			}
		}()
		block := bytes.Repeat([]byte("O"), 65536)
		for {
			if _, err := os.Stdout.Write(block); err != nil {
				os.Exit(29)
			}
		}
	case "tree", "branch", "leaf", "tree_exit":
		if _, err := fmt.Fprintf(os.Stdout, "pid=%d\n", os.Getpid()); err != nil {
			os.Exit(30)
		}
		if mode != "leaf" {
			next := "leaf"
			if mode == "tree" || mode == "tree_exit" {
				next = "branch"
			}
			executable, err := os.Executable()
			if err != nil {
				os.Exit(37)
			}
			//nolint:noctx // Deliberately unmanaged descendants prove the production executor, not a helper context, terminates the entire tree.
			child := exec.Command(executable, "-test.run=^TestNativeProcessHelper$", "--") // #nosec G204 -- Tests execute this exact Go test binary, never shell/user input.
			child.Env = []string{nativeHelperMode + "=" + next}
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
			var readiness *os.File
			if mode == "tree_exit" {
				read, write, err := os.Pipe()
				if err != nil {
					os.Exit(33)
				}
				readiness, child.Stdout = read, write
			}
			configureNativeTestChild(child)
			if child.Start() != nil {
				os.Exit(31)
			}
			if mode == "tree_exit" {
				// Forward actual branch + grandchild readiness, then exit without
				// waiting for either one. No guessed startup delay.
				scanner := bufio.NewScanner(readiness)
				for range 2 {
					if !scanner.Scan() {
						os.Exit(34)
					}
					if _, err := fmt.Fprintln(os.Stdout, scanner.Text()); err != nil {
						os.Exit(35)
					}
				}
				for {
					if _, err := os.Stat("parent-exit.ack"); err == nil {
						break
					}
					time.Sleep(time.Millisecond)
				}
				os.Exit(0)
			}
		}
		for {
			time.Sleep(time.Hour)
		}
	case "empty":
	case "platform":
		if !nativeTestPlatformHelper() {
			os.Exit(36)
		}
	default:
		os.Exit(32)
	}
	os.Exit(0)
}

func TestNativeProcessExplicitEnvironmentArgumentsDirectoryAndStdin(t *testing.T) {
	t.Setenv("MII_NATIVE_PARENT_CANARY", "MUST_NOT_INHERIT")
	spec := nativeTestSpec(t, "inspect")
	want := []string{"", "with spaces", `a\"b`, `trailing space\`, "引号与中文", "line\nnext", "&echo;$(no-shell)", `\\host\folder\`}
	spec.args = append(spec.args, want...)
	var stdout, stderr bytes.Buffer
	spec.stdout, spec.stderr = &stdout, &stderr
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := executeNative(ctx, spec); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Args        []string
		Canary, Dir string
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Args, want) || got.Canary != "" || !strings.EqualFold(got.Dir, spec.dir) || stderr.Len() != 0 {
		t.Fatalf("explicit argv/env/cwd/stdin contract failed: args=%v canaryPresent=%v sameDir=%v stderrBytes=%d", got.Args, got.Canary != "", strings.EqualFold(got.Dir, spec.dir), stderr.Len())
	}
}

func TestNativeProcessDrainsBothStreams(t *testing.T) {
	spec := nativeTestSpec(t, "streams")
	var stdout, stderr bytes.Buffer
	spec.stdout, spec.stderr = &stdout, &stderr
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := executeNative(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stdout.Bytes(), bytes.Repeat([]byte("A"), 256<<10)) || !bytes.Equal(stderr.Bytes(), bytes.Repeat([]byte("B"), 256<<10)) {
		t.Fatalf("incomplete streams: stdout=%d stderr=%d", stdout.Len(), stderr.Len())
	}
}

func TestNativeProcessClosedFailures(t *testing.T) {
	for _, mode := range []string{"nonzero", "missing"} {
		t.Run(mode, func(t *testing.T) {
			spec := nativeTestSpec(t, mode)
			if mode == "missing" {
				spec.path = filepath.Join(spec.dir, "absent-executable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := executeNative(ctx, spec); err != ErrProcess { //nolint:errorlint // Exact closed value is required: wrappers could expose diagnostics.
				t.Fatalf("got %v, want closed process error", err)
			}
		})
	}
}

type nativeFailWriter struct {
	mode           string
	bytes, largest int
}

func (writer *nativeFailWriter) Write(data []byte) (int, error) {
	writer.bytes += len(data)
	writer.largest = max(writer.largest, len(data))
	switch writer.mode {
	case "panic":
		panic("MII_NATIVE_WRITER_PANIC_SECRET")
	case "short":
		return len(data) - 1, nil
	case "limit":
		return 0, fmt.Errorf("MII_NATIVE_WRITER_SECRET: %w", ErrLimit)
	default:
		return 0, errors.New("MII_NATIVE_WRITER_SECRET")
	}
}

func TestNativeProcessOutputFailureKillsAndJoins(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		for _, mode := range []string{"panic", "short", "limit", "error"} {
			t.Run(stream+"/"+mode, func(t *testing.T) {
				spec := nativeTestSpec(t, "flood")
				writer := &nativeFailWriter{mode: mode}
				if stream == "stdout" {
					spec.stdout = writer
				} else {
					spec.stderr = writer
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				want := ErrOutput
				if mode == "limit" {
					want = ErrLimit
				}
				if err := executeNative(ctx, spec); err != want { //nolint:errorlint // Reject wrapped writer errors containing private messages.
					t.Fatalf("got %v, want %v", err, want)
				}
				if writer.bytes == 0 || writer.largest > 32<<10 {
					t.Fatalf("copy was absent or unbounded: bytes=%d largest=%d", writer.bytes, writer.largest)
				}
			})
		}
	}
}

type nativePIDWriter struct {
	pending string
	pids    chan int
}

func (writer *nativePIDWriter) Write(data []byte) (int, error) {
	writer.pending += string(data)
	for {
		line, rest, found := strings.Cut(writer.pending, "\n")
		if !found {
			break
		}
		writer.pending = rest
		pid, err := strconv.Atoi(strings.TrimPrefix(line, "pid="))
		if err != nil || pid <= 0 {
			return 0, ErrOutput
		}
		select {
		case writer.pids <- pid:
		default:
			return 0, ErrLimit
		}
	}
	if len(writer.pending) > 128 {
		return 0, ErrLimit
	}
	return len(data), nil
}

func TestNativeProcessCancellationTerminatesGrandchildren(t *testing.T) {
	spec := nativeTestSpec(t, "tree")
	writer := &nativePIDWriter{pids: make(chan int, 3)}
	spec.stdout = writer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- executeNative(ctx, spec) }()
	var checks []func() bool
	for range 3 {
		select {
		case pid := <-writer.pids:
			alive, closeObserver, err := observeNativeTestProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			defer closeObserver()
			if !alive() {
				t.Fatal("child was not actually running before cancellation")
			}
			checks = append(checks, alive)
		case err := <-result:
			t.Fatalf("executor exited before three generation handshake: %v", err)
		case <-ctx.Done():
			t.Fatal("no three generation handshake")
		}
	}
	cancel()
	select {
	case err := <-result:
		if err != ErrCanceled { //nolint:errorlint // Exact closed cancellation error is part of the boundary.
			t.Fatalf("got %v", err)
		}
	case <-time.After(12 * time.Second):
		t.Fatal("canceled executor did not join cleanup")
	}
	for i, alive := range checks {
		if alive() {
			t.Fatalf("generation %d survived cancellation", i)
		}
	}
}

func TestNativeProcessParentExitCannotLeaveGrandchildren(t *testing.T) {
	spec := nativeTestSpec(t, "tree_exit")
	ack := filepath.Join(spec.dir, "parent-exit.ack")
	writer := &nativePIDWriter{pids: make(chan int, 3)}
	spec.stdout = writer
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- executeNative(ctx, spec) }()
	var checks []func() bool
	for range 3 {
		select {
		case pid := <-writer.pids:
			alive, closeObserver, err := observeNativeTestProcess(pid)
			if err != nil {
				t.Fatal(err)
			}
			defer closeObserver()
			if !alive() {
				t.Fatal("child was not running before parent exit")
			}
			checks = append(checks, alive)
		case <-ctx.Done():
			t.Fatal("missing three generation readiness")
		}
	}
	if err := os.WriteFile(ack, []byte("exit"), 0600); err != nil {
		t.Fatal(err)
	}
	var err error
	select {
	case err = <-result:
	case <-ctx.Done():
		t.Fatal("executor hung after parent exit")
	}
	if err != nil && (runtime.GOOS != "linux" || err != ErrProcess) { //nolint:errorlint // Only a closed cleanup error is allowed, not OS diagnostics.
		t.Fatalf("unexpected cleanup result %v", err)
	}
	// Linux may fail closed if init retains orphan zombies; it still must not
	// leave a running descendant. Windows Job accounting must reach zero.
	for index, alive := range checks {
		if alive() {
			t.Fatalf("generation %d still has an unsignaled process handle after parent's exit", index)
		}
	}
}

func TestNativeProcessInvalidConfigurationDoesNotStart(t *testing.T) {
	for _, field := range []string{"nil-context", "no-deadline", "too-long", "relative-path", "relative-dir", "nil-env", "nul-arg", "bad-env", "duplicate-env", "nil-writer", "typed-nil-writer", "canceled"} {
		t.Run(field, func(t *testing.T) {
			spec := nativeTestSpec(t, "nonzero")
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			want := ErrConfiguration
			switch field {
			case "nil-context":
				ctx = nil
			case "no-deadline":
				ctx = context.Background()
			case "too-long":
				var extra context.CancelFunc
				ctx, extra = context.WithTimeout(context.Background(), 25*time.Hour)
				defer extra()
			case "relative-path":
				spec.path = "relative.exe"
			case "relative-dir":
				spec.dir = "."
			case "nil-env":
				spec.env = nil
			case "nul-arg":
				spec.args = append(spec.args, "bad\x00arg")
			case "bad-env":
				spec.env = []string{"INVALID"}
			case "duplicate-env":
				spec.env = []string{"MiI=v1", "MII=v2"}
			case "nil-writer":
				spec.stdout = nil
			case "typed-nil-writer":
				var buffer *bytes.Buffer
				spec.stdout = buffer
			case "canceled":
				cancel()
				want = ErrCanceled
			}
			if err := executeNative(ctx, spec); err != want { //nolint:errorlint // Configuration and cancellation must return exact closed values.
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}

func TestNativeProcessJoinClosesBlockedRead(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = write.Close() }()
	streams := make(chan error, 1)
	go pumpNativeStream(read, io.Discard, streams)
	closed := false
	result := joinNativeStreams(streams, 1, nil, func() {
		closed = true
		if err := read.Close(); err != nil {
			t.Errorf("close blocked read: %v", err)
		}
	})
	if !closed || !errors.Is(result, ErrProcess) {
		t.Fatalf("blocked pipe wasn't joined after cleanup failure: closed=%v result=%v", closed, result)
	}
}
