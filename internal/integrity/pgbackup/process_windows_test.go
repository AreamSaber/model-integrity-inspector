//go:build windows

package pgbackup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func configureNativeTestChild(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
}

func observeNativeTestProcess(pid int) (func() bool, func(), error) {
	if pid <= 0 || uint64(pid) > 1<<32-1 {
		return nil, nil, ErrConfiguration
	}
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return nil, nil, err
	}
	return func() bool {
		state, err := windows.WaitForSingleObject(handle, 0)
		return err != nil || state != windows.WAIT_OBJECT_0
	}, func() { _ = windows.CloseHandle(handle) }, nil
}

func nativeTestPlatformHelper() bool {
	raw, err := strconv.ParseUint(os.Getenv("MII_NATIVE_HANDLE_CANARY"), 10, 64)
	if err != nil {
		return false
	}
	// SetEvent would signal the parent's exact event if this arbitrary
	// inheritable handle escaped the explicit HANDLE_LIST.
	_ = windows.SetEvent(windows.Handle(raw))
	return true
}

func TestNativeProcessWindowsHandleAllowlist(t *testing.T) {
	security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	event, err := windows.CreateEvent(&security, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if windows.CloseHandle(event) != nil {
			t.Error("close canary event")
		}
	}()
	spec := nativeTestSpec(t, "platform")
	spec.env = append(spec.env, "MII_NATIVE_HANDLE_CANARY="+strconv.FormatUint(uint64(event), 10))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = executeNative(ctx, spec); err != nil {
		t.Fatal(err)
	}
	state, err := windows.WaitForSingleObject(event, 0)
	if err != nil || state != uint32(windows.WAIT_TIMEOUT) {
		t.Fatal("non-allowlisted inheritable handle reached child")
	}
}

func TestNativeProcessWindowsHandlesAreReleased(t *testing.T) {
	getCount := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessHandleCount")
	count := func() uint32 {
		t.Helper()
		var result uint32
		ok, _, _ := getCount.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&result))) // #nosec G103 -- Test passes one uint32 output buffer to documented GetProcessHandleCount.
		if ok == 0 {
			t.Fatal("GetProcessHandleCount failed")
		}
		return result
	}
	spec := nativeTestSpec(t, "empty")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// Warm Go runtime and lazy syscalls before measuring. Do not GC afterwards:
	// finalizers must not mask leaked handles from the measured executions.
	var warm sync.WaitGroup
	warmErrors := make(chan error, 10)
	for range 10 {
		warm.Go(func() { warmErrors <- executeNative(ctx, spec) })
	}
	warm.Wait()
	for range 10 {
		if err := <-warmErrors; err != nil {
			t.Fatal(err)
		}
	}
	before := count()
	threadsBefore := nativeTestThreadCount(t)
	for i := range 20 {
		current := spec
		var want error
		switch i % 4 {
		case 1:
			current.env = []string{nativeHelperMode + "=nonzero"}
			want = ErrProcess
		case 2:
			current.env = []string{nativeHelperMode + "=flood"}
			current.stdout = &nativeFailWriter{mode: "limit"}
			want = ErrLimit
		case 3:
			current.dir = filepath.Join(spec.dir, "nonexistent-workdir")
			want = ErrProcess
		}
		if err := executeNative(ctx, current); err != want { //nolint:errorlint // Measured lifecycle paths must return their exact closed outcomes.
			t.Fatalf("lifecycle measurement got %v, want %v", err, want)
		}
	}
	after := count()
	threadsAfter := nativeTestThreadCount(t)
	if after > before {
		t.Fatalf("native handle count grew: before=%d after=%d threadsBefore=%d threadsAfter=%d", before, after, threadsBefore, threadsAfter)
	}
}

func nativeTestThreadCount(t *testing.T) uint32 {
	t.Helper()
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if windows.CloseHandle(snapshot) != nil {
			t.Error("close thread snapshot")
		}
	}()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	count := uint32(0)
	for err = windows.Thread32First(snapshot, &entry); err == nil; err = windows.Thread32Next(snapshot, &entry) {
		if entry.OwnerProcessID == windows.GetCurrentProcessId() {
			count++
		}
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		t.Fatal("thread enumeration failed")
	}
	return count
}

func TestNativeProcessWindowsInventoryChangesAreNotPartialSuccess(t *testing.T) {
	for _, counts := range [][2]uint32{{1, 0}, {0, 1}} {
		t.Run(strconv.Itoa(int(counts[0]))+"-"+strconv.Itoa(int(counts[1])), func(t *testing.T) {
			calls := 0
			list, err := nativeWindowsCoherentJobList(func(list *nativeWindowsJobList) error {
				calls++
				if calls == 1 {
					list.assigned, list.count = counts[0], counts[1]
					return nil
				}
				list.assigned, list.count, list.pids[0] = 1, 1, 42
				return nil
			}, time.Now().Add(time.Second))
			if err != nil || calls != 2 || list.assigned != 1 || list.count != 1 || list.pids[0] != 42 {
				t.Fatalf("partial/changing inventory accepted: calls=%d assigned=%d count=%d err=%v", calls, list.assigned, list.count, err)
			}
		})
	}
	for _, kind := range []string{"assigned-capacity", "count-capacity", "native-error", "persistent-change"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			list, err := nativeWindowsCoherentJobList(func(list *nativeWindowsJobList) error {
				calls++
				switch kind {
				case "assigned-capacity":
					list.assigned, list.count = 1025, 1024
				case "count-capacity":
					list.assigned, list.count = 1024, 1025
				case "native-error":
					return windows.ERROR_ACCESS_DENIED
				default:
					list.assigned, list.count = 1, 0
				}
				return nil
			}, time.Now().Add(30*time.Millisecond))
			if !errors.Is(err, ErrProcess) || list != (nativeWindowsJobList{}) || calls == 0 || (kind != "persistent-change" && calls != 1) {
				t.Fatalf("invalid inventory accepted or wrong operation retried: calls=%d err=%v", calls, err)
			}
		})
	}
}
