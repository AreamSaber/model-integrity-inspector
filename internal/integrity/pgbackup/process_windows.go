//go:build windows

package pgbackup

import (
	"context"
	"errors"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinSDK WinBase.h: ProcThreadAttributeJobList = 13; the Input bit is
// PROC_THREAD_ATTRIBUTE_INPUT = 0x00020000. Unlike post-Start AssignProcess,
// this attribute assigns the job before the initial thread can execute.
const procThreadAttributeJobList = 0x0002000d

var nativeIsProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

type nativeJobAccounting struct {
	totalUserTime, totalKernelTime, thisPeriodUserTime, thisPeriodKernelTime  int64
	totalPageFaultCount, totalProcesses, activeProcesses, terminatedProcesses uint32
}

type nativeWindowsJobList struct {
	assigned, count uint32
	pids            [1024]uintptr
}

func executeNative(ctx context.Context, spec nativeProcessSpec) (result error) {
	if err := validateNativeProcess(ctx, spec); err != nil {
		return err
	}
	closeHandle := func(handle windows.Handle) {
		if err := windows.CloseHandle(handle); err != nil && result == nil {
			result = ErrProcess
		}
	}
	closeFile := func(file *os.File) {
		if err := file.Close(); err != nil && result == nil {
			result = ErrProcess
		}
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return ErrProcess
	}
	defer func() {
		if job != 0 {
			closeHandle(job)
		}
	}()
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if err = nativeWindowsSetJobLimits(job, &limits); err != nil {
		return ErrProcess
	}
	var reads [3]*os.File
	var writes [3]windows.Handle
	for i := range reads {
		var read windows.Handle
		security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
		if err = windows.CreatePipe(&read, &writes[i], &security, 0); err != nil {
			return ErrProcess
		}
		reads[i] = os.NewFile(uintptr(read), "private process pipe")
		defer closeFile(reads[i])
		defer func(i int) {
			if writes[i] != 0 {
				closeHandle(writes[i])
			}
		}(i)
		// stdin's read end is the only inherited read handle.
		if i != 0 {
			if err = windows.SetHandleInformation(read, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
				return ErrProcess
			}
		}
	}
	// EOF on stdin, never a console or an inherited interactive input stream.
	closeHandle(writes[0])
	writes[0] = 0
	if result != nil {
		return result
	}
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return ErrProcess
	}
	defer attributes.Delete()
	handles := [3]windows.Handle{windows.Handle(reads[0].Fd()), writes[1], writes[2]}
	if err = attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&handles[0]), unsafe.Sizeof(handles)); err != nil { // #nosec G103 -- Three owned handles; attribute container retains this pointer through CreateProcess.
		return ErrProcess
	}
	if err = attributes.Update(procThreadAttributeJobList, unsafe.Pointer(&job), unsafe.Sizeof(job)); err != nil { // #nosec G103 -- Owned job handle; attribute container retains this pointer through CreateProcess.
		return ErrProcess
	}
	info := windows.StartupInfoEx{StartupInfo: windows.StartupInfo{
		Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{})), Flags: windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE, StdInput: handles[0], StdOutput: handles[1], StdErr: handles[2],
	}, ProcThreadAttributeList: attributes.List()}
	app, err := windows.UTF16PtrFromString(spec.path)
	if err != nil {
		return ErrConfiguration
	}
	line := windows.ComposeCommandLine(append([]string{spec.path}, spec.args...))
	command, err := windows.UTF16FromString(line)
	if err != nil || len(command) > 32767 {
		return ErrConfiguration
	}
	directory, err := windows.UTF16PtrFromString(spec.dir)
	if err != nil {
		return ErrConfiguration
	}
	environment := nativeWindowsEnvironment(spec.env)
	defer clear(environment)
	process := windows.ProcessInformation{}
	if ctx.Err() != nil {
		return ErrCanceled
	}
	if err = windows.CreateProcess(app, &command[0], nil, nil, true,
		windows.CREATE_NO_WINDOW|windows.CREATE_UNICODE_ENVIRONMENT|windows.EXTENDED_STARTUPINFO_PRESENT,
		&environment[0], directory, &info.StartupInfo, &process); err != nil {
		return nativeResult(ctx, ErrProcess)
	}
	defer closeHandle(process.Process)
	defer closeHandle(process.Thread)
	// Parent copies of pipe write handles must close before waiting for EOF.
	for i := 1; i < 3; i++ {
		closeHandle(writes[i])
		writes[i] = 0
	}
	streams := make(chan error, 2)
	go pumpNativeStream(reads[1], spec.stdout, streams)
	go pumpNativeStream(reads[2], spec.stderr, streams)
	pending := 2
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for result == nil {
		state, waitErr := windows.WaitForSingleObject(process.Process, 0)
		if waitErr != nil {
			result = ErrProcess
			break
		}
		if state == windows.WAIT_OBJECT_0 {
			var code uint32
			if windows.GetExitCodeProcess(process.Process, &code) != nil || code != 0 {
				result = ErrProcess
			}
			break
		}
		select {
		case <-ctx.Done():
			result = ErrCanceled
		case streamErr := <-streams:
			pending--
			if streamErr != nil {
				result = streamErr
			}
		case <-ticker.C:
		}
	}
	// A successful parent is insufficient: kill any remaining descendants, then
	// verify actual Job ActiveProcesses == 0. No breakaway flags were enabled.
	until := time.Now().Add(nativeCleanupTimeout)
	members, memberErr := nativeWindowsJobMembers(job, until)
	for _, member := range members {
		defer closeHandle(member)
	}
	if memberErr != nil && result == nil {
		result = ErrProcess
	}
	if err = windows.TerminateJobObject(job, 1); err != nil && result == nil {
		result = ErrProcess
	}
	confirmedEmpty := false
	for {
		accounting := nativeJobAccounting{}
		err = nativeWindowsQueryJob(job, windows.JobObjectBasicAccountingInformation,
			unsafe.Pointer(&accounting), uint32(unsafe.Sizeof(accounting))) // #nosec G103 -- Fixed accounting ABI output buffer, pinned across the syscall.
		if err != nil || time.Now().After(until) {
			if result == nil {
				result = ErrProcess
			}
			break
		}
		if accounting.activeProcesses == 0 {
			confirmedEmpty = true
			for _, member := range members {
				state, err := windows.WaitForSingleObject(member, 0)
				if err != nil || state != windows.WAIT_OBJECT_0 {
					confirmedEmpty = false
					break
				}
			}
			if confirmedEmpty {
				break
			}
		}
		<-ticker.C
	}
	closeReads := func() { closeFile(reads[1]); closeFile(reads[2]) }
	if !confirmedEmpty {
		// KILL_ON_JOB_CLOSE remains a fallback, not proof of completion. Close
		// it before joining streams: a surviving descendant may hold a write end.
		closeHandle(job)
		job = 0
		closeReads()
	}
	state, waitErr := windows.WaitForSingleObject(process.Process, uint32(nativeCleanupTimeout/time.Millisecond))
	if (waitErr != nil || state != windows.WAIT_OBJECT_0) && result == nil {
		result = ErrProcess
	}
	result = joinNativeStreams(streams, pending, result, closeReads)
	return nativeResult(ctx, result)
}

func nativeWindowsJobMembers(job windows.Handle, until time.Time) ([]windows.Handle, error) {
	// The pinned custom-format pg_dump does not parallelize. Bound the native
	// member inventory; overflow is a failure, not a partial successful cleanup.
	list, err := nativeWindowsCoherentJobList(func(list *nativeWindowsJobList) error {
		return nativeWindowsQueryJob(job, windows.JobObjectBasicProcessIdList,
			unsafe.Pointer(list), uint32(unsafe.Sizeof(*list))) // #nosec G103 -- Bounded pinned ABI header/array; returned counts are validated before slicing.
	}, until)
	if err != nil {
		return nil, ErrProcess
	}
	result := make([]windows.Handle, 0, list.count)
	for _, pid := range list.pids[:list.count] {
		if pid == 0 || uint64(pid) > 1<<32-1 {
			return result, ErrProcess
		}
		handle, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			continue
		}
		if err != nil {
			return result, ErrProcess
		}
		result = append(result, handle)
		// The PID may have exited/recycled since inventory. Validate the actual
		// opened handle against our Job before waiting; never signal this PID.
		var belongs uint32
		ok, _, _ := nativeIsProcessInJob.Call(uintptr(handle), uintptr(job), uintptr(unsafe.Pointer(&belongs))) // #nosec G103 -- Documented IsProcessInJob BOOL output, owned handle and job.
		if ok == 0 || belongs == 0 {
			return result, ErrProcess
		}
	}
	return result, nil
}

func nativeWindowsCoherentJobList(query func(*nativeWindowsJobList) error, until time.Time) (nativeWindowsJobList, error) {
	// Never accept a successful query with an inconsistent header as complete.
	// Re-read that owned inventory within the SAME cleanup deadline, rather than
	// making a partial list appear empty. This does not attribute the observed
	// inconsistency to a particular OS race. Never grow the fixed cap or retry a
	// native API/capacity error.
	for {
		var list nativeWindowsJobList
		if !time.Now().Before(until) || query(&list) != nil ||
			list.assigned > uint32(len(list.pids)) || list.count > uint32(len(list.pids)) {
			return nativeWindowsJobList{}, ErrProcess
		}
		if list.assigned == list.count {
			return list, nil
		}
		pause := min(10*time.Millisecond, time.Until(until))
		if pause <= 0 {
			return nativeWindowsJobList{}, ErrProcess
		}
		time.Sleep(pause)
	}
}

func nativeWindowsQueryJob(job windows.Handle, class int32, buffer unsafe.Pointer, size uint32) error {
	// x/sys exposes this parameter as uintptr. Pin before converting so Go
	// stack growth or GC during the wrapper/lazy-procedure lookup cannot make
	// an invisible stack pointer stale. KeepAlive alone does not pin a stack.
	var pin runtime.Pinner
	pin.Pin(buffer)
	defer pin.Unpin()
	return windows.QueryInformationJobObject(job, class, uintptr(buffer), size, nil)
}

func nativeWindowsSetJobLimits(job windows.Handle, limits *windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION) error {
	var pin runtime.Pinner
	pin.Pin(limits)
	defer pin.Unpin()
	_, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(limits)), uint32(unsafe.Sizeof(*limits))) // #nosec G103 -- Fixed limits ABI struct explicitly pinned through the uintptr wrapper.
	return err
}

func nativeWindowsEnvironment(entries []string) []uint16 {
	entries = append([]string{}, entries...)
	sort.Slice(entries, func(i, j int) bool { return strings.ToUpper(entries[i]) < strings.ToUpper(entries[j]) })
	var block []uint16
	for _, entry := range entries {
		block = append(block, utf16.Encode([]rune(entry))...)
		block = append(block, 0)
	}
	block = append(block, 0)
	if len(entries) == 0 {
		block = append(block, 0)
	}
	return block
}
