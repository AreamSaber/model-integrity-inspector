//go:build linux

package pgbackup

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func configureNativeTestChild(*exec.Cmd) {}

func nativeTestPlatformHelper() bool { return false }

func observeNativeTestProcess(pid int) (func() bool, func(), error) {
	path := "/proc/" + strconv.Itoa(pid) + "/stat"
	initial, err := os.ReadFile(path) // #nosec G304 -- Test-only /proc/<decimal owned helper PID>/stat, no user-controlled path components.
	if err != nil {
		return nil, nil, err
	}
	identity := nativeProcessStat(initial)
	return func() bool {
		current, err := os.ReadFile(path) // #nosec G304 -- Same fixed procfs identity path as the initial observation.
		if os.IsNotExist(err) {
			return false
		}
		if err != nil {
			return true
		}
		fields := nativeProcessStat(current)
		return len(fields) < 20 || len(identity) < 20 || (fields[19] == identity[19] && fields[0] != "Z" && fields[0] != "X")
	}, func() {}, nil
}

func nativeProcessStat(data []byte) []string {
	text := string(data)
	end := strings.LastIndex(text, ")")
	if end < 0 {
		return nil
	}
	return strings.Fields(text[end+1:])
}
