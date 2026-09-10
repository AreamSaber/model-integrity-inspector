//go:build !linux && !windows

package app

import "testing"

func backupCompletionPrivateDirectory(t *testing.T) string {
	t.Helper()
	t.Fatal("backup completion native fixture unsupported platform")
	return ""
}
