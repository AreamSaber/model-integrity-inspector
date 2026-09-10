//go:build linux

package app

import "testing"

func backupPublicationPrivateDirectory(t *testing.T) string {
	t.Helper()
	return backupCompletionPrivateDirectory(t)
}
