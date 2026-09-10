//go:build !windows && !linux

package app

import "testing"

func backupPublicationPrivateDirectory(t *testing.T) string {
	t.Helper()
	t.Fatal("publication fixture platform unsupported")
	return ""
}
