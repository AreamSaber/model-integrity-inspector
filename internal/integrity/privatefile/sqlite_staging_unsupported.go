//go:build !linux && !windows

package privatefile

func newSQLiteStaging(string) (sqliteStagingNative, error) { return nil, ErrFilesystem }
