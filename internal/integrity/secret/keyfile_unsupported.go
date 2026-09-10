//go:build !windows && !aix && !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris

package secret

import "os"

func openRestrictedKeyFile(string, bool) (*os.File, error) { return nil, ErrUnavailable }
func validateKeyHandle(*os.File) error                     { return ErrUnavailable }
