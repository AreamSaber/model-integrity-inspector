//go:build !windows

package capturefixture

import "os"

func protectCaptureDirectory(path string) error {
	// Owner traversal is necessary for a private directory, not a key file.
	return os.Chmod(path, 0o700) // #nosec G302 -- private test-owned directory.
}
