//go:build linux

package main

import "os"

// #nosec G302 -- private directory needs owner traversal, not public file access.
func protectCLITestDirectory(path string) error { return os.Chmod(path, 0o700) }
