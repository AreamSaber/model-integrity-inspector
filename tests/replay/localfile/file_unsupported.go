//go:build !windows && !linux

package localfile

import "os"

func validatePath(string) error                        { return ErrFilesystem }
func openDirectory(string, bool) (*os.File, error)     { return nil, ErrFilesystem }
func openInput(*os.File, string) (*os.File, error)     { return nil, ErrFilesystem }
func createTemp(*os.File, string) (*os.File, error)    { return nil, ErrFilesystem }
func validateFile(*os.File) error                      { return ErrFilesystem }
func publish(*os.File, *os.File, string, string) error { return ErrFilesystem }
func removeTemp(*os.File, *os.File, string) error      { return ErrFilesystem }
func syncDirectory(*os.File) error                     { return ErrFilesystem }
