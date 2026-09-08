//go:build !windows && !linux

package privatefile

import "os"

func validatePath(string) error                        { return ErrFilesystem }
func openDirectory(string) (*os.File, error)           { return nil, ErrFilesystem }
func validateDirectory(*os.File) error                 { return ErrFilesystem }
func openInput(*os.File, string) (*os.File, error)     { return nil, ErrFilesystem }
func createTemp(*os.File, string) (*os.File, error)    { return nil, ErrFilesystem }
func validateFile(*os.File) error                      { return ErrFilesystem }
func publish(*os.File, *os.File, string, string) error { return ErrFilesystem }
func removeTemp(*os.File, *os.File, string) error      { return ErrFilesystem }
func syncDirectory(*os.File) error                     { return ErrFilesystem }
