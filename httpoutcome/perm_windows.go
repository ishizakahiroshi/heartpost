//go:build windows

package httpoutcome

import "os"

// Windows mode bits do not express ACLs, so owner and mode are not checked.
func checkOwnerAndMode(string, os.FileInfo, []uint32) error { return nil }

func checkAncestor(string, os.FileInfo, []uint32) error { return nil }
