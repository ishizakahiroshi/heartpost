//go:build windows

package httpoutcome

import "os"

// Windows mode bits do not express ACLs, so owner and mode are not checked.
func checkOwnerAndMode(string, os.FileInfo) error { return nil }
