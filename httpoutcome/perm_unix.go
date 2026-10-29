//go:build !windows

package httpoutcome

import (
	"fmt"
	"os"
	"syscall"
)

func ownerUID(path string, fi os.FileInfo) (uint32, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%s: cannot read owner", path)
	}
	return st.Uid, nil
}

func uidAllowed(uid uint32, owners []uint32, allowRoot bool) bool {
	if uid == uint32(os.Getuid()) || (allowRoot && uid == 0) {
		return true
	}
	for _, o := range owners {
		if o == uid {
			return true
		}
	}
	return false
}

// checkOwnerAndMode accepts files and directories owned by the current user or
// by a uid in owners, and never group/world writable.
func checkOwnerAndMode(path string, fi os.FileInfo, owners []uint32) error {
	uid, err := ownerUID(path, fi)
	if err != nil {
		return err
	}
	if !uidAllowed(uid, owners, false) {
		return fmt.Errorf("%s is not owned by the current user or a trusted owner", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group or world writable", path)
	}
	return nil
}

// checkAncestor vets a directory above the immediate parent.
func checkAncestor(path string, fi os.FileInfo, owners []uint32) error {
	uid, err := ownerUID(path, fi)
	if err != nil {
		return err
	}
	if !uidAllowed(uid, owners, true) {
		return fmt.Errorf("%s has an untrusted owner", path)
	}
	if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%s is group or world writable", path)
	}
	return nil
}
