//go:build !windows

package httpoutcome

import (
	"fmt"
	"os"
	"syscall"
)

func checkOwnerAndMode(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read owner", path)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user", path)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group or world writable", path)
	}
	return nil
}
