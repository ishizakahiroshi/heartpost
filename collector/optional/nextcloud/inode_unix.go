//go:build unix

package nextcloud

import (
	"os"
	"syscall"
)

// statInode は info の inode を返す（取れなければ 0）。
func statInode(info os.FileInfo) uint64 {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
