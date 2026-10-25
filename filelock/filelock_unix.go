//go:build !windows

package filelock

import (
	"errors"
	"os"
	"syscall"
)

// lockFile は flock(2) の排他ロックを非ブロッキングで取る。
// 対象は FreeBSD の共有ホスティングを含むので、fcntl ではなく flock を使う
// （NFS 上のホームでも共有ホスティング側で flock が使えることを前提にする）。
func lockFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return ErrLocked
		}
		return err
	}
	return nil
}

func unlockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}
