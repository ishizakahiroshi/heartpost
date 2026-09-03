//go:build windows

package filelock

import (
	"os"
	"syscall"
	"unsafe"
)

// Windows の LockFileEx / UnlockFileEx を直接引く。
// 標準の syscall パッケージはこの 2 本を公開しておらず、公開しているのは
// golang.org/x/sys/windows のほうだが、この道具は依存を増やさない方針なので
// kernel32 から自分で取る。
var (
	kernel32     = syscall.NewLazyDLL("kernel32.dll")
	procLockFile = kernel32.NewProc("LockFileEx")
	procUnlock   = kernel32.NewProc("UnlockFileEx")
)

const (
	lockfileFailImmediately = 0x00000001
	lockfileExclusiveLock   = 0x00000002

	// errorLockViolation は既に他プロセスがロックしているときに返る Win32 エラー。
	errorLockViolation = syscall.Errno(33)
)

// lockFile はファイル全域にバイト範囲ロックを取る（非ブロッキング）。
//
// Windows 版があるのは本番のためではなく（対象は FreeBSD / Linux）、
// 開発機でも二重起動防止の挙動をそのまま検証できるようにするため。
// no-op にすると「開発機では素通りするのに本番でだけ弾かれる」差が生まれる。
func lockFile(f *os.File) error {
	ol := new(syscall.Overlapped)
	r, _, err := procLockFile.Call(
		f.Fd(),
		uintptr(lockfileExclusiveLock|lockfileFailImmediately),
		0,
		uintptr(^uint32(0)),
		uintptr(^uint32(0)),
		uintptr(unsafe.Pointer(ol)),
	)
	if r == 0 {
		if errno, ok := err.(syscall.Errno); ok && errno == errorLockViolation {
			return ErrLocked
		}
		return err
	}
	return nil
}

func unlockFile(f *os.File) error {
	ol := new(syscall.Overlapped)
	r, _, err := procUnlock.Call(
		f.Fd(),
		0,
		uintptr(^uint32(0)),
		uintptr(^uint32(0)),
		uintptr(unsafe.Pointer(ol)),
	)
	if r == 0 {
		return err
	}
	return nil
}
