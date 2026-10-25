//go:build !unix

package nextcloud

import "os"

// statInode は inode を取れない環境（Windows 等）では 0 を返す。0 のときは大きさだけで切り替えを見る。
func statInode(info os.FileInfo) uint64 { return 0 }
