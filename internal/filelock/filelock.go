// Package filelock は「同じ設定で agent が二重に走らない」ことだけを担う。
//
// agent は cron から one-shot で起動される。前回の実行が長引いているところへ
// 次の起動が重なると、同じログファイルへ両者が書き、同じ収集を二重に送る。
// ロックはそれを止めるためだけにあり、待たない（取れなければ ErrLocked を返して即座に諦める）。
// cron はどうせ次の周期でまた起動するので、待って詰まらせるより落ちたほうが安全。
package filelock

import (
	"errors"
	"fmt"
	"os"
)

// ErrLocked はロックが他プロセスに保持されていて取得できなかったことを表す sentinel error。
//
// open 失敗（権限不足・パス不正）と区別できるようにしてあるのは、呼び出し側が
// 「既に走っているので今回は何もしない」と「設定が壊れている」を別物として扱うため。
// 判定は errors.Is(err, ErrLocked) で行う。
var ErrLocked = errors.New("filelock: already locked")

// Acquire は path に排他ロックを取得する（非ブロッキング）。
// 取得できたら解放用のクロージャを返す。競合時は ErrLocked を返す。
//
// ロックファイル自体は意図的に削除しない。ロックは Close で解放されるので
// ファイルが残っていても次回の取得に支障はなく、削除と解放の競合を避けられる。
func Acquire(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
	}, nil
}

// TryAcquire は Acquire の別名。呼び出し側で「待たない取得」であることを明示したいときに使う。
func TryAcquire(path string) (func(), error) {
	return Acquire(path)
}
