// Package collector は agent が各サーバーから値を集めるための最小の枠組みを定める。
//
// 収集する側（agent）と受け取る側（monitor）で実装が割れないよう、インターフェースと
// 共有ヘルパはこのパッケージ 1 箇所に置く。
package collector

import (
	"context"
	"os/exec"
	"time"
)

// Collector は各収集モジュールが実装するインターフェース
type Collector interface {
	// Name は collector の識別名を返す（agent.toml の jobs キーと一致させる）
	Name() string
	// Collect はデータを収集して JSON エンコード可能な値を返す
	// 取得不可の場合は (nil, nil) を返す（Monitor 側で null として扱われる）
	Collect(cfg Config) (interface{}, error)
}

// Config は各 collector へ渡す設定のサブセット
type Config struct {
	AgentID string
	HomeDir string
	WWWDir  string
	LogDir  string
}

// RunWithTimeout は name コマンドを timeout 付き（context.WithTimeout + exec.CommandContext）で
// 実行し標準出力を返す。rental Agent の collector は ctx を受け取らないため、ハングし得る
// 外部コマンド（df/ps/hostname/uname/sysctl/crontab 等）は本関数経由で実行し、無期限ブロックを防ぐ
// （C1: exec-no-timeout-blocks-loop）。
func RunWithTimeout(timeout time.Duration, name string, args ...string) ([]byte, error) {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Output()
}

// shutdownCh は rental Agent のシャットダウン（ctx.Done()）を collector の待機処理へ伝える。
// rental は one-shot だが Runtime.TimeoutSec で全体に ctx タイムアウトが張られるため、
// cpu collector の 1 秒サンプリング待ちを中断可能にする（C1: blocking-sleep-ignores-shutdown）。
var shutdownCh <-chan struct{}

// SetShutdownCh は rental main から shutdown シグナル（ctx.Done()）を登録する。
func SetShutdownCh(ch <-chan struct{}) {
	shutdownCh = ch
}

// ShutdownCh は登録済み shutdown チャネルを返す。未登録時は決して閉じないチャネルを返す。
func ShutdownCh() <-chan struct{} {
	if shutdownCh == nil {
		return neverClosed
	}
	return shutdownCh
}

var neverClosed = make(chan struct{})

// IsExcludedDiskFSType は fstype が仮想/擬似ファイルシステムとして disk 集計から
// 除外すべきかを返す（C5: disk-filter-inconsistent-dev）。VPS 側 system collector の
// 除外集合と意味を揃える。FreeBSD の devfs/procfs 等も含む。
func IsExcludedDiskFSType(fstype string) bool {
	switch fstype {
	case "tmpfs", "devtmpfs", "squashfs", "overlay", "overlayfs", "ramfs",
		"devfs", "fdescfs", "procfs", "linprocfs", "linsysfs", "nullfs":
		return true
	}
	return false
}

// location は収集結果の時刻を表示するタイムゾーン。既定は実行ホストのローカル時刻。
//
// Config へフィールドを足さずにパッケージ変数で持つのは、collector のインターフェースを
// 呼び出し側ごとに変えないため（shutdown チャネルと同じ方式）。ログ行に含まれる
// オフセット自体は解釈に使われるので、この設定が効くのは出力の表示形式だけ。
var location = time.Local

// SetLocation は収集結果の時刻表示に使うタイムゾーンを差し替える。agent の起動時に
// 1 回だけ呼ぶ。呼ばなければ実行ホストのローカル時刻を使う。
func SetLocation(loc *time.Location) {
	if loc != nil {
		location = loc
	}
}

// Location は現在設定されているタイムゾーンを返す。
func Location() *time.Location { return location }
