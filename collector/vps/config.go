// Package vps は Linux の VPS 向け collector をまとめる。
//
// monitor を載せるサーバー自身も見たいので、共有ホスティング向けの rental と別に
// この一式を持つ。特定の製品（グループウェア・チャット基盤など）に紐づく収集は
// ここには置かない。置くと「その製品を使っていない人には常に空の項目」が増える。
package vps

import "github.com/ishizakahiroshi/heartpost/collector"

// Config は vps collector 群へ渡す設定。
//
// 汎用に保つため、**特定の製品名を持つフィールドを足さない**。監視したいサービスは
// ServiceNames に systemd のユニット名で並べる。ログの場所も製品ごとの定数ではなく
// パスで受け取る。
type Config struct {
	// AgentID は送信元の識別子。ログの出力先を分けるのに使う。
	AgentID string

	// ServiceNames は systemctl で状態を見るユニット名の一覧。
	// 例: ["nginx", "sshd", "cron"]
	ServiceNames []string

	// Paths は読みたいログとデータの置き場。空なら該当 collector は取得不可として nil を返す。
	Paths PathConfig

	// Rules は各ログを何行さかのぼるか。0 なら collector 側の既定を使う。
	Rules RulesConfig

	// Domain は SSL 証明書を確認する対象ドメイン。空なら ssl collector は何も返さない。
	Domain string

	// RenewTimer は証明書更新タイマーの systemd ユニット名。空なら certbot.timer を見る。
	RenewTimer string
}

// PathConfig は collector が読むファイルとディレクトリ。
type PathConfig struct {
	// AuthLog は SSH の認証ログ（例: /var/log/auth.log）。
	AuthLog string
	// NginxLog は nginx のアクセスログ（例: /var/log/nginx/access.log）。
	NginxLog string
	// DataDir は collector が前回値や抽出結果を置く作業ディレクトリ。
	DataDir string
}

// RulesConfig は各ログをさかのぼる行数。
type RulesConfig struct {
	AuthLogLines  int
	NginxLogLines int
}

// Collector は vps collector が実装するインターフェース。
//
// 共有コアの collector.Collector と形が違うのは、渡す設定が違うだけ。
// agent 側では Adapt で共通の形へ包んで 1 本のリストに並べる。
type Collector interface {
	// Name は collector の識別名。agent.toml の [collectors.jobs] のキーと一致させる。
	Name() string
	// Collect はデータを集める。取得対象が無い場合は (nil, nil) を返す。
	Collect(cfg Config) (interface{}, error)
}

// Adapt は vps collector を共有コアのインターフェースへ包む。
// vps 側の設定はここで閉じ込めるので、agent は rental と vps を同じリストで扱える。
func Adapt(c Collector, cfg Config) collector.Collector {
	return &adapter{inner: c, cfg: cfg}
}

type adapter struct {
	inner Collector
	cfg   Config
}

func (a *adapter) Name() string { return a.inner.Name() }

func (a *adapter) Collect(_ collector.Config) (interface{}, error) {
	return a.inner.Collect(a.cfg)
}
