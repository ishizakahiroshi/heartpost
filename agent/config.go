package agent

import (
	"fmt"
	"github.com/ishizakahiroshi/heartpost/report"
	"io/fs"
	"path/filepath"
)

// secretsFileName は API キーだけを分けて置くためのファイル名。
// agent.toml の隣に置いてあれば読み込み、同じキーは後勝ちで上書きする。
const secretsFileName = "agent_secrets.toml"

// AgentConfig は agent.toml（＋ agent_secrets.toml）の内容。
//
// セクションを増やすほど「どこに何を書くのか」を人が読み違える。共有ホスティング側で
// 必要なのは先頭 5 セクションだけで、[vps] は agent.type = "vps" のときにしか読まれない。
type AgentConfig struct {
	Agent struct {
		ID    string `toml:"id"`
		Label string `toml:"label"`
		Type  string `toml:"type"`
	} `toml:"agent"`

	Monitor struct {
		Endpoint       string `toml:"endpoint"`
		Path           string `toml:"path"`
		APIKey         string `toml:"api_key"`
		HTTPTimeoutSec int    `toml:"http_timeout_sec"`
		RetryCount     int    `toml:"retry_count"`
	} `toml:"monitor"`

	Runtime struct {
		LogFile     string `toml:"log_file"`
		LogMaxBytes int64  `toml:"log_max_bytes"`
		TimeoutSec  int    `toml:"timeout_sec"`
	} `toml:"runtime"`

	Collectors struct {
		Jobs map[string]bool `toml:"jobs"`
	} `toml:"collectors"`

	Paths struct {
		HomeDir string `toml:"home_dir"`
		WWWDir  string `toml:"www_dir"`
		LogDir  string `toml:"log_dir"`
	} `toml:"paths"`

	// VPS は agent.type = "vps" のときだけ使う。共有ホスティングでは丸ごと不要。
	VPS struct {
		ServiceNames  []string `toml:"service_names"`
		AuthLog       string   `toml:"auth_log"`
		NginxLog      string   `toml:"nginx_log"`
		DataDir       string   `toml:"data_dir"`
		AuthLogLines  int      `toml:"auth_log_lines"`
		NginxLogLines int      `toml:"nginx_log_lines"`

		HTTPOutcomeLogs     []string `toml:"http_outcome_logs"`
		HTTPOutcomeLogLines int      `toml:"http_outcome_log_lines"`
		Domain              string   `toml:"domain"`
		RenewTimer          string   `toml:"renew_timer"`
	} `toml:"vps"`

	// ConfigDir は agent.toml が置かれているディレクトリ。ロックファイルの
	// 置き場所を決めるときの最後のよりどころに使う。
	ConfigDir string `toml:"-"`
}

// loadConfig は agent.toml を読み、隣に agent_secrets.toml があればマージする。
//
// 第 2 戻り値はログ出力したい警告。ロガーは設定を読んでからでないと組み立てられないので、
// 設定読み込み中に気づいたことはここで返して、呼び出し側がログへ流す。
func LoadConfig(configPath string) (*AgentConfig, []string, error) {
	cfg := &AgentConfig{}
	warnings, err := DecodeConfig(configPath, cfg, ConfigReadOptions{CheckSecretsPermissions: true})
	if err != nil {
		return nil, nil, err
	}
	cfg.ConfigDir = filepath.Dir(configPath)

	if err := cfg.Validate(); err != nil {
		return nil, nil, err
	}
	return cfg, warnings, nil
}

// checkSecretsPerm は鍵ファイルのパーミッションを検査する。
//
// 共有ホスティングは他人と同居しているホストで、ホームの下が同一 OS 上の
// 別ユーザーから読める設定になっていることがある。API キーが漏れると
// 他人が自分の名前でレポートを投げられるので、600 以外は起動そのものを止める。
// 警告に落とさず起動を拒否するのは、警告はログに流れて誰も見ないため。
//
// Windows はこの mode ビットが実際の ACL を表さない（os.Chmod は読み取り専用属性しか
// 動かさない）ので、判定できないことを警告して素通りさせる。開発機での実行を
// 止めないためで、本番の対象 OS ではない。
func CheckSecretsPerm(path string, mode fs.FileMode, goos string) (string, error) {
	if goos == "windows" {
		return fmt.Sprintf("cannot verify permissions of %s on windows; make sure it is not readable by other users", path), nil
	}
	if perm := mode.Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf(
			"%s is readable by group or others (mode %04o); this file holds the API key on a shared host. run: chmod 600 %s",
			path, perm, path)
	}
	return "", nil
}

// validate は必須項目を確かめ、省略された項目に既定値を入れる。
func (c *AgentConfig) Validate() error {
	if c.Agent.ID == "" {
		return fmt.Errorf("agent.id is required")
	}
	if c.Agent.Type == "" {
		c.Agent.Type = "rental"
	}
	if c.Agent.Type != "rental" && c.Agent.Type != "vps" {
		return fmt.Errorf("agent.type は rental か vps のいずれか（実際の値: %q）", c.Agent.Type)
	}
	if c.Monitor.Path == "" {
		c.Monitor.Path = report.DefaultPath
	}
	if c.Monitor.HTTPTimeoutSec <= 0 {
		c.Monitor.HTTPTimeoutSec = 10
	}
	if c.Monitor.RetryCount < 0 {
		c.Monitor.RetryCount = 0
	}
	if c.Runtime.TimeoutSec <= 0 {
		c.Runtime.TimeoutSec = 30
	}
	if c.Runtime.LogMaxBytes <= 0 {
		c.Runtime.LogMaxBytes = 5 * 1024 * 1024
	}
	// endpoint が空のときは送らない（dry-run）。送るつもりなのに鍵が無い設定は、
	// 送信時まで気づけないと cron のログに毎回 401 が並ぶだけなので起動時に止める。
	if c.Monitor.Endpoint != "" && c.Monitor.APIKey == "" {
		return fmt.Errorf("monitor.api_key is required when monitor.endpoint is set (put it in %s)", secretsFileName)
	}
	return nil
}

// collectorEnabled は [collectors.jobs] に false と書かれていない collector を有効とみなす。
// 未記載を既定で有効にするのは、collector が増えたときに設定を書き直さなくても拾えるようにするため。
func (c *AgentConfig) CollectorEnabled(name string) bool {
	return JobEnabled(c.Collectors.Jobs, name)
}

// JobEnabled uses the existing default-on jobs policy.
func JobEnabled(jobs map[string]bool, name string) bool {
	enabled, exists := jobs[name]
	return !exists || enabled
}

// lockPath は二重起動防止に使うロックファイルの場所を返す。
// ログと同じ場所 → ホーム配下 → 設定ファイルの隣、の順に落とす。
func (c *AgentConfig) LockPath() string {
	if c.Runtime.LogFile != "" {
		return filepath.Join(filepath.Dir(c.Runtime.LogFile), "heartpost-agent.lock")
	}
	if c.Paths.HomeDir != "" {
		return filepath.Join(c.Paths.HomeDir, "heartpost", "heartpost-agent.lock")
	}
	return filepath.Join(c.ConfigDir, "heartpost-agent.lock")
}
