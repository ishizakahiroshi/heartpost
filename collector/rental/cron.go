package rental

import (
	"strings"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type CronCollector struct{}

type CronData struct {
	Lines []string `json:"lines"`
}

func (c *CronCollector) Name() string { return "cron" }

// Collect は `crontab -l` を実行して cron ジョブ一覧（コメント行・空行含む）を返す。
// crontab が未設定の場合は空スライスを返す（エラー扱いしない）。
func (c *CronCollector) Collect(cfg collector.Config) (interface{}, error) {
	out, err := runCommand("crontab", "-l")
	if err != nil {
		// "no crontab for user" は error 扱いしない
		return &CronData{Lines: []string{}}, nil
	}

	raw := strings.TrimSpace(out)
	if raw == "" {
		return &CronData{Lines: []string{}}, nil
	}

	lines := strings.Split(raw, "\n")
	return &CronData{Lines: lines}, nil
}
