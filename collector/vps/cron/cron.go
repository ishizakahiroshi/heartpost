package cron

import (
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

type CronData struct {
	Lines []string `json:"lines"`
}

func (c *Collector) Name() string { return "cron" }

// Collect は crontab -l を実行する。未設定・エラーの場合は空スライスを返す。
// crontab のハング防止に RunWithTimeout 経由で実行する（C1: exec-no-timeout-blocks-loop）。
func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	out, err := collector.RunWithTimeout(5*time.Second, "crontab", "-l")
	if err != nil {
		return &CronData{Lines: []string{}}, nil
	}

	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return &CronData{Lines: []string{}}, nil
	}

	return &CronData{Lines: strings.Split(raw, "\n")}, nil
}
