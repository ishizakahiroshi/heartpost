// Package nc_extract summarizes configured extracted JSONL events.
// Nextcloud ログ抽出モジュール有効時（collectors.jobs.nc_extract = true）のみ動作する。
//
// nc_extract JSONL はサーバー側の event-extractor プロセスが生成する:
//   - login_events.jsonl  — ログインイベント（成功/失敗）
//   - login_context.jsonl — ブルートフォース等の付随コンテキスト
package nc_extract

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

type Collector struct{}

func (c *Collector) Name() string     { return "nc_extract" }
func (c *Collector) Interval() string { return "log" }

type loginEventRecord struct {
	TS     string `json:"ts"`
	Result string `json:"result"` // "success" | "fail"
	User   string `json:"user"`
	IP     string `json:"ip"`
}

// CollectResult は Monitor へ送るサマリー
type CollectResult struct {
	LoginEventsPath  string `json:"login_events_path"`
	LoginContextPath string `json:"login_context_path"`
	TotalLoginEvents int    `json:"total_login_events"`
	SuccessCount     int    `json:"success_count"`
	FailCount        int    `json:"fail_count"`
}

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	dir := cfg.Paths.NcExtractDir
	if dir == "" {
		return nil, nil
	}

	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, nil
	}

	loginPath := filepath.Join(dir, "login_events.jsonl")
	contextPath := filepath.Join(dir, "login_context.jsonl")

	total, success, fail := countLoginEvents(loginPath)

	return &CollectResult{
		LoginEventsPath:  loginPath,
		LoginContextPath: contextPath,
		TotalLoginEvents: total,
		SuccessCount:     success,
		FailCount:        fail,
	}, nil
}

func countLoginEvents(path string) (total, success, fail int) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	// 監視側 TailJSONL に合わせて 512KiB。1 行が上限を超えると bufio.ErrTooLong で
	// 走査が黙って打ち切られ、成功/失敗集計が過小になる事故を避けるため sc.Err() も確認。
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		var rec loginEventRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		total++
		switch strings.ToLower(rec.Result) {
		case "success":
			success++
		case "fail", "failed":
			fail++
		}
	}
	if err := sc.Err(); err != nil {
		log.Printf("WARN: nc_extract: scanner %s: %v", path, err)
	}
	return
}
