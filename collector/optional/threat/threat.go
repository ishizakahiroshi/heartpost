// threat パッケージは data/csv/threat_score.csv を読み込んで Monitor に送る。
// CSV フォーマット（v3）:
//
//	timestamp,ip,score,scan_hits,scan_criticals,auth_fails,nc_fails,nc_4xx,is_banned,is_foreign
//	2026-04-20 15:30:45,203.0.113.1,85,12,2,5,3,1,0,1
package threat

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

type Collector struct{}

func (c *Collector) Name() string     { return "threat" }
func (c *Collector) Interval() string { return "security" }

type ThreatEntry struct {
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	Score     int    `json:"score"`
	ScanHits  int    `json:"scan_hits"`
	ScanCrits int    `json:"scan_criticals"`
	AuthFails int    `json:"auth_fails"`
	NcFails   int    `json:"nc_fails"`
	Nc4xx     int    `json:"nc_4xx"`
	IsBanned  bool   `json:"is_banned"`
	IsForeign bool   `json:"is_foreign"`
}

type CollectResult struct {
	Entries   []ThreatEntry `json:"entries"`
	TotalIPs  int           `json:"total_ips"`
	BannedIPs int           `json:"banned_ips"`
	TopScores []ThreatEntry `json:"top_scores"`
}

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	if cfg.Paths.DataDir == "" {
		return nil, nil
	}
	csvPath := filepath.Join(cfg.Paths.DataDir, "csv", "threat_score.csv")
	if _, err := os.Stat(csvPath); os.IsNotExist(err) {
		return nil, nil
	}

	entries, err := loadCSV(csvPath)
	if err != nil {
		return nil, fmt.Errorf("load threat_score.csv: %w", err)
	}

	return buildResult(entries), nil
}

func loadCSV(csvPath string) ([]ThreatEntry, error) {
	f, err := os.Open(csvPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(bufio.NewReader(f))
	r.Comment = '#'
	r.TrimLeadingSpace = true
	// 列数の揺れる 1 行（書き込み途中の不完全行等）で ReadAll 全体が error になり
	// 全エントリが欠落するのを防ぐ。行ごとの妥当性は下の len(row)<10 スキップで担保。
	// Monitor/alerts 側の正準リーダーと挙動を揃える。
	r.FieldsPerRecord = -1

	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	var entries []ThreatEntry
	for _, row := range rows {
		// ヘッダ行をスキップ
		if len(row) == 0 || row[0] == "timestamp" {
			continue
		}
		e, ok := parseRow(row)
		if !ok {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

func parseRow(row []string) (ThreatEntry, bool) {
	// 最低10列必要
	if len(row) < 10 {
		return ThreatEntry{}, false
	}
	score, err := strconv.Atoi(row[2])
	if err != nil {
		return ThreatEntry{}, false
	}
	return ThreatEntry{
		Timestamp: row[0],
		IP:        row[1],
		Score:     score,
		ScanHits:  parseInt(row[3]),
		ScanCrits: parseInt(row[4]),
		AuthFails: parseInt(row[5]),
		NcFails:   parseInt(row[6]),
		Nc4xx:     parseInt(row[7]),
		IsBanned:  row[8] == "1",
		IsForeign: row[9] == "1",
	}, true
}

func parseInt(s string) int {
	v, _ := strconv.Atoi(s)
	return v
}

func buildResult(entries []ThreatEntry) *CollectResult {
	banned := 0
	for _, e := range entries {
		if e.IsBanned {
			banned++
		}
	}

	// スコア降順でTop10
	sorted := make([]ThreatEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Score > sorted[j].Score })
	top := 10
	if len(sorted) < top {
		top = len(sorted)
	}

	return &CollectResult{
		Entries:   entries,
		TotalIPs:  len(entries),
		BannedIPs: banned,
		TopScores: sorted[:top],
	}
}
