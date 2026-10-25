// honeypot パッケージは Agent honeypot JSONL を集計し、詳細 events を Monitor に送る。
// 1レコードのフォーマット:
//
//	{"ts":"...","ip":"...","method":"GET","path":"...","query":"...","trigger":"...","is_whitelisted":false,"headers":{...}}
package honeypot

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

type Collector struct{}

func (c *Collector) Name() string     { return "honeypot" }
func (c *Collector) Interval() string { return "security" }

type hpRecord struct {
	Schema        string            `json:"schema"`
	TS            string            `json:"ts"`
	IP            string            `json:"ip"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Trigger       string            `json:"trigger"`
	IsWhitelisted bool              `json:"is_whitelisted"`
	Headers       map[string]string `json:"headers"`
	PostBody      string            `json:"post_body,omitempty"`
	DedupeKey     string            `json:"dedupe_key,omitempty"`
}

// CollectResult は Monitor へ送るサマリー
type CollectResult struct {
	TotalHits     int            `json:"total_hits"`
	UniqueIPs     int            `json:"unique_ips"`
	TriggerCounts map[string]int `json:"trigger_counts"`
	TopIPs        []IPCount      `json:"top_ips"`
	RecentHits    []hpRecord     `json:"recent_hits"`
	NewEvents     int            `json:"new_events"`
	Events        []hpRecord     `json:"events"`
	JSONLPath     string         `json:"jsonl_path"`
	PeriodDays    int            `json:"period_days"`
}

type IPCount struct {
	IP    string `json:"ip"`
	Count int    `json:"count"`
}

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	jsonlPath := cfg.Honeypot.JSONLPath
	if jsonlPath == "" {
		if cfg.Paths.DataDir == "" {
			return nil, nil
		}
		jsonlPath = filepath.Join(cfg.Paths.DataDir, "logs", "honeypot.jsonl")
	}
	if _, err := os.Stat(jsonlPath); os.IsNotExist(err) {
		if cfg.Paths.DataDir == "" {
			return nil, nil
		}
		legacyDir := filepath.Join(cfg.Paths.DataDir, "json", "honeypot")
		if _, err := os.Stat(legacyDir); os.IsNotExist(err) {
			return nil, nil
		}
		cutoff := time.Now().AddDate(0, 0, -cfg.Rules.HoneypotDays)
		records, err := loadRecords(legacyDir, cutoff)
		if err != nil {
			return nil, fmt.Errorf("load legacy honeypot records: %w", err)
		}
		return buildResult(records, cfg.Rules.HoneypotDays, legacyDir), nil
	} else if err != nil {
		// ハニーポット未導入環境では (nil, nil) を返す
		return nil, nil
	}

	cutoff := time.Now().AddDate(0, 0, -cfg.Rules.HoneypotDays)
	records, err := readJSONL(jsonlPath, cutoff)
	if err != nil {
		return nil, fmt.Errorf("load honeypot records: %w", err)
	}

	return buildResult(records, cfg.Rules.HoneypotDays, jsonlPath), nil
}

func loadRecords(dir string, cutoff time.Time) ([]hpRecord, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var records []hpRecord
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".jsonl" {
			continue
		}
		recs, err := readJSONL(filepath.Join(dir, e.Name()), cutoff)
		if err != nil {
			continue
		}
		records = append(records, recs...)
	}
	return records, nil
}

func readJSONL(path string, cutoff time.Time) ([]hpRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var records []hpRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 512*1024), 512*1024)
	for sc.Scan() {
		var r hpRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, r.TS)
		if err != nil {
			continue
		}
		if t.Before(cutoff) {
			continue
		}
		records = append(records, r)
	}
	return records, sc.Err()
}

func buildResult(records []hpRecord, periodDays int, jsonlPath string) *CollectResult {
	triggerCounts := make(map[string]int)
	ipCounts := make(map[string]int)

	for _, r := range records {
		if r.Trigger != "" {
			triggerCounts[r.Trigger]++
		}
		if r.IP != "" {
			ipCounts[r.IP]++
		}
	}

	// Top10 IP
	type kv struct {
		k string
		v int
	}
	var sorted []kv
	for k, v := range ipCounts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	top := 10
	if len(sorted) < top {
		top = len(sorted)
	}
	topIPs := make([]IPCount, top)
	for i := 0; i < top; i++ {
		topIPs[i] = IPCount{IP: sorted[i].k, Count: sorted[i].v}
	}

	// 直近20件（末尾）
	recent := records
	if len(recent) > 20 {
		recent = recent[len(recent)-20:]
	}
	events := records
	if len(events) > 200 {
		events = events[len(events)-200:]
	}

	return &CollectResult{
		TotalHits:     len(records),
		UniqueIPs:     len(ipCounts),
		TriggerCounts: triggerCounts,
		TopIPs:        topIPs,
		RecentHits:    recent,
		NewEvents:     len(events),
		Events:        events,
		JSONLPath:     jsonlPath,
		PeriodDays:    periodDays,
	}
}
