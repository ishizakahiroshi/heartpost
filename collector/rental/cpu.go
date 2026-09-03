package rental

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type CPUCollector struct{}

type CPUData struct {
	UsagePercent float64 `json:"usage_percent"`
}

func (c *CPUCollector) Name() string { return "cpu" }

// Collect は sysctl kern.cp_time を 1 秒間隔で 2 回サンプリングし、
// USER+NICE+SYSTEM+INTR の差分 / 全 tick 差分 で CPU 使用率を算出する。
// FreeBSD 出力形式: "kern.cp_time: 2219621341 27231495 816752141 97671951 41682851720"
// フィールド順: USER NICE SYSTEM INTR IDLE
func (c *CPUCollector) Collect(cfg collector.Config) (interface{}, error) {
	ticks1, err := readCPTicks()
	if err != nil {
		return nil, err
	}

	// 1 秒のサンプリング間隔。素の time.Sleep は ctx タイムアウト（Runtime.TimeoutSec）を
	// 無視して必ず完走するため、shutdown チャネルを見る select で中断可能にする
	// （C1: blocking-sleep-ignores-shutdown）。
	select {
	case <-time.After(1 * time.Second):
	case <-collector.ShutdownCh():
		return nil, fmt.Errorf("cpu collect interrupted by shutdown")
	}

	ticks2, err := readCPTicks()
	if err != nil {
		return nil, err
	}

	var busy, total int64
	for i := 0; i < 5; i++ {
		delta := ticks2[i] - ticks1[i]
		total += delta
		if i != 4 { // IDLE は index 4
			busy += delta
		}
	}

	if total == 0 {
		return nil, fmt.Errorf("cpu tick delta is zero")
	}

	usage := float64(busy) / float64(total) * 100.0
	// 小数点2桁に丸める
	usage, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", usage), 64)

	return &CPUData{UsagePercent: usage}, nil
}

func readCPTicks() ([5]int64, error) {
	var ticks [5]int64

	out, err := runCommand("sysctl", "kern.cp_time")
	if err != nil {
		return ticks, err
	}

	// "kern.cp_time: 2219621341 27231495 816752141 97671951 41682851720"
	line := strings.TrimSpace(out)
	idx := strings.Index(line, ":")
	if idx < 0 {
		return ticks, fmt.Errorf("unexpected kern.cp_time output: %q", out)
	}

	fields := strings.Fields(strings.TrimSpace(line[idx+1:]))
	if len(fields) < 5 {
		return ticks, fmt.Errorf("expected 5 fields in kern.cp_time, got %d: %q", len(fields), out)
	}

	for i := 0; i < 5; i++ {
		v, err := strconv.ParseInt(fields[i], 10, 64)
		if err != nil {
			return ticks, fmt.Errorf("parse kern.cp_time field[%d] %q: %w", i, fields[i], err)
		}
		ticks[i] = v
	}

	return ticks, nil
}
