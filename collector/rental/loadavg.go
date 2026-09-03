package rental

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type LoadavgCollector struct{}

type LoadavgData struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

func (l *LoadavgCollector) Name() string { return "loadavg" }

// Collect は `sysctl -n vm.loadavg` を実行して parse する。
// FreeBSD の出力形式: { 0.12 0.34 0.56 }
func (l *LoadavgCollector) Collect(cfg collector.Config) (interface{}, error) {
	out, err := runCommand("sysctl", "-n", "vm.loadavg")
	if err != nil {
		return nil, err
	}

	raw := strings.TrimSpace(out)
	// "{ 0.12 0.34 0.56 }" → ["0.12", "0.34", "0.56"]
	raw = strings.TrimPrefix(raw, "{")
	raw = strings.TrimSuffix(raw, "}")
	fields := strings.Fields(raw)
	if len(fields) < 3 {
		return nil, fmt.Errorf("unexpected vm.loadavg output: %q", out)
	}

	parse := func(s string) (float64, error) {
		return strconv.ParseFloat(s, 64)
	}

	load1, err := parse(fields[0])
	if err != nil {
		return nil, err
	}
	load5, err := parse(fields[1])
	if err != nil {
		return nil, err
	}
	load15, err := parse(fields[2])
	if err != nil {
		return nil, err
	}

	return &LoadavgData{Load1: load1, Load5: load5, Load15: load15}, nil
}
