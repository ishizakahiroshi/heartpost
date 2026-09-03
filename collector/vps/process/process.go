package process

import (
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

type Entry struct {
	User    string `json:"user"`
	PID     string `json:"pid"`
	CPU     string `json:"cpu"`
	Mem     string `json:"mem"`
	VSZ     string `json:"vsz"`
	RSS     string `json:"rss"`
	TTY     string `json:"tty"`
	Stat    string `json:"stat"`
	Start   string `json:"start"`
	Time    string `json:"time"`
	Command string `json:"command"`
}

func (p *Collector) Name() string { return "process" }

func (p *Collector) Collect(cfg vps.Config) (interface{}, error) {
	// ps のハング（ゾンビ/Dステート）で系統ループが止まるのを防ぐため RunWithTimeout 経由
	// で実行する（C1: exec-no-timeout-blocks-loop）。
	out, err := collector.RunWithTimeout(5*time.Second, "ps", "aux")
	if err != nil {
		return nil, err
	}

	var entries []Entry
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		entries = append(entries, Entry{
			User:    fields[0],
			PID:     fields[1],
			CPU:     fields[2],
			Mem:     fields[3],
			VSZ:     fields[4],
			RSS:     fields[5],
			TTY:     fields[6],
			Stat:    fields[7],
			Start:   fields[8],
			Time:    fields[9],
			Command: strings.Join(fields[10:], " "),
		})
	}

	return entries, nil
}
