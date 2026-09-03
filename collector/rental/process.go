package rental

import (
	"strings"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type ProcessCollector struct{}

type ProcessEntry struct {
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

func (p *ProcessCollector) Name() string { return "process" }

// Collect は `ps aux` を実行する。
// FreeBSD の共有環境では自プロセスのみ表示されるため、全行をそのまま返す。
func (p *ProcessCollector) Collect(cfg collector.Config) (interface{}, error) {
	out, err := runCommand("ps", "aux")
	if err != nil {
		return nil, err
	}

	var entries []ProcessEntry
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// 先頭ヘッダ行をスキップ
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue
		}
		entries = append(entries, ProcessEntry{
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
