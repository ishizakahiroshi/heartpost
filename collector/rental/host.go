package rental

import (
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type HostCollector struct{}

type HostData struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
}

func (h *HostCollector) Name() string { return "host" }

func (h *HostCollector) Collect(cfg collector.Config) (interface{}, error) {
	hostname, err := runCommand("hostname")
	if err != nil {
		return nil, err
	}

	uname, err := runCommand("uname", "-a")
	if err != nil {
		return nil, err
	}

	return &HostData{
		Hostname: strings.TrimSpace(hostname),
		OS:       strings.TrimSpace(uname),
	}, nil
}

// runCommand は rental collector 群が共用するコマンド実行ヘルパ。timeout を付けて
// hostname/uname/sysctl/df/ps/crontab のハングが one-shot 実行全体を止めるのを防ぐ
// （C1: exec-no-timeout-blocks-loop）。
func runCommand(name string, args ...string) (string, error) {
	out, err := collector.RunWithTimeout(5*time.Second, name, args...)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
