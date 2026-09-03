// ssh パッケージは /var/log/auth.log をパースして logs/ssh.jsonl に追記する。
// 実機フォーマット（Ubuntu 24.x):
//
//	2026-04-21T01:08:24.607912+09:00 hostname sshd[PID]: Accepted publickey for USER from IP port PORT ssh2: ...
//	2026-04-21T01:08:24.580914+09:00 hostname sshd[PID]: Accepted key ED25519 SHA256:... found at /path:1
//	2026-04-21T01:08:30.000000+09:00 hostname sshd[PID]: Failed password for USER from IP port PORT ssh2
//	2026-04-21T01:08:30.000000+09:00 hostname sshd[PID]: Invalid user USER from IP port PORT
package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

func (c *Collector) Name() string { return "ssh" }

// SSHEvent は ssh.jsonl の1レコード
type SSHEvent struct {
	TS     string `json:"ts"`
	Event  string `json:"event"`
	User   string `json:"user"`
	IP     string `json:"ip"`
	Port   string `json:"port"`
	Method string `json:"method"`
}

// CollectResult は Monitor へ送るサマリー
type CollectResult struct {
	NewEvents int        `json:"new_events"`
	JsonlPath string     `json:"jsonl_path"`
	Events    []SSHEvent `json:"events,omitempty"`
}

var (
	// 2026-04-21T01:08:24.607912+09:00 hostname sshd[PID]: ...
	reTimestamp = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[+-]\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+(.+)$`)

	// Accepted publickey for USER from IP port PORT
	reAccepted = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port (\d+)`)
	// Failed password for USER from IP port PORT
	reFailed = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	// Invalid user USER from IP port PORT
	reInvalid = regexp.MustCompile(`^Invalid user (\S+) from (\S+) port (\d+)`)
	// Disconnected from IP port PORT
	reDisconnect = regexp.MustCompile(`^Disconnected from (?:invalid user \S+ )?(\S+) port (\d+)`)
)

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	jsonlPath := filepath.Join(cfg.Paths.DataDir, "logs", "ssh.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir logs: %w", err)
	}

	// jsonl tail+seen+append+rotate の共通フローはテンプレートに委譲し、
	// ここは ParseLine / SeenKey の差分だけ渡す（C3: jsonl-collector-pattern-duplication）。
	jst := collector.Location()
	tmpl := &collector.JSONLLogCollector[SSHEvent]{
		JSONLPath: jsonlPath,
		ParseLine: func(line string) (SSHEvent, bool) { return parseLine(line, jst) },
		SeenKey:   seenKey,
	}

	events, err := tmpl.Run(cfg.Paths.AuthLog, cfg.Rules.AuthLogLines)
	if err != nil {
		return nil, fmt.Errorf("parse auth.log: %w", err)
	}

	return &CollectResult{
		NewEvents: len(events),
		JsonlPath: jsonlPath,
		Events:    events,
	}, nil
}

func seenKey(ev SSHEvent) string {
	return ev.TS + "|" + ev.IP + "|" + ev.Event
}

// parseLine は1行をパースして SSHEvent に変換する
func parseLine(line string, jst *time.Location) (SSHEvent, bool) {
	m := reTimestamp.FindStringSubmatch(line)
	if m == nil {
		return SSHEvent{}, false
	}
	rawTS, msg := m[1], m[2]

	// RFC3339 に正規化
	t, err := time.Parse("2006-01-02T15:04:05.999999999-07:00", rawTS)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05.999999999+07:00", rawTS)
		if err != nil {
			return SSHEvent{}, false
		}
	}
	ts := t.In(jst).Format(time.RFC3339)

	if sub := reAccepted.FindStringSubmatch(msg); sub != nil {
		return SSHEvent{TS: ts, Event: "accepted", Method: sub[1], User: sub[2], IP: sub[3], Port: sub[4]}, true
	}
	if sub := reFailed.FindStringSubmatch(msg); sub != nil {
		return SSHEvent{TS: ts, Event: "failed", Method: sub[1], User: sub[2], IP: sub[3], Port: sub[4]}, true
	}
	if sub := reInvalid.FindStringSubmatch(msg); sub != nil {
		return SSHEvent{TS: ts, Event: "invalid_user", User: sub[1], IP: sub[2], Port: sub[3], Method: ""}, true
	}
	if sub := reDisconnect.FindStringSubmatch(msg); sub != nil {
		if !strings.Contains(msg, "authenticating") {
			return SSHEvent{TS: ts, Event: "disconnect", IP: sub[1], Port: sub[2]}, true
		}
	}
	return SSHEvent{}, false
}
