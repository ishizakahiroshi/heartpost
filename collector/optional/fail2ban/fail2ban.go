// fail2ban パッケージは /var/log/fail2ban.log をパースして logs/fail2ban.jsonl に追記する。
// 実機フォーマット（Ubuntu 24.x, fail2ban 1.x):
//
//	2026-04-15 02:56:23,931 fail2ban.actions [PID]: NOTICE [jail] Ban 192.0.2.9
//	2026-04-15 02:56:23,931 fail2ban.actions [PID]: NOTICE [jail] Unban 192.0.2.9
//	2026-04-15 02:56:23,931 fail2ban.actions [PID]: NOTICE [jail] Restore Ban 192.0.2.9
//	2026-04-15 02:37:23,458 fail2ban.filter  [PID]: INFO   [jail] Found 192.0.2.9 - 2026-04-15 02:37:23
package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	sharedcollector "github.com/ishizakahiroshi/heartpost/collector"
	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

type Collector struct{}

var runWithTimeout = sharedcollector.RunWithTimeout

func (c *Collector) Name() string     { return "fail2ban" }
func (c *Collector) Interval() string { return "security" }

// F2BEvent は fail2ban.jsonl の1レコード
type F2BEvent struct {
	TS       string `json:"ts"`
	Event    string `json:"event"`
	Jail     string `json:"jail"`
	IP       string `json:"ip"`
	Failures int    `json:"failures,omitempty"`
}

type CollectResult struct {
	NewEvents int        `json:"new_events"`
	JsonlPath string     `json:"jsonl_path"`
	Events    []F2BEvent `json:"events,omitempty"`
	Active    int        `json:"active,omitempty"`
	Jails     []JailInfo `json:"jails,omitempty"`
}

type JailInfo struct {
	Name        string   `json:"name"`
	BanCount    int      `json:"ban_count"`
	TotalBanned int      `json:"total_banned"`
	TotalFound  int      `json:"total_found"`
	BannedIPs   []string `json:"banned_ips,omitempty"`
}

var (
	// YYYY-MM-DD HH:MM:SS,mmm ... [jail] Ban/Unban/Found IP
	reBan = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[\d+\]:\s+NOTICE\s+\[(\S+)\]\s+Ban\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	)
	reUnban = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[\d+\]:\s+NOTICE\s+\[(\S+)\]\s+Unban\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	)
	reRestore = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[\d+\]:\s+NOTICE\s+\[(\S+)\]\s+Restore Ban\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	)
	reFound = regexp.MustCompile(
		`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[\d+\]:\s+INFO\s+\[(\S+)\]\s+Found\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`,
	)
	logTimeLayout = "2006-01-02 15:04:05"
)

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	if strings.TrimSpace(cfg.Paths.DataDir) == "" || strings.TrimSpace(cfg.Paths.Fail2banLog) == "" {
		return nil, fmt.Errorf("paths.data_dir and paths.fail2ban_log are required")
	}
	jsonlPath := filepath.Join(cfg.Paths.DataDir, "logs", "fail2ban.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir logs: %w", err)
	}

	jst := sharedcollector.Location()
	tmpl := &sharedcollector.JSONLLogCollector[F2BEvent]{
		JSONLPath: jsonlPath,
		ParseLine: func(line string) (F2BEvent, bool) { return parseLine(line, jst) },
		SeenKey:   seenKey,
	}

	events, err := tmpl.Run(cfg.Paths.Fail2banLog, cfg.Rules.Fail2banLogLines)
	if err != nil {
		return nil, fmt.Errorf("parse fail2ban.log: %w", err)
	}

	jails := collectJailSnapshots()

	return &CollectResult{
		NewEvents: len(events),
		JsonlPath: jsonlPath,
		Events:    events,
		Active:    activeJailsBanCount(jails),
		Jails:     jails,
	}, nil
}

func activeJailsBanCount(jails []JailInfo) int {
	total := 0
	for _, j := range jails {
		total += j.BanCount
	}
	return total
}

// defaultJails は fail2ban-client status からの動的取得が失敗した場合のフォールバック。
var defaultJails = []string{"nextcloud", "nginx-suspicious", "nginx-basic-auth", "recidive"}

func collectJailSnapshots() []JailInfo {
	targets := discoverJails()
	out := make([]JailInfo, 0, len(targets))
	for _, jail := range targets {
		if info, ok := readJailStatus(jail); ok {
			out = append(out, info)
		}
	}
	return out
}

// discoverJails は `fail2ban-client status` の "Jail list:" 行から有効な jail 名を
// 動的に取得する。取得・解析に失敗した場合は defaultJails にフォールバックする。
func discoverJails() []string {
	// fail2ban-client のハング防止に RunWithTimeout 経由で実行する
	// （C1: exec-no-timeout-blocks-loop）。
	raw, err := runWithTimeout(5*time.Second, "/usr/bin/fail2ban-client", "status")
	if err != nil {
		return defaultJails
	}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		idx := strings.Index(s, "Jail list:")
		if idx < 0 {
			continue
		}
		var jails []string
		for _, j := range strings.Split(s[idx+len("Jail list:"):], ",") {
			if j = strings.TrimSpace(j); j != "" {
				jails = append(jails, j)
			}
		}
		if len(jails) > 0 {
			return jails
		}
	}
	return defaultJails
}

func readJailStatus(jail string) (JailInfo, bool) {
	raw, err := runWithTimeout(5*time.Second, "/usr/bin/fail2ban-client", "status", jail)
	if err != nil {
		return JailInfo{}, false
	}
	info := JailInfo{Name: jail}
	for _, line := range strings.Split(string(raw), "\n") {
		s := strings.TrimSpace(line)
		switch {
		case strings.Contains(s, "Currently banned:"):
			info.BanCount = parseStatusInt(s)
		case strings.Contains(s, "Total banned:"):
			info.TotalBanned = parseStatusInt(s)
		case strings.Contains(s, "Total found:"):
			info.TotalFound = parseStatusInt(s)
		case strings.Contains(s, "Banned IP list:"):
			idx := strings.Index(s, "Banned IP list:")
			if idx >= 0 {
				ipPart := strings.TrimSpace(s[idx+len("Banned IP list:"):])
				if ipPart != "" {
					info.BannedIPs = strings.Fields(ipPart)
				}
			}
		}
	}
	if info.BannedIPs == nil {
		info.BannedIPs = []string{}
	}
	return info, true
}

func parseStatusInt(line string) int {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(parts[len(parts)-1])
	return n
}

func seenKey(ev F2BEvent) string {
	return ev.TS + "|" + ev.Jail + "|" + ev.IP + "|" + ev.Event
}

func parseLine(line string, jst *time.Location) (F2BEvent, bool) {
	if m := reBan.FindStringSubmatch(line); m != nil {
		ts := parseTS(m[1], jst)
		return F2BEvent{TS: ts, Event: "ban", Jail: m[2], IP: m[3]}, true
	}
	if m := reUnban.FindStringSubmatch(line); m != nil {
		ts := parseTS(m[1], jst)
		return F2BEvent{TS: ts, Event: "unban", Jail: m[2], IP: m[3]}, true
	}
	if m := reRestore.FindStringSubmatch(line); m != nil {
		ts := parseTS(m[1], jst)
		return F2BEvent{TS: ts, Event: "restore", Jail: m[2], IP: m[3]}, true
	}
	if m := reFound.FindStringSubmatch(line); m != nil {
		ts := parseTS(m[1], jst)
		return F2BEvent{TS: ts, Event: "found", Jail: m[2], IP: m[3]}, true
	}
	return F2BEvent{}, false
}

func parseTS(raw string, jst *time.Location) string {
	t, err := time.ParseInLocation(logTimeLayout, raw, jst)
	if err != nil {
		return raw
	}
	return t.Format(time.RFC3339)
}
