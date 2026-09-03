// nginx パッケージは /var/log/nginx/access.log をパースして logs/nginx.jsonl に追記する。
// 実機フォーマット（nginx combined + $request_time 拡張）:
//
//	IP - user [DD/Mon/YYYY:HH:MM:SS +0900] "METHOD path HTTP/1.1" STATUS BYTES RESP_BYTES "REFERER" "UA"
//
// RESP_BYTES は nginx の $body_bytes_sent の後に追加された $bytes_sent または $request_time。
// フィールド数が9の場合は拡張フォーマット、8の場合は標準 combined フォーマットとして処理する。
package nginx

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

func (c *Collector) Name() string { return "nginx" }

// NginxEvent は nginx.jsonl の1レコード（plan の JSONL スキーマに準拠）
type NginxEvent struct {
	TS      string `json:"ts"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Bytes   int    `json:"bytes"`
	UA      string `json:"ua"`
	Referer string `json:"referer"`
	RespMs  int    `json:"resp_ms"`
}

type CollectResult struct {
	NewEvents int          `json:"new_events"`
	JsonlPath string       `json:"jsonl_path"`
	Events    []NginxEvent `json:"events,omitempty"`
}

// 実機フォーマット:
// 133.209.8.192 - admin [21/Apr/2026:01:05:40 +0900] "GET /path HTTP/1.1" 304 0 443 "-" "UA"
// フィールド: IP auth user [time] "request" status body_bytes resp_bytes "referer" "ua"
// resp_bytes が存在しない場合は標準 combined: IP - user [time] "request" status body_bytes "referer" "ua"
var reLogLine = regexp.MustCompile(
	`^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+(\d+)(?:\s+(\d+))?\s+"([^"]*)"\s+"([^"]*)"`,
)

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	jsonlPath := filepath.Join(cfg.Paths.DataDir, "logs", "nginx.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir logs: %w", err)
	}

	jst := collector.Location()
	tmpl := &collector.JSONLLogCollector[NginxEvent]{
		JSONLPath: jsonlPath,
		ParseLine: func(line string) (NginxEvent, bool) { return parseLine(line, jst) },
		SeenKey:   seenKey,
	}

	events, err := tmpl.Run(cfg.Paths.NginxLog, cfg.Rules.NginxLogLines)
	if err != nil {
		return nil, fmt.Errorf("parse nginx access.log: %w", err)
	}

	return &CollectResult{
		NewEvents: len(events),
		JsonlPath: jsonlPath,
		Events:    events,
	}, nil
}

func seenKey(ev NginxEvent) string {
	return ev.TS + "|" + ev.IP + "|" + ev.Path
}

// parseLine は nginx access.log の1行をパースする
func parseLine(line string, jst *time.Location) (NginxEvent, bool) {
	m := reLogLine.FindStringSubmatch(line)
	if m == nil {
		return NginxEvent{}, false
	}
	// m[1]=ip, m[2]=user, m[3]=time, m[4]=request, m[5]=status, m[6]=body_bytes
	// m[7]=resp_bytes(optional), m[8]=referer, m[9]=ua

	ip := m[1]
	rawTime := m[3]
	request := m[4]
	statusStr := m[5]
	bytesStr := m[6]
	respBytesStr := m[7]
	referer := m[8]
	ua := m[9]

	// 時刻パース: "21/Apr/2026:01:05:40 +0900"
	t, err := time.ParseInLocation("02/Jan/2006:15:04:05 -0700", rawTime, jst)
	if err != nil {
		return NginxEvent{}, false
	}
	ts := t.In(jst).Format(time.RFC3339)

	// リクエスト行を分割: "GET /path HTTP/1.1"
	parts := strings.SplitN(request, " ", 3)
	if len(parts) < 2 {
		return NginxEvent{}, false
	}
	method := parts[0]
	path := parts[1]

	status, _ := strconv.Atoi(statusStr)
	bytes, _ := strconv.Atoi(bytesStr)

	// resp_ms: resp_bytes フィールドがあれば使用（$bytes_sent が秒単位の場合もあるが ms で保持）
	// 実機では3フィールド目が $bytes_sent（整数）なので resp_ms は -1 で返す
	respMs := -1
	if respBytesStr != "" {
		// $bytes_sent はバイト数。resp_ms は別途取得できないため -1
		_ = respBytesStr
	}

	if referer == "-" {
		referer = ""
	}

	return NginxEvent{
		TS:      ts,
		IP:      ip,
		Method:  method,
		Path:    path,
		Status:  status,
		Bytes:   bytes,
		UA:      ua,
		Referer: referer,
		RespMs:  respMs,
	}, true
}
