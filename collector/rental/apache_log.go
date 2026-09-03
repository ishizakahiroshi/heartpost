package rental

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type ApacheLogCollector struct{}

const apacheLogEventTailLines = 500

type ApacheLogData struct {
	AccessCount int                 `json:"access_count"` // 当日アクセスログの行数
	LogPath     string              `json:"log_path"`     // 参照したログファイルパス
	Events      []ApacheAccessEvent `json:"events,omitempty"`
}

type ApacheAccessEvent struct {
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

func (a *ApacheLogCollector) Name() string { return "apache_log" }

// Collect は ~/log/access_log_YYYYMMDD（当日分）の行数を返す。
// ファイルが存在しない場合は null を返す（アクセスなし or ローテーション直後）。
func (a *ApacheLogCollector) Collect(cfg collector.Config) (interface{}, error) {
	logDir := cfg.LogDir
	if logDir == "" {
		logDir = filepath.Join(cfg.HomeDir, "log")
	}

	today := time.Now().Format("20060102")
	logPath := filepath.Join(logDir, fmt.Sprintf("access_log_%s", today))

	if _, err := os.Stat(logPath); os.IsNotExist(err) {
		// ファイル未存在は取得不可として null 扱い
		return nil, nil
	}

	count, err := countLines(logPath)
	if err != nil {
		return nil, err
	}

	events, err := parseApacheAccessEvents(logPath, apacheLogEventTailLines)
	if err != nil {
		return nil, err
	}

	return &ApacheLogData{AccessCount: count, LogPath: logPath, Events: events}, nil
}

func countLines(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	// 既定 64KB バッファだと長い 1 行（長大 URL/UA）で bufio.ErrTooLong になり
	// countLines が error を返して当日の apache_log カードが欠測する。tailLines と同じ
	// 1MB 上限に揃えて行長依存の取りこぼしを防ぐ。
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		count++
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("scan %s: %w", path, err)
	}

	return count, nil
}

var reApacheLogLine = regexp.MustCompile(
	`^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?`,
)
var reApacheVhostLogLine = regexp.MustCompile(
	`^\S+\s+(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?`,
)

func parseApacheAccessEvents(path string, maxLines int) ([]ApacheAccessEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	lines, err := tailLines(f, maxLines)
	if err != nil {
		return nil, fmt.Errorf("tail %s: %w", path, err)
	}

	loc := collector.Location()
	events := make([]ApacheAccessEvent, 0, len(lines))
	for _, line := range lines {
		ev, ok := parseApacheAccessLine(line, loc)
		if ok {
			events = append(events, ev)
		}
	}
	return events, nil
}

func parseApacheAccessLine(line string, jst *time.Location) (ApacheAccessEvent, bool) {
	m := reApacheLogLine.FindStringSubmatch(line)
	if m == nil {
		m = reApacheVhostLogLine.FindStringSubmatch(line)
		if m == nil {
			return ApacheAccessEvent{}, false
		}
	}

	t, err := time.ParseInLocation("02/Jan/2006:15:04:05 -0700", m[2], jst)
	if err != nil {
		return ApacheAccessEvent{}, false
	}

	method, reqPath := splitApacheRequest(m[3])
	status, _ := strconv.Atoi(m[4])
	bytesSent := 0
	if m[5] != "-" {
		bytesSent, _ = strconv.Atoi(m[5])
	}

	referer := ""
	if len(m) > 6 && m[6] != "-" {
		referer = m[6]
	}
	ua := ""
	if len(m) > 7 {
		ua = m[7]
	}

	return ApacheAccessEvent{
		TS:      t.In(jst).Format(time.RFC3339),
		IP:      m[1],
		Method:  method,
		Path:    reqPath,
		Status:  status,
		Bytes:   bytesSent,
		UA:      ua,
		Referer: referer,
		RespMs:  -1,
	}, true
}

func splitApacheRequest(request string) (string, string) {
	parts := strings.SplitN(request, " ", 3)
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return "", request
}

func tailLines(f *os.File, n int) ([]string, error) {
	if n <= 0 {
		n = apacheLogEventTailLines
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	ring := make([]string, n)
	count := 0
	for scanner.Scan() {
		ring[count%n] = scanner.Text()
		count++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	total := count
	if total > n {
		total = n
	}
	out := make([]string, 0, total)
	start := 0
	if count > n {
		start = count % n
	}
	for i := 0; i < total; i++ {
		out = append(out, ring[(start+i)%n])
	}
	return out, nil
}
