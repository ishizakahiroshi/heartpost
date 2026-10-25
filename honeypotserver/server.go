package honeypotserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
)

const Schema = "honeypot.v1"

type Config struct {
	Listen         string
	JSONLPath      string
	MaxBodyBytes   int64
	AllowedHeaders []string
	IgnorePaths    []string
}

type Event struct {
	Schema        string            `json:"schema"`
	TS            string            `json:"ts"`
	IP            string            `json:"ip"`
	Method        string            `json:"method"`
	Path          string            `json:"path"`
	Query         string            `json:"query"`
	Trigger       string            `json:"trigger"`
	Headers       map[string]string `json:"headers,omitempty"`
	PostBody      string            `json:"post_body,omitempty"`
	IsWhitelisted bool              `json:"is_whitelisted"`
	DedupeKey     string            `json:"dedupe_key"`
}

type Server struct {
	cfg Config
}

func New(cfg Config) (*Server, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8776"
	}
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("invalid honeypot.listen: %w", err)
	}
	if host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return nil, fmt.Errorf("honeypot.listen must bind localhost, got %q", cfg.Listen)
	}
	if cfg.JSONLPath == "" {
		return nil, fmt.Errorf("honeypot.jsonl_path is required")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 8192
	}
	if len(cfg.AllowedHeaders) == 0 {
		cfg.AllowedHeaders = []string{"user-agent", "referer"}
	}
	return &Server{cfg: cfg}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handle)
	return mux
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if shouldIgnorePath(r.URL.Path, s.cfg.IgnorePaths) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	body := readLimitedBody(r.Body, s.cfg.MaxBodyBytes)
	ev := Event{
		Schema:        Schema,
		TS:            time.Now().In(collector.Location()).Format(time.RFC3339),
		IP:            clientIP(r),
		Method:        r.Method,
		Path:          r.URL.Path,
		Query:         r.URL.RawQuery,
		Trigger:       ClassifyTrigger(r.URL.Path, r.URL.RawQuery),
		Headers:       filteredHeaders(r.Header, s.cfg.AllowedHeaders),
		PostBody:      maskBody(body),
		IsWhitelisted: false,
	}
	ev.DedupeKey = buildDedupeKey(ev)
	_ = AppendEvent(s.cfg.JSONLPath, ev)

	w.WriteHeader(http.StatusForbidden)
}

// appendMu は AppendEvent の並行書き込みを直列化する。O_APPEND は PIPE_BUF(4KB) 超の
// 書き込みでアトミック性が保証されず、イベント JSON が 4KB を超えると並行 append で
// 行が混ざり JSON が破損しうるため Mutex でシリアライズする。
var appendMu sync.Mutex

func AppendEvent(path string, ev Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')

	appendMu.Lock()
	defer appendMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(b); err != nil {
		return err
	}
	return nil
}

func clientIP(r *http.Request) string {
	for _, key := range []string{"X-Real-IP", "X-Forwarded-For"} {
		v := strings.TrimSpace(r.Header.Get(key))
		if v == "" {
			continue
		}
		if key == "X-Forwarded-For" {
			v = strings.TrimSpace(strings.Split(v, ",")[0])
		}
		if ip := net.ParseIP(v); ip != nil {
			return ip.String()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func readLimitedBody(body io.ReadCloser, limit int64) string {
	defer body.Close()
	if limit <= 0 {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(body, limit))
	return string(b)
}

func filteredHeaders(h http.Header, allowed []string) map[string]string {
	out := make(map[string]string)
	allow := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allow[strings.ToLower(key)] = struct{}{}
	}
	for key, vals := range h {
		lower := strings.ToLower(key)
		if _, ok := allow[lower]; !ok {
			continue
		}
		out[lower] = strings.Join(vals, ", ")
	}
	return out
}

func shouldIgnorePath(path string, ignore []string) bool {
	for _, p := range ignore {
		if p != "" && path == p {
			return true
		}
	}
	return false
}

func buildDedupeKey(ev Event) string {
	ua := ev.Headers["user-agent"]
	sum := sha256.Sum256([]byte(strings.Join([]string{
		ev.TS, ev.IP, ev.Method, ev.Path, ev.Query, ev.Trigger, ua, ev.PostBody,
	}, "|")))
	return "honeypot|" + hex.EncodeToString(sum[:])
}

var maskBodyRe = regexp.MustCompile(`(?i)(password|passwd|token|secret|api[_-]?key)=([^&\s]+)`)

func maskBody(body string) string {
	if body == "" {
		return ""
	}
	return maskBodyRe.ReplaceAllString(body, `$1=***`)
}

func ClassifyTrigger(path, query string) string {
	s := strings.ToLower(path)
	q := strings.ToLower(query)
	switch {
	case containsAny(s, "webshell", "c99", "r57", "cmd.php", "shell.php", "wso.php"):
		return "backdoor"
	case q != "" && containsAny(q, "union+select", "union select", "select%20", "../", "%2e%2e", "etc/passwd", "<script", "%3cscript"):
		return "query_string"
	case strings.Contains(s, "wp-admin") || strings.Contains(s, "wp-login") || strings.Contains(s, "xmlrpc.php"):
		return "wordpress"
	case containsAny(s, "phpmyadmin", "phpma", "adminer", "mysqladmin"):
		return "db_tool"
	case containsAny(s, "vendor/phpunit", "phpunit", "/vendor/", "laravel", "thinkphp"):
		return "framework"
	case containsAny(s, "/.env", "/.git", "/.svn", "/.htaccess"):
		return "dotfile"
	case containsAny(s, "autodiscover", ".aspx", "owa/", "exchange"):
		return "microsoft"
	default:
		return "other"
	}
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
