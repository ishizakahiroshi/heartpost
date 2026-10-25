package honeypotserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClassifyTrigger(t *testing.T) {
	cases := []struct {
		path  string
		query string
		want  string
	}{
		{"/.env", "", "dotfile"},
		{"/wp-admin/setup-config.php", "", "wordpress"},
		{"/phpmyadmin/index.php", "", "db_tool"},
		{"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "", "framework"},
		{"/shell.php", "", "backdoor"},
		{"/search", "q=../etc/passwd", "query_string"},
		{"/autodiscover/autodiscover.xml", "", "microsoft"},
		{"/unknown", "", "other"},
	}
	for _, tc := range cases {
		if got := ClassifyTrigger(tc.path, tc.query); got != tc.want {
			t.Fatalf("ClassifyTrigger(%q, %q) = %q, want %q", tc.path, tc.query, got, tc.want)
		}
	}
}

func TestHandlerWritesFilteredEventAndReturnsForbidden(t *testing.T) {
	dir := t.TempDir()
	s, err := New(Config{
		Listen:         "127.0.0.1:8776",
		JSONLPath:      filepath.Join(dir, "honeypot.jsonl"),
		MaxBodyBytes:   12,
		AllowedHeaders: []string{"user-agent", "referer"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/.env?token=abc", strings.NewReader("password=secret&after=truncated"))
	req.Header.Set("X-Real-IP", "203.0.113.10")
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("Cookie", "sid=secret")
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	b, err := os.ReadFile(filepath.Join(dir, "honeypot.jsonl"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var ev Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &ev); err != nil {
		t.Fatalf("unmarshal event: %v", err)
	}
	if ev.Schema != Schema || ev.IP != "203.0.113.10" || ev.Trigger != "dotfile" {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if _, ok := ev.Headers["cookie"]; ok {
		t.Fatalf("cookie header was persisted")
	}
	if ev.PostBody != "password=***" {
		t.Fatalf("post_body = %q, want masked limited body", ev.PostBody)
	}
	if ev.DedupeKey == "" {
		t.Fatalf("dedupe_key is empty")
	}
}

func TestNewRejectsNonLocalBind(t *testing.T) {
	_, err := New(Config{Listen: "0.0.0.0:8776", JSONLPath: filepath.Join(t.TempDir(), "hp.jsonl")})
	if err == nil {
		t.Fatalf("New accepted non-local bind")
	}
}
