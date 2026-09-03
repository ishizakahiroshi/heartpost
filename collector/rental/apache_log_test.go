package rental

import (
	"testing"
	"time"
)

func TestParseApacheAccessLineCombined(t *testing.T) {
	jst := time.FixedZone("JST", 9*60*60)
	ev, ok := parseApacheAccessLine(`203.0.113.10 - - [23/Apr/2026:10:20:30 +0900] "GET /index.php HTTP/1.1" 200 123 "-" "curl/8.0"`, jst)
	if !ok {
		t.Fatalf("parseApacheAccessLine returned ok=false")
	}
	if ev.TS != "2026-04-23T10:20:30+09:00" {
		t.Fatalf("TS = %q", ev.TS)
	}
	if ev.IP != "203.0.113.10" || ev.Method != "GET" || ev.Path != "/index.php" || ev.Status != 200 || ev.Bytes != 123 || ev.UA != "curl/8.0" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestParseApacheAccessLineVhostPrefix(t *testing.T) {
	jst := time.FixedZone("JST", 9*60*60)
	ev, ok := parseApacheAccessLine(`example.com 203.0.113.11 - - [23/Apr/2026:10:20:31 +0900] "POST /login HTTP/1.1" 403 - "https://example.com/" "Mozilla/5.0"`, jst)
	if !ok {
		t.Fatalf("parseApacheAccessLine returned ok=false")
	}
	if ev.IP != "203.0.113.11" {
		t.Fatalf("IP = %q", ev.IP)
	}
	if ev.Method != "POST" || ev.Path != "/login" || ev.Status != 403 || ev.Bytes != 0 {
		t.Fatalf("unexpected event: %+v", ev)
	}
	if ev.Referer != "https://example.com/" || ev.UA != "Mozilla/5.0" {
		t.Fatalf("unexpected referer/ua: %+v", ev)
	}
}
