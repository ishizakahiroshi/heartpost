package nginx

import (
	"strings"
	"testing"
	"time"
)

const (
	baseLine = `192.0.2.10 - alice [21/Apr/2026:01:05:40 +0900] "PROPFIND /dav/files/x HTTP/1.1" 404 12 "-" "synthetic-ua/1.0"`
	hexID    = "0123456789abcdef0123456789abcdef"
)

func jst() *time.Location { return time.FixedZone("JST", 9*3600) }

// Lines without the op field must parse exactly as before.
func TestParseLineWithoutOpUnchanged(t *testing.T) {
	ev, ok := parseLine(baseLine, jst())
	if !ok {
		t.Fatal("not parsed")
	}
	want := NginxEvent{
		TS: "2026-04-21T01:05:40+09:00", IP: "192.0.2.10", Method: "PROPFIND", Path: "/dav/files/x",
		Status: 404, Bytes: 12, UA: "synthetic-ua/1.0", Referer: "", RespMs: -1,
	}
	if ev != want {
		t.Fatalf("got %+v want %+v", ev, want)
	}
	if seenKey(ev) != "2026-04-21T01:05:40+09:00|192.0.2.10|/dav/files/x" {
		t.Fatalf("seen key changed: %s", seenKey(ev))
	}
}

func TestParseLineExtendedWithoutOpUnchanged(t *testing.T) {
	line := `192.0.2.10 - alice [21/Apr/2026:01:05:40 +0900] "GET /a HTTP/1.1" 304 0 443 "https://example.test/" "ua"`
	ev, ok := parseLine(line, jst())
	if !ok || ev.RequestID != "" || ev.Status != 304 || ev.Referer != "https://example.test/" {
		t.Fatalf("%+v ok=%v", ev, ok)
	}
}

func TestParseLineOpField(t *testing.T) {
	cases := []struct {
		name, suffix, want string
	}{
		{"valid", ` "op=` + hexID + `"`, hexID},
		{"dash", ` "op=-"`, ""},
		{"empty", ` "op="`, ""},
		{"uppercase", ` "op=` + strings.ToUpper(hexID) + `"`, ""},
		{"short", ` "op=0123abcd"`, ""},
		{"long", ` "op=` + hexID + `00"`, ""},
		{"non hex", ` "op=` + strings.Repeat("g", 32) + `"`, ""},
	}
	for _, c := range cases {
		ev, ok := parseLine(baseLine+c.suffix, jst())
		if !ok {
			t.Fatalf("%s: line rejected", c.name)
		}
		if ev.RequestID != c.want {
			t.Errorf("%s: request_id %q want %q", c.name, ev.RequestID, c.want)
		}
		if ev.UA != "synthetic-ua/1.0" || ev.Status != 404 {
			t.Errorf("%s: other fields disturbed: %+v", c.name, ev)
		}
	}
}

func TestSeenKeyUsesRequestID(t *testing.T) {
	a, _ := parseLine(baseLine+` "op=`+hexID+`"`, jst())
	b, _ := parseLine(baseLine+` "op=`+strings.Repeat("f", 32)+`"`, jst())
	if seenKey(a) == seenKey(b) {
		t.Fatal("distinct operations share a seen key")
	}
}
