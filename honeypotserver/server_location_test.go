package honeypotserver

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
)

func TestEventUsesConfiguredCollectorLocation(t *testing.T) {
	previous := collector.Location()
	collector.SetLocation(time.FixedZone("Example", 2*3600))
	t.Cleanup(func() { collector.SetLocation(previous) })
	path := filepath.Join(t.TempDir(), "event.jsonl")
	server, err := New(Config{JSONLPath: path})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://example.com/.env", nil))
	if w.Code != 403 {
		t.Fatal("honeypot status changed")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event Event
	if err := json.Unmarshal(body, &event); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(event.TS, "+02:00") {
		t.Fatalf("event location=%s", event.TS)
	}
}
