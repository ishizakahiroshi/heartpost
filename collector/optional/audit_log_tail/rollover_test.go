package audit_log_tail

import (
	"fmt"
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRolloverDrainsOlderFileWithinBudget(t *testing.T) {
	base := t.TempDir()
	logs := filepath.Join(base, "audit")
	if err := os.MkdirAll(logs, 0700); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(logs, "audit_log.jsonl.2026-01-01")
	if err := os.WriteFile(old, []byte("{\"time\":\"example\",\"event\":\"LOGIN\",\"user\":\"first\",\"result\":\"success\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := optional.Config{Paths: optional.PathConfig{DataDir: filepath.Join(base, "data"), AuditLog: logs}}
	if _, err := (&Collector{}).Collect(cfg); err != nil {
		t.Fatal(err)
	}
	var backlog strings.Builder
	for i := 0; i < maxEventsPerCollect+1; i++ {
		fmt.Fprintf(&backlog, "{\"time\":\"example\",\"event\":\"LOGIN\",\"user\":\"old-%d\",\"result\":\"success\"}\n", i)
	}
	f, err := os.OpenFile(old, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(backlog.String())
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logs, "audit_log.jsonl.2026-01-02"), []byte("{\"time\":\"example\",\"event\":\"LOGIN\",\"user\":\"new\",\"result\":\"success\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := (&Collector{}).Collect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	first := got.(*CollectResult)
	if first.NewEvents != maxEventsPerCollect || first.CurrentFile != filepath.Base(old) {
		t.Fatalf("first rollover batch=%+v", first)
	}
	got, err = (&Collector{}).Collect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	next := got.(*CollectResult)
	if next.NewEvents != 2 || next.Events[0].User != "old-5000" || next.Events[1].User != "new" {
		t.Fatalf("remaining old/new order=%+v", next)
	}
}
