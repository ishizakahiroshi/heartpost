package honeypot

import (
	"os"
	"path/filepath"
	"testing"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

func TestCollectReadsAgentJSONLAndIncludesEvents(t *testing.T) {
	dir := t.TempDir()
	jsonl := filepath.Join(dir, "logs", "honeypot.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonl), 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	data := `{"schema":"honeypot.v1","ts":"2999-04-29T10:00:00+09:00","ip":"203.0.113.10","method":"GET","path":"/.env","query":"","trigger":"dotfile","headers":{"user-agent":"curl"},"dedupe_key":"k1"}` + "\n"
	if err := os.WriteFile(jsonl, []byte(data), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := (&Collector{}).Collect(collector.Config{
		Paths: collector.PathConfig{DataDir: dir},
		Rules: collector.RulesConfig{HoneypotDays: 30},
		Honeypot: collector.HoneypotConfig{
			JSONLPath: jsonl,
		},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	result, ok := got.(*CollectResult)
	if !ok {
		t.Fatalf("Collect returned %T", got)
	}
	if result.TotalHits != 1 || result.NewEvents != 1 || len(result.Events) != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.Events[0].Schema != "honeypot.v1" || result.Events[0].DedupeKey != "k1" {
		t.Fatalf("event fields not preserved: %+v", result.Events[0])
	}
}
