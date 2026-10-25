package nc_extract

import (
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
	"os"
	"path/filepath"
	"testing"
)

func TestExplicitDirectoryAndNoDefault(t *testing.T) {
	if got, err := (&Collector{}).Collect(optional.Config{}); err != nil || got != nil {
		t.Fatalf("unconfigured=%v %v", got, err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "login_events.jsonl")
	if err := os.WriteFile(path, []byte("{\"result\":\"success\"}\ninvalid\n{\"result\":\"failed\"}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := (&Collector{}).Collect(optional.Config{Paths: optional.PathConfig{NcExtractDir: dir}})
	if err != nil {
		t.Fatal(err)
	}
	result := got.(*CollectResult)
	if result.TotalLoginEvents != 2 || result.SuccessCount != 1 || result.FailCount != 1 || result.LoginEventsPath != path {
		t.Fatalf("result=%+v", result)
	}
}
