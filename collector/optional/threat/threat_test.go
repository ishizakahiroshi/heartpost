package threat

import (
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
	"os"
	"path/filepath"
	"testing"
)

func TestConfiguredCSVSkipsIncompleteRows(t *testing.T) {
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "csv"), 0700); err != nil {
		t.Fatal(err)
	}
	data := "timestamp,ip,score,scan_hits,scan_criticals,auth_fails,nc_fails,nc_4xx,is_banned,is_foreign\nexample,192.0.2.1,10,1,0,2,3,4,0,1\nincomplete,192.0.2.3\nexample,192.0.2.2,90,2,1,3,4,5,1,0\n"
	if err := os.WriteFile(filepath.Join(base, "csv", "threat_score.csv"), []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := (&Collector{}).Collect(optional.Config{Paths: optional.PathConfig{DataDir: base}})
	if err != nil {
		t.Fatal(err)
	}
	result := got.(*CollectResult)
	if result.TotalIPs != 2 || result.BannedIPs != 1 || result.TopScores[0].IP != "192.0.2.2" || result.Entries[0].Score != 10 {
		t.Fatalf("result=%+v", result)
	}
}
