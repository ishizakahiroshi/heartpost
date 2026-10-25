package backup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
)

func TestConfiguredFilesAndLocationWithoutDatabase(t *testing.T) {
	previous := collector.Location()
	collector.SetLocation(time.FixedZone("Example", 2*3600))
	t.Cleanup(func() { collector.SetLocation(previous) })
	base := t.TempDir()
	file := filepath.Join(base, "example backup.sql.zst")
	if err := os.WriteFile(file, []byte("123"), 0600); err != nil {
		t.Fatal(err)
	}
	stamp := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	if err := os.Chtimes(file, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	got, err := (&Collector{}).Collect(optional.Config{Database: optional.DatabaseConfig{BackupDir: base}})
	if err != nil {
		t.Fatal(err)
	}
	result := got.(*CollectResult)
	if result.DBSize != "?" || len(result.BackupFiles) != 1 || result.BackupFiles[0] != (BackupFile{Name: "example backup.sql.zst", Size: "3", Date: "2026-01-02 05:04:05"}) {
		t.Fatalf("result=%+v", result)
	}
	user, pass, socket := parseMysqlDSN("example:synthetic:pass@unix(/tmp/example.sock)/example")
	if user != "example" || pass != "synthetic:pass" || socket != "/tmp/example.sock" {
		t.Fatal("DSN parsing changed")
	}
}
