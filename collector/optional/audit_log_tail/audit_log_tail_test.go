package audit_log_tail

import (
	"os"
	"path/filepath"
	"testing"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

// audit_log_tail は引き続き paths.audit_log のフォルダから audit_log.jsonl.* を読み、
// paths.nc_audit_log（Nextcloud の audit.log）は読まないこと。
func TestCollectReadsAuditLogDirOnly(t *testing.T) {
	dir := t.TempDir()
	monitorAuditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(monitorAuditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// 合成データ（利用者は example.com、IP は 192.0.2.0/24）。
	lines := `{"time":"2026-10-16T10:00:00+09:00","event":"login","user":"alice@example.com","ip":"192.0.2.20","result":"success"}
{"time":"2026-10-16T10:01:00+09:00","event":"logout","user":"alice@example.com","ip":"192.0.2.20","result":"success"}
`
	if err := os.WriteFile(filepath.Join(monitorAuditDir, "audit_log.jsonl.2026-10-16"), []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	ncAudit := filepath.Join(dir, "nc", "audit.log")
	if err := os.MkdirAll(filepath.Dir(ncAudit), 0o755); err != nil {
		t.Fatal(err)
	}
	ncLine := `{"reqId":"req-0001","level":1,"time":"2026-10-16T01:00:00+00:00","remoteAddr":"192.0.2.10","user":"admin@example.com","app":"admin_audit","message":"User created: \"bob@example.com\""}` + "\n"
	if err := os.WriteFile(ncAudit, []byte(ncLine), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := collector.Config{
		Paths: collector.PathConfig{
			AuditLog:   monitorAuditDir,
			NcAuditLog: ncAudit,
			DataDir:    filepath.Join(dir, "data"),
		},
	}
	got, err := (&Collector{}).Collect(cfg)
	if err != nil {
		t.Fatalf("Collect() error: %v", err)
	}
	res, ok := got.(*CollectResult)
	if !ok || res == nil {
		t.Fatalf("Collect() = %#v, want *CollectResult", got)
	}
	if res.NewEvents != 2 || len(res.Events) != 2 {
		t.Fatalf("NewEvents=%d len(Events)=%d, want 2/2 (%+v)", res.NewEvents, len(res.Events), res.Events)
	}
	if res.CurrentFile != "audit_log.jsonl.2026-10-16" {
		t.Fatalf("CurrentFile = %q, want audit_log.jsonl.2026-10-16", res.CurrentFile)
	}
	for _, ev := range res.Events {
		if ev.User != "alice@example.com" {
			t.Fatalf("unexpected event %+v (Nextcloud audit.log must not be read)", ev)
		}
	}
	if res.Offset != int64(len(lines)) {
		t.Fatalf("Offset = %d, want %d", res.Offset, len(lines))
	}

	// 2 回目は state の offset から読むので新しいイベントは無い
	got2, err := (&Collector{}).Collect(cfg)
	if err != nil {
		t.Fatalf("second Collect() error: %v", err)
	}
	if res2 := got2.(*CollectResult); res2.NewEvents != 0 {
		t.Fatalf("second Collect NewEvents = %d, want 0", res2.NewEvents)
	}
}
