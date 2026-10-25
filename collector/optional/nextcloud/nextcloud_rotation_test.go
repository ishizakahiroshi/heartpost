package nextcloud

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

// rotTestLine は Nextcloud の audit.log 形式の合成の 1 行（改行つき）を返す。
func rotTestLine(t *testing.T, ts, msg string) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{
		"reqId": "req-" + ts, "level": 1, "time": ts, "remoteAddr": "192.0.2.10",
		"user": "alice@example.com", "app": "admin_audit", "message": msg,
		"url": "/nextcloud/index.php", "method": "GET", "userAgent": "synthetic-test-agent",
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

func rotAppend(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// 手元の nextcloud.jsonl が 10MB を超えて .1 に名前が変わった後も、同じイベントを
// 2 回返さないこと（2026-10-16 の送り直しの不具合の陰性対照）。
func TestCollectNoResendAfterLocalJSONLRotation(t *testing.T) {
	dir := t.TempDir()
	auditLog := filepath.Join(dir, "nc", "audit.log")
	dataDir := filepath.Join(dir, "data")
	jsonlPath := filepath.Join(dataDir, "logs", "nextcloud.jsonl")
	cfg := collector.Config{
		Paths: collector.PathConfig{
			NextcloudLog: filepath.Join(dir, "nc", "nextcloud.log"), // 無い
			NcAuditLog:   auditLog,
			DataDir:      dataDir,
		},
	}
	collect := func(step string) *CollectResult {
		t.Helper()
		got, err := (&Collector{}).Collect(cfg)
		if err != nil {
			t.Fatalf("%s: Collect error: %v", step, err)
		}
		res, ok := got.(*CollectResult)
		if !ok || res == nil {
			t.Fatalf("%s: Collect = %#v, want *CollectResult", step, got)
		}
		return res
	}

	var backlog strings.Builder
	for _, ts := range []string{"2026-10-16T01:00:01+00:00", "2026-10-16T01:00:02+00:00", "2026-10-16T01:00:03+00:00"} {
		backlog.WriteString(rotTestLine(t, ts, "File accessed: \"/old/"+ts+"\""))
	}
	rotAppend(t, auditLog, backlog.String())
	collect("#1") // 初回（返す件数はここでは問わない）

	returned := map[string]int{}
	record := func(res *CollectResult) {
		for _, ev := range res.Events {
			returned[ev.Msg]++
		}
	}

	rotAppend(t, auditLog, rotTestLine(t, "2026-10-16T01:01:00+00:00", "File accessed: \"/new/1\"")+
		rotTestLine(t, "2026-10-16T01:01:01+00:00", "File accessed: \"/new/2\""))
	res2 := collect("#2")
	if res2.NewEvents != 2 {
		t.Fatalf("#2 NewEvents = %d, want 2 (%+v)", res2.NewEvents, res2.Events)
	}
	record(res2)

	// 手元の nextcloud.jsonl を 10MB 超にして、次の追記の後に .1 へ名前が変わるようにする。
	pad := `{"ts":"2000-01-01T00:00:00+09:00","source":"pad","msg":"` + strings.Repeat("x", 1000) + `"}` + "\n"
	rotAppend(t, jsonlPath, strings.Repeat(pad, 10600))

	rotAppend(t, auditLog, rotTestLine(t, "2026-10-16T01:02:00+00:00", "File accessed: \"/new/3\""))
	res3 := collect("#3")
	record(res3)
	if _, err := os.Stat(jsonlPath + ".1"); err != nil {
		t.Fatalf("#3: nextcloud.jsonl was not rotated to .1: %v", err)
	}

	// 元のログに新しい行は無い。名前が変わった後でも、何も返さないのが正しい。
	res4 := collect("#4")
	record(res4)
	if res4.NewEvents != 0 {
		t.Fatalf("#4 after local jsonl rotation: NewEvents = %d, want 0 (resent %d events)", res4.NewEvents, len(res4.Events))
	}
	for msg, n := range returned {
		if n > 1 {
			t.Fatalf("event %q returned %d times", msg, n)
		}
	}
	if returned[`File accessed: "/new/3"`] != 1 {
		t.Fatalf("/new/3 returned %d times, want 1", returned[`File accessed: "/new/3"`])
	}
}
