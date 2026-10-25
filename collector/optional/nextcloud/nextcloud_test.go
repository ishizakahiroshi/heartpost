package nextcloud

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

// 合成データだけを使う（利用者は example.com、IP は 192.0.2.0/24）。
// 行の組み立ては nextcloud_rotation_test.go の rotTestLine / rotAppend を使う。

type ncTestEnv struct {
	cfg      collector.Config
	appLog   string
	auditLog string
	jsonl    string
	state    string
}

func newNCTestEnv(t *testing.T) *ncTestEnv {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	e := &ncTestEnv{
		appLog:   filepath.Join(dir, "nc", "nextcloud.log"),
		auditLog: filepath.Join(dir, "nc", "audit.log"),
		jsonl:    filepath.Join(dataDir, "logs", "nextcloud.jsonl"),
		state:    filepath.Join(dataDir, "json", stateFileName),
	}
	e.cfg = collector.Config{Paths: collector.PathConfig{
		NextcloudLog: e.appLog,
		AuditLog:     filepath.Join(dir, "monitor-audit"), // audit_log_tail 用（読まれない）
		NcAuditLog:   e.auditLog,
		DataDir:      dataDir,
	}}
	return e
}

func (e *ncTestEnv) collect(t *testing.T, step string) *CollectResult {
	t.Helper()
	got, err := (&Collector{}).Collect(e.cfg)
	if err != nil {
		t.Fatalf("%s: Collect error: %v", step, err)
	}
	res, ok := got.(*CollectResult)
	if !ok || res == nil {
		t.Fatalf("%s: Collect = %#v, want *CollectResult", step, got)
	}
	if res.NewEvents != len(res.Events) {
		t.Fatalf("%s: NewEvents=%d but len(Events)=%d", step, res.NewEvents, len(res.Events))
	}
	return res
}

// line は n 番目の合成の行（時刻は 2026-10-16T03:MM:SS+00:00 の形）。
func line(t *testing.T, n int, msg string) string {
	t.Helper()
	return rotTestLine(t, fmt.Sprintf("2026-10-16T03:%02d:%02d+00:00", (n/60)%60, n%60), msg)
}

func msgsOf(res *CollectResult) []string {
	out := []string{}
	for _, ev := range res.Events {
		out = append(out, ev.Source+":"+ev.Msg)
	}
	return out
}

func expectMsgs(t *testing.T, step string, res *CollectResult, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if got := msgsOf(res); !reflect.DeepEqual(got, want) {
		t.Fatalf("%s: events = %q, want %q", step, got, want)
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return strings.Count(string(b), "\n")
}

// fakeInodes はテストの間だけ inode の取得を差し替え、パスごとの inode を手で決める。
func fakeInodes(t *testing.T) map[string]uint64 {
	t.Helper()
	m := map[string]uint64{}
	orig := fileInode
	fileInode = func(path string, info os.FileInfo) uint64 { return m[path] }
	t.Cleanup(func() { fileInode = orig })
	return m
}

// Nextcloud が無いホスト（nextcloud.log も Nextcloud の audit.log も無い）で、
// paths.audit_log に monitor の監査ログのフォルダがあっても (nil, nil) を返すこと。
func TestCollectWithoutNextcloudIgnoresAuditLogDir(t *testing.T) {
	dir := t.TempDir()
	monitorAuditDir := filepath.Join(dir, "audit")
	if err := os.MkdirAll(monitorAuditDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := collector.Config{
		Paths: collector.PathConfig{
			NextcloudLog: filepath.Join(dir, "missing", "nextcloud.log"),
			AuditLog:     monitorAuditDir,
			NcAuditLog:   filepath.Join(dir, "missing", "audit.log"),
			DataDir:      filepath.Join(dir, "data"),
		},
	}
	got, err := (&Collector{}).Collect(cfg)
	if err != nil || got != nil {
		t.Fatalf("Collect() = (%#v, %v), want (nil, nil)", got, err)
	}
}

// paths.audit_log（monitor の監査ログのフォルダ）ではなく paths.nc_audit_log
// （Nextcloud の audit.log）を読み、jsonl にも追記すること。
func TestCollectReadsNcAuditLogNotAuditLog(t *testing.T) {
	e := newNCTestEnv(t)
	monitorAuditDir := e.cfg.Paths.AuditLog
	// monitor の監査ログ（読まれてはいけない）
	rotAppend(t, filepath.Join(monitorAuditDir, "audit_log.jsonl.2026-10-16"),
		`{"time":"2026-10-16T10:00:00+09:00","event":"login","user":"bob@example.com","ip":"192.0.2.50","result":"success"}`+"\n")
	rotAppend(t, e.auditLog, "") // 空の audit.log

	expectMsgs(t, "#1 first run", e.collect(t, "#1"))

	rotAppend(t, e.auditLog, line(t, 1, `User created: "alice@example.com"`))
	res := e.collect(t, "#2")
	expectMsgs(t, "#2", res, `audit:User created: "alice@example.com"`)
	if ev := res.Events[0]; ev.User != "alice@example.com" || ev.IP != "192.0.2.10" || ev.TS != "2026-10-16T12:00:01+09:00" {
		t.Fatalf("event = %+v", ev)
	}
	raw, err := os.ReadFile(e.jsonl)
	if err != nil {
		t.Fatalf("nextcloud.jsonl not written: %v", err)
	}
	if strings.Count(string(raw), "\n") != 1 || strings.Contains(string(raw), "bob@example.com") {
		t.Fatalf("nextcloud.jsonl = %q, want only the Nextcloud audit.log event", raw)
	}
	expectMsgs(t, "#3", e.collect(t, "#3"))
}

// 状態が無い初回は過去分を送らず、2 回目以降は増えた分だけ返す。書きかけの行は改行が来てから返す。
func TestCollectFirstRunSkipsBacklogThenReturnsOnlyNew(t *testing.T) {
	e := newNCTestEnv(t)
	for i := 0; i < 3; i++ {
		rotAppend(t, e.appLog, line(t, i, fmt.Sprintf("app-old-%d", i)))
		rotAppend(t, e.auditLog, line(t, i, fmt.Sprintf("audit-old-%d", i)))
	}

	res1 := e.collect(t, "#1")
	expectMsgs(t, "#1 first run", res1)
	if _, err := os.Stat(e.state); err != nil {
		t.Fatalf("#1: state file not written: %v", err)
	}

	rotAppend(t, e.appLog, line(t, 10, "app-new-1"))
	rotAppend(t, e.auditLog, line(t, 10, "audit-new-1"))
	partial := strings.TrimSuffix(line(t, 11, "audit-partial"), "\n")
	rotAppend(t, e.auditLog, partial) // 改行がまだ来ていない
	expectMsgs(t, "#2", e.collect(t, "#2"), "app:app-new-1", "audit:audit-new-1")

	rotAppend(t, e.auditLog, "\n")
	expectMsgs(t, "#3", e.collect(t, "#3"), "audit:audit-partial")
	expectMsgs(t, "#4", e.collect(t, "#4"))

	if n := countLines(t, e.jsonl); n != 3 {
		t.Fatalf("nextcloud.jsonl lines = %d, want 3", n)
	}

	// 状態ファイルには元のファイルごとの位置と（取れる環境では）inode が入る
	var st tailState
	b, _ := os.ReadFile(e.state)
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("state: %v", err)
	}
	ai, _ := os.Stat(e.auditLog)
	if got := st.Files["audit"]; got == nil || got.Path != e.auditLog || got.Offset != ai.Size() {
		t.Fatalf("state audit = %+v, want path=%s offset=%d", got, e.auditLog, ai.Size())
	}

	// 読むファイルの設定が変わったら、そのファイルも初回扱い（過去分を送らない）
	other := filepath.Join(filepath.Dir(e.auditLog), "audit-other.log")
	rotAppend(t, other, line(t, 20, "other-old"))
	e.cfg.Paths.NcAuditLog = other
	expectMsgs(t, "#5 path changed", e.collect(t, "#5"))
	rotAppend(t, other, line(t, 21, "other-new"))
	expectMsgs(t, "#6", e.collect(t, "#6"), "audit:other-new")
}

// copytruncate（nextcloud.log）: 元のファイルを .1 に写して切り詰めても、取りこぼしも重複もない。
func TestCollectCopytruncateWithPrevNoLossNoDup(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, line(t, 0, "old-0"))
	e.collect(t, "#1")

	rotAppend(t, e.appLog, line(t, 1, "a1")+line(t, 2, "a2"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "app:a1", "app:a2")

	rotAppend(t, e.appLog, line(t, 3, "a3")+line(t, 4, "a4")) // まだ読んでいない
	data, err := os.ReadFile(e.appLog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.appLog+".1", data, 0o600); err != nil { // copy
		t.Fatal(err)
	}
	if err := os.Truncate(e.appLog, 0); err != nil { // truncate（inode は同じ）
		t.Fatal(err)
	}
	rotAppend(t, e.appLog, line(t, 5, "b1")+line(t, 6, "b2"))

	expectMsgs(t, "#3 after copytruncate", e.collect(t, "#3"), "app:a3", "app:a4", "app:b1", "app:b2")
	expectMsgs(t, "#4", e.collect(t, "#4"))
	rotAppend(t, e.appLog, line(t, 7, "b3"))
	expectMsgs(t, "#5", e.collect(t, "#5"), "app:b3")
}

// 切り詰められたが .1 が無い（小さい）ときは、元のファイルを 0 から読むだけ。
func TestCollectTruncatedWithoutPrevReadsFromStart(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, line(t, 0, "old-0"))
	e.collect(t, "#1")
	rotAppend(t, e.appLog, line(t, 1, "a1"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "app:a1")

	if err := os.Truncate(e.appLog, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.appLog+".1", []byte(line(t, 0, "too-small")), 0o600); err != nil { // 記録した位置より小さい
		t.Fatal(err)
	}
	rotAppend(t, e.appLog, line(t, 2, "b1"))
	expectMsgs(t, "#3", e.collect(t, "#3"), "app:b1")
	expectMsgs(t, "#4", e.collect(t, "#4"))
}

// create（audit.log）: .1 へ名前を変えて新しいファイルを作り、その新しいファイルが次の回までに
// 記録した位置より大きく育っていても、inode の変化で切り替えを見分け、取りこぼしも重複もない。
// （大きさだけで見ると、育った新しいファイルを記録した位置から読み、行の途中から読む・前半を落とす）
func TestCollectCreateRotationNewFileGrewPastOffset(t *testing.T) {
	ino := fakeInodes(t)
	e := newNCTestEnv(t)
	ino[e.auditLog] = 101
	rotAppend(t, e.auditLog, line(t, 0, "old-0"))
	e.collect(t, "#1")
	rotAppend(t, e.auditLog, line(t, 1, "a1"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "audit:a1")

	rotAppend(t, e.auditLog, line(t, 2, "a2")) // まだ読んでいない
	if err := os.Rename(e.auditLog, e.auditLog+".1"); err != nil {
		t.Fatal(err)
	}
	ino[e.auditLog+".1"] = 101 // 旧ファイルがそのまま .1 になる
	ino[e.auditLog] = 202      // 新しいファイル
	var grown strings.Builder
	want := []string{"audit:a2"}
	for i := 0; i < 8; i++ {
		grown.WriteString(line(t, 10+i, fmt.Sprintf("b%d-long-message-to-make-the-new-file-larger", i)))
		want = append(want, fmt.Sprintf("audit:b%d-long-message-to-make-the-new-file-larger", i))
	}
	rotAppend(t, e.auditLog, grown.String())
	old, _ := os.Stat(e.auditLog + ".1")
	cur, _ := os.Stat(e.auditLog)
	if cur.Size() <= old.Size() {
		t.Fatalf("test setup: new file (%d) must be larger than the recorded offset (%d)", cur.Size(), old.Size())
	}

	expectMsgs(t, "#3 after create rotation", e.collect(t, "#3"), want...)
	expectMsgs(t, "#4", e.collect(t, "#4"))
}

// 1 回の上限で打ち切られ、次の回に残りが出て、合計で取りこぼしも重複もない。
// 打ち切った回の CollectResult の JSON は上限以下。2 つの元のファイルの両方が先へ進む。
func TestCollectResultCappedAndCarriedOver(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, "")
	rotAppend(t, e.auditLog, "")
	e.collect(t, "#1")

	const nApp, nAudit = 600, 3000
	pad := strings.Repeat("x", 300)
	var app, audit strings.Builder
	for i := 0; i < nApp; i++ {
		app.WriteString(line(t, i, fmt.Sprintf("app-%04d %s", i, pad)))
	}
	for i := 0; i < nAudit; i++ {
		audit.WriteString(line(t, i, fmt.Sprintf("File accessed: \"/alice@example.com/files/%04d\" %s", i, pad)))
	}
	rotAppend(t, e.appLog, app.String())
	rotAppend(t, e.auditLog, audit.String())

	seen := map[string]int{}
	truncatedRounds := 0
	for round := 1; round <= 20; round++ {
		res := e.collect(t, fmt.Sprintf("round %d", round))
		b, err := json.Marshal(res)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > maxResultJSONBytes {
			t.Fatalf("round %d: CollectResult JSON = %d bytes, want <= %d", round, len(b), maxResultJSONBytes)
		}
		if res.Truncated {
			truncatedRounds++
			if len(res.CollectNotes()) == 0 {
				t.Fatalf("round %d: truncated but no note", round)
			}
		}
		if round == 1 {
			var a, u int
			for _, ev := range res.Events {
				if ev.Source == "app" {
					a++
				} else {
					u++
				}
			}
			if !res.Truncated || a == 0 || u == 0 {
				t.Fatalf("round 1: truncated=%v app=%d audit=%d, want truncated with both sources", res.Truncated, a, u)
			}
		}
		for _, m := range msgsOf(res) {
			seen[m]++
		}
		if res.NewEvents == 0 {
			break
		}
	}
	if truncatedRounds < 2 {
		t.Fatalf("truncated rounds = %d, want >= 2", truncatedRounds)
	}
	if len(seen) != nApp+nAudit {
		t.Fatalf("unique events = %d, want %d", len(seen), nApp+nAudit)
	}
	for m, n := range seen {
		if n != 1 {
			t.Fatalf("%q returned %d times", m, n)
		}
	}
	if n := countLines(t, e.jsonl); n != nApp+nAudit {
		t.Fatalf("nextcloud.jsonl lines = %d, want %d", n, nApp+nAudit)
	}
}

// .1 の続きを読んでいる途中で上限に達したら、次の回に .1 の続き、続けて新しいファイルを読む。
func TestCollectCapWhileDrainingPrevContinuesNextTime(t *testing.T) {
	orig := maxResultJSONBytes
	maxResultJSONBytes = 4096
	t.Cleanup(func() { maxResultJSONBytes = orig })
	ino := fakeInodes(t)

	e := newNCTestEnv(t)
	ino[e.auditLog] = 7
	rotAppend(t, e.auditLog, "")
	e.collect(t, "#1")

	var want []string
	var old strings.Builder
	for i := 0; i < 30; i++ {
		old.WriteString(line(t, i, fmt.Sprintf("a%02d", i)))
		want = append(want, fmt.Sprintf("audit:a%02d", i))
	}
	rotAppend(t, e.auditLog, old.String())
	if err := os.Rename(e.auditLog, e.auditLog+".1"); err != nil {
		t.Fatal(err)
	}
	ino[e.auditLog+".1"] = 7
	ino[e.auditLog] = 8
	var cur strings.Builder
	for i := 0; i < 5; i++ {
		cur.WriteString(line(t, 40+i, fmt.Sprintf("b%02d", i)))
		want = append(want, fmt.Sprintf("audit:b%02d", i))
	}
	rotAppend(t, e.auditLog, cur.String())

	var got []string
	for round := 1; round <= 50; round++ {
		res := e.collect(t, fmt.Sprintf("round %d", round))
		if b, _ := json.Marshal(res); len(b) > maxResultJSONBytes {
			t.Fatalf("round %d: JSON %d bytes > %d", round, len(b), maxResultJSONBytes)
		}
		got = append(got, msgsOf(res)...)
		if res.NewEvents == 0 {
			break
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("events over rounds =\n%q\nwant\n%q", got, want)
	}
}

// 1 件だけで上限を超えるイベントは送らずに読み飛ばし、止まらずに先へ進む。
func TestCollectSkipsOversizedEvent(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.auditLog, "")
	e.collect(t, "#1")

	rotAppend(t, e.auditLog, line(t, 1, strings.Repeat("y", maxResultJSONBytes+1))+line(t, 2, "after-oversized"))
	res := e.collect(t, "#2")
	expectMsgs(t, "#2", res, "audit:after-oversized")
	if res.SkippedOversize != 1 || len(res.CollectNotes()) == 0 {
		t.Fatalf("SkippedOversize=%d notes=%q, want 1 and a note", res.SkippedOversize, res.CollectNotes())
	}
	expectMsgs(t, "#3", e.collect(t, "#3"))
}
