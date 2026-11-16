package nc_deletion

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
)

// テストの値はすべて合成（example.com・203.0.113.0/24 の文書用アドレス）。

const (
	testUser = "alice@example.com"
	testIP   = "203.0.113.10"
	testUA   = "Mozilla/5.0 (Windows) mirall/35.0.3 (build 20261104) (Nextcloud, windows-10.0)"
)

type env struct {
	t       *testing.T
	ncData  string
	dataDir string
	audit   string
	now     time.Time
	c       *Collector
}

func newEnv(t *testing.T) *env {
	t.Helper()
	base := t.TempDir()
	e := &env{t: t, ncData: filepath.Join(base, "ncdata"), dataDir: filepath.Join(base, "agentdata")}
	e.audit = filepath.Join(e.ncData, "audit.log")
	if err := os.MkdirAll(e.ncData, 0o755); err != nil {
		t.Fatal(err)
	}
	e.now = time.Date(2026, 11, 16, 1, 0, 0, 0, time.UTC)
	e.c = &Collector{Now: func() time.Time { return e.now }}
	e.write("") // 空の audit.log を作る
	return e
}

func (e *env) cfg() optional.Config {
	return optional.Config{Paths: optional.PathConfig{NcAuditLog: e.audit, DataDir: e.dataDir}}
}

func (e *env) write(s string) {
	e.t.Helper()
	f, err := os.OpenFile(e.audit, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		e.t.Fatal(err)
	}
}

func line(t time.Time, user, ip, ua, method, msg string) string {
	b, _ := json.Marshal(map[string]string{
		"reqId": "x", "time": t.UTC().Format(time.RFC3339), "user": user, "remoteAddr": ip,
		"userAgent": ua, "method": method, "app": "admin_audit", "message": msg,
	})
	return string(b) + "\n"
}

func delLine(t time.Time, rel string) string {
	return line(t, testUser, testIP, testUA, "DELETE", fmt.Sprintf(`File with id "%d" deleted: "/%s/files/%s"`, t.Unix()%100000, testUser, rel))
}

func (e *env) collect() Summary {
	e.t.Helper()
	v, err := e.c.Collect(e.cfg())
	if err != nil {
		e.t.Fatal(err)
	}
	s, ok := v.(Summary)
	if !ok {
		e.t.Fatalf("Collect returned %T", v)
	}
	return s
}

func (e *env) records() []Record {
	e.t.Helper()
	f, err := os.Open(filepath.Join(e.dataDir, "logs", "nc_deletion.jsonl"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		e.t.Fatal(err)
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			e.t.Fatalf("bad record %q: %v", sc.Text(), err)
		}
		out = append(out, r)
	}
	return out
}

func TestNoAuditLogReturnsNil(t *testing.T) {
	c := &Collector{}
	v, err := c.Collect(optional.Config{Paths: optional.PathConfig{NcAuditLog: filepath.Join(t.TempDir(), "none.log"), DataDir: t.TempDir()}})
	if err != nil || v != nil {
		t.Fatalf("got %v, %v; want nil, nil", v, err)
	}
}

// 初回は過去の行を記録しない（末尾へ進めるだけ）。
func TestFirstRunSkipsExistingLines(t *testing.T) {
	e := newEnv(t)
	e.write(delLine(e.now.Add(-time.Hour), "A/old.txt"))
	e.collect()
	e.now = e.now.Add(time.Hour)
	e.collect()
	if r := e.records(); len(r) != 0 {
		t.Fatalf("first run recorded %d lines: %+v", len(r), r)
	}
}

// 数分間の大量削除が 1 行にまとまり、フォルダ別の件数・クライアントの種類が入る。
func TestMassDeleteBecomesOneCluster(t *testing.T) {
	e := newEnv(t)
	e.collect() // 初回（位置を覚える）

	start := e.now.Add(time.Minute)
	for i := 0; i < 120; i++ {
		ts := start.Add(time.Duration(i) * time.Second)
		folder := "Shared/Photos/2026"
		if i%3 == 0 {
			folder = "Shared/Invoices"
		}
		e.write(delLine(ts, fmt.Sprintf("%s/img_%03d.jpg", folder, i)))
	}
	// まだ最後の削除から 5 分経っていない: 記録されず、途中の塊として残る
	e.now = start.Add(3 * time.Minute)
	s := e.collect()
	if s.OpenClusters != 1 || len(e.records()) != 0 {
		t.Fatalf("open=%d records=%d; want open 1, records 0", s.OpenClusters, len(e.records()))
	}
	// 5 分を過ぎたら 1 行で記録される
	e.now = start.Add(10 * time.Minute)
	s = e.collect()
	recs := e.records()
	if len(recs) != 1 {
		t.Fatalf("records=%d; want 1: %+v", len(recs), recs)
	}
	r := recs[0]
	if r.Kind != "delete" || r.Count != 120 || r.User != testUser || r.RemoteAddr != testIP || r.Client != "デスクトップ同期クライアント" {
		t.Fatalf("unexpected record: %+v", r)
	}
	if len(r.Folders) != 2 || r.Folders[0].Folder != "Shared/Photos" || r.Folders[0].Count != 80 || r.Folders[1].Count != 40 {
		t.Fatalf("folders = %+v", r.Folders)
	}
	if len(r.Samples) != samplePaths {
		t.Fatalf("samples = %v", r.Samples)
	}
	if s.Clusters24h != 1 || s.Files24h != 120 || s.Largest24h != 120 || s.OpenClusters != 0 {
		t.Fatalf("summary = %+v", s)
	}
	// 要約に名義や接続元を載せない
	b, _ := json.Marshal(s)
	if strings.Contains(string(b), testUser) || strings.Contains(string(b), testIP) {
		t.Fatalf("summary leaks identity: %s", b)
	}
}

// 5 分を超えて空いた削除は別の塊になる。違う名義も別の塊になる。
func TestGapAndDifferentUserSplitClusters(t *testing.T) {
	e := newEnv(t)
	e.collect()
	t0 := e.now.Add(time.Minute)
	e.write(delLine(t0, "A/1.txt"))
	e.write(delLine(t0.Add(10*time.Minute), "A/2.txt"))
	e.write(line(t0.Add(10*time.Minute), "bob@example.com", "203.0.113.20", "Mozilla/5.0 (X11) Firefox/140.0", "DELETE", `File with id "9" deleted: "/bob@example.com/files/B/3.txt"`))
	e.now = t0.Add(30 * time.Minute)
	e.collect()
	recs := e.records()
	if len(recs) != 3 {
		t.Fatalf("records=%d; want 3: %+v", len(recs), recs)
	}
}

// ごみ箱の完全削除・版の削除・保守の操作も記録される。関係のない occ は記録しない。
func TestOtherKindsAndOps(t *testing.T) {
	e := newEnv(t)
	e.collect()
	t0 := e.now.Add(time.Minute)
	e.write(line(t0, testUser, testIP, "Mozilla/5.0 Chrome/140", "DELETE", `File "/files_trashbin/files/a.txt.d1794000000" deleted from trash bin.`))
	e.write(line(t0, testUser, testIP, "Mozilla/5.0 Chrome/140", "DELETE", `Version "/A/b.txt.v1794000000" was deleted.`))
	e.write(line(t0, "--", "", "--", "", "Console command executed: maintenance:mode --on"))
	e.write(line(t0, "--", "", "--", "", "Console command executed: status --output=json"))
	e.write(line(t0, "--", "", "--", "", "Console command executed: upgrade"))
	e.now = t0.Add(10 * time.Minute)
	e.collect()
	kinds := map[string]int{}
	for _, r := range e.records() {
		kinds[r.Kind]++
	}
	want := map[string]int{"trash_purge": 1, "version_delete": 1, "ops": 2}
	for k, n := range want {
		if kinds[k] != n {
			t.Fatalf("kinds = %v; want %v", kinds, want)
		}
	}
	if len(kinds) != len(want) {
		t.Fatalf("kinds = %v; want %v", kinds, want)
	}
}

// ログが切り替わっても、切り替わり前の残りの行を読み落とさない。
func TestRotationReadsRestOfOldFile(t *testing.T) {
	e := newEnv(t)
	e.write(line(e.now, "--", "", "--", "", "Console command executed: status"))
	e.collect() // 位置を覚える
	t0 := e.now.Add(time.Minute)
	e.write(delLine(t0, "A/before-rotate.txt"))
	// logrotate（create）の再現: audit.log -> audit.log.1、新しい空の audit.log
	if err := os.Rename(e.audit, e.audit+".1"); err != nil {
		t.Fatal(err)
	}
	e.write(delLine(t0.Add(time.Second), "A/after-rotate.txt"))
	e.now = t0.Add(10 * time.Minute)
	e.collect()
	recs := e.records()
	if len(recs) != 1 || recs[0].Count != 2 {
		t.Fatalf("records = %+v; want 1 cluster of 2", recs)
	}
}

// 書きかけ（改行の無い）行は次回に回す。
func TestPartialLineIsReadNextTime(t *testing.T) {
	e := newEnv(t)
	e.collect()
	t0 := e.now.Add(time.Minute)
	full := delLine(t0, "A/x.txt")
	e.write(full[:20])
	e.now = t0.Add(10 * time.Minute)
	e.collect()
	if len(e.records()) != 0 {
		t.Fatal("partial line was recorded")
	}
	e.write(full[20:])
	e.collect()
	e.now = e.now.Add(10 * time.Minute)
	e.collect()
	if recs := e.records(); len(recs) != 1 || recs[0].Count != 1 {
		t.Fatalf("records = %+v", recs)
	}
}

// グループフォルダのごみ箱から消えた項目を記録し、戻した記録があるものと分ける。
func TestGroupFolderTrashRemoval(t *testing.T) {
	e := newEnv(t)
	trash := filepath.Join(e.ncData, "__groupfolders", "5", "trash")
	if err := os.MkdirAll(trash, 0o755); err != nil {
		t.Fatal(err)
	}
	old := e.now.Add(-20 * 24 * time.Hour).Unix()
	recentDel := e.now.Add(-time.Hour).Unix()
	names := []string{
		fmt.Sprintf("expired.pdf.d%d", old),
		fmt.Sprintf("restored.jpg.d%d", recentDel),
		fmt.Sprintf("kept.txt.d%d", recentDel),
	}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(trash, n), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e.collect() // 初回は一覧を覚えるだけ
	if len(e.records()) != 0 {
		t.Fatal("first trash scan recorded")
	}
	// 1 件は「戻した」記録あり、1 件は記録なしで消える
	e.write(line(e.now.Add(time.Minute), testUser, testIP, "Mozilla/5.0 Chrome/140", "MOVE", `File "/Shared/A/restored.jpg" restored from trash bin.`))
	for _, n := range names[:2] {
		if err := os.Remove(filepath.Join(trash, n)); err != nil {
			t.Fatal(err)
		}
	}
	e.now = e.now.Add(10 * time.Minute)
	s := e.collect()
	var got *Record
	for _, r := range e.records() {
		if r.Kind == "gf_trash_removed" {
			r := r
			got = &r
		}
	}
	if got == nil {
		t.Fatalf("no gf_trash_removed record: %+v", e.records())
	}
	if got.FolderID != "5" || got.Count != 2 || got.Restored != 1 || got.Unlogged != 1 || got.OlderThan14 != 1 {
		t.Fatalf("record = %+v", *got)
	}
	if s.TrashRemoved24h != 2 {
		t.Fatalf("summary = %+v", s)
	}
}

// 読めないごみ箱を「消えた」と誤って記録しない（前回の一覧を保つ）。
func TestUnreadableTrashKeepsPrevious(t *testing.T) {
	if os.PathSeparator == '\\' {
		// Windows ではファイルへの ReadDir が「存在しない」扱いになり、Linux（ENOTDIR）と同じ失敗を作れない
		t.Skip("Linux の ReadDir の失敗を再現する検査")
	}
	e := newEnv(t)
	st := newState()
	st.TrashSet = true
	st.Trash = map[string][]string{"7": {"a.d1794000000"}}
	root := filepath.Join(e.ncData, "__groupfolders")
	// folder 7 の trash の代わりにファイルを置き、ReadDir を失敗させる
	if err := os.MkdirAll(filepath.Join(root, "7"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "7", "trash"), []byte("not a dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	recs, err := st.scanTrash(root, e.now)
	if err == nil {
		t.Fatal("want error for unreadable trash")
	}
	if len(recs) != 0 {
		t.Fatalf("recorded %+v", recs)
	}
	if len(st.Trash["7"]) != 1 {
		t.Fatalf("previous list lost: %+v", st.Trash)
	}
}

func TestFolderOfAndRelPath(t *testing.T) {
	cases := map[string]string{
		"a.txt":         "/",
		"A/a.txt":       "A",
		"A/B/a.txt":     "A/B",
		"A/B/C/D/a.txt": "A/B",
	}
	for in, want := range cases {
		if got := folderOf(in); got != want {
			t.Errorf("folderOf(%q) = %q; want %q", in, got, want)
		}
	}
	if got := relPath(testUser, "/"+testUser+"/files/A/b.txt"); got != "A/b.txt" {
		t.Errorf("relPath = %q", got)
	}
}

func TestStateAndRecordPermissions(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("権限の検査は Unix だけ")
	}
	e := newEnv(t)
	e.collect()
	e.write(delLine(e.now.Add(time.Minute), "A/x.txt"))
	e.now = e.now.Add(20 * time.Minute)
	e.collect()
	for _, p := range []string{filepath.Join(e.dataDir, "json", "nc_deletion_state.json"), filepath.Join(e.dataDir, "logs", "nc_deletion.jsonl")} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s perm = %o; want 600", p, fi.Mode().Perm())
		}
	}
}
