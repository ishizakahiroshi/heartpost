package nextcloud

// 2026-10-16 のレビュー（164363b を崩しにいくレビュー）の F1〜F8 を、合成の再現で確かめるテスト。
// 修正前（164363b）で失敗し、修正後に通ることを確かめた。

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func setCap(t *testing.T, n int) {
	t.Helper()
	orig := maxResultJSONBytes
	maxResultJSONBytes = n
	t.Cleanup(func() { maxResultJSONBytes = orig })
}

// copyTruncate は logrotate の copytruncate を模す（本体を .1 へ写し、本体を 0 に切り詰める。inode は同じ）。
func copyTruncate(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".1", data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
}

func editState(t *testing.T, path string, edit func(files map[string]map[string]interface{})) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	files := map[string]map[string]interface{}{}
	for k, v := range raw["files"].(map[string]interface{}) {
		files[k] = v.(map[string]interface{})
	}
	edit(files)
	raw["files"] = files
	out, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// F1: copytruncate の後、次の回までに新しいファイルが記録位置より大きく育っても見落とさない。
func TestReviewF1CopytruncateNewFileGrewPastOffset(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, line(t, 0, "old-0"))
	e.collect(t, "#1")
	rotAppend(t, e.appLog, line(t, 1, "a1"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "app:a1")

	rotAppend(t, e.appLog, line(t, 2, "a2")) // 読ませる前に
	copyTruncate(t, e.appLog)
	want := []string{"app:a2"}
	for i := 0; i < 10; i++ {
		rotAppend(t, e.appLog, line(t, 10+i, fmt.Sprintf("b%d", i)))
		want = append(want, fmt.Sprintf("app:b%d", i))
	}
	expectMsgs(t, "#3", e.collect(t, "#3"), want...)
	expectMsgs(t, "#4", e.collect(t, "#4"))
}

// F2: .1 の続きを読んでいる途中にもう一度 copytruncate が入っても、本体の分を落とさない。
func TestReviewF2SecondCopytruncateWhileDrainingPrev(t *testing.T) {
	setCap(t, 4096)
	e := newNCTestEnv(t)
	// 初めの分を大きくして、1 回目の切り替えは大きさの縮みでも見分けられるようにする（F1 と切り分けるため）
	var old strings.Builder
	for i := 0; i < 20; i++ {
		old.WriteString(line(t, i, fmt.Sprintf("old-%02d", i)))
	}
	rotAppend(t, e.appLog, old.String())
	e.collect(t, "#1")

	var a strings.Builder
	for i := 0; i < 40; i++ {
		a.WriteString(line(t, 100+i, fmt.Sprintf("a%02d", i)))
	}
	rotAppend(t, e.appLog, a.String())
	copyTruncate(t, e.appLog) // 1 回目
	for i := 0; i < 5; i++ {
		rotAppend(t, e.appLog, line(t, 200+i, fmt.Sprintf("b%02d", i)))
	}
	res2 := e.collect(t, "#2")
	if !res2.Truncated || len(res2.Events) == 0 {
		t.Fatalf("test setup: #2 must stop in the middle of .1 (truncated=%v events=%d)", res2.Truncated, len(res2.Events))
	}
	got := msgsOf(res2)

	for i := 5; i < 10; i++ {
		rotAppend(t, e.appLog, line(t, 200+i, fmt.Sprintf("b%02d", i)))
	}
	// 2 回目: 今の .1 は .2 へ（実機では圧縮される）、本体（b00..b09）を .1 へ写して切り詰める
	if err := os.Rename(e.appLog+".1", e.appLog+".2"); err != nil {
		t.Fatal(err)
	}
	copyTruncate(t, e.appLog)
	for i := 0; i < 3; i++ {
		rotAppend(t, e.appLog, line(t, 300+i, fmt.Sprintf("c%02d", i)))
	}
	for round := 3; round < 40; round++ {
		res := e.collect(t, fmt.Sprintf("#%d", round))
		got = append(got, msgsOf(res)...)
		if res.NewEvents == 0 {
			break
		}
	}

	var bc, wantBC []string
	nextA := 0
	seen := map[string]bool{}
	for _, m := range got {
		if seen[m] {
			t.Fatalf("%q returned twice (all: %q)", m, got)
		}
		seen[m] = true
		if strings.HasPrefix(m, "app:a") {
			if m != fmt.Sprintf("app:a%02d", nextA) {
				t.Fatalf("a lines out of order: got %q, want app:a%02d (all: %q)", m, nextA, got)
			}
			nextA++
			continue
		}
		bc = append(bc, m)
	}
	for i := 0; i < 10; i++ {
		wantBC = append(wantBC, fmt.Sprintf("app:b%02d", i))
	}
	for i := 0; i < 3; i++ {
		wantBC = append(wantBC, fmt.Sprintf("app:c%02d", i))
	}
	if strings.Join(bc, ",") != strings.Join(wantBC, ",") {
		t.Fatalf("b/c lines = %q, want %q", bc, wantBC)
	}
}

// F3: 古い .1 が残ったまま本体を手で切り詰めても、.1（昨日の分）を送り直さない。
func TestReviewF3StalePrevAfterManualTruncate(t *testing.T) {
	e := newNCTestEnv(t)
	var y strings.Builder
	for i := 0; i < 40; i++ {
		y.WriteString(line(t, 200+i, fmt.Sprintf("yesterday-%02d", i)))
	}
	rotAppend(t, e.appLog+".1", y.String())
	rotAppend(t, e.appLog, line(t, 0, "today-0"))
	e.collect(t, "#1")
	rotAppend(t, e.appLog, line(t, 1, "today-1"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "app:today-1")

	if err := os.Truncate(e.appLog, 0); err != nil {
		t.Fatal(err)
	}
	rotAppend(t, e.appLog, line(t, 2, "n1"))
	expectMsgs(t, "#3", e.collect(t, "#3"), "app:n1")
	expectMsgs(t, "#4", e.collect(t, "#4"))
}

// F4: create が続き、新しいファイルが古い inode を使い回しても、新しいファイルを途中から読まない。
func TestReviewF4CreateReusesOldInode(t *testing.T) {
	ino := fakeInodes(t)
	e := newNCTestEnv(t)
	ino[e.auditLog] = 5
	rotAppend(t, e.auditLog, line(t, 0, "A-old"))
	e.collect(t, "#1")
	rotAppend(t, e.auditLog, line(t, 1, "A-1"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "audit:A-1")

	// 次の回までに create が 2 回: A → .1 → .2（圧縮で消える）、B → .1、新しい C が A の inode 5 を使い回す
	if err := os.Rename(e.auditLog, e.auditLog+".2"); err != nil {
		t.Fatal(err)
	}
	rotAppend(t, e.auditLog+".1", line(t, 50, "B-0")+line(t, 51, "B-1"))
	ino[e.auditLog+".1"] = 6
	var c strings.Builder
	var want []string
	for i := 0; i < 8; i++ {
		c.WriteString(line(t, 60+i, fmt.Sprintf("C-%d-long-message-to-grow-the-file", i)))
		want = append(want, fmt.Sprintf("audit:C-%d-long-message-to-grow-the-file", i))
	}
	rotAppend(t, e.auditLog, c.String())
	ino[e.auditLog] = 5
	expectMsgs(t, "#3", e.collect(t, "#3"), want...)
	expectMsgs(t, "#4", e.collect(t, "#4"))
}

// F5: 1 回の結果は 2 つのファイルの合計で 1000 件まで（Monitor は 1 回の報告で 1 collector あたり
// 最後の 1000 件しか残さない）。残りは次の回に出て、合計で取りこぼしも重複もない。
func TestReviewF5AtMost1000EventsPerResult(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, "")
	rotAppend(t, e.auditLog, "")
	e.collect(t, "#1")
	var app, audit strings.Builder
	for i := 0; i < 1500; i++ {
		app.WriteString(line(t, i, fmt.Sprintf("a%04d", i)))
		audit.WriteString(line(t, i, fmt.Sprintf("u%04d", i)))
	}
	rotAppend(t, e.appLog, app.String())
	rotAppend(t, e.auditLog, audit.String())

	seen := map[string]int{}
	for round := 2; round < 20; round++ {
		res := e.collect(t, fmt.Sprintf("#%d", round))
		if len(res.Events) > 1000 {
			t.Fatalf("#%d: %d events in one result, want <= 1000", round, len(res.Events))
		}
		for _, m := range msgsOf(res) {
			seen[m]++
		}
		if res.NewEvents == 0 {
			break
		}
	}
	if len(seen) != 3000 {
		t.Fatalf("unique events = %d, want 3000", len(seen))
	}
	for m, n := range seen {
		if n != 1 {
			t.Fatalf("%q returned %d times", m, n)
		}
	}
}

// F6: 位置の保存に失敗しても、次の回に nextcloud.jsonl へ同じイベントを重ねて足さない。
func TestReviewF6StateSaveFailureDoesNotDuplicateJSONL(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.auditLog, line(t, 0, "old"))
	e.collect(t, "#1")
	rotAppend(t, e.auditLog, line(t, 1, "n1")+line(t, 2, "n2"))

	// 位置の保存を失敗させる（一時ファイルの場所にフォルダを置く）
	blocker := e.state + ".tmp"
	if err := os.MkdirAll(blocker, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Collector{}).Collect(e.cfg); err == nil {
		t.Fatal("#2: want an error while the state cannot be saved")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}

	expectMsgs(t, "#3", e.collect(t, "#3"), "audit:n1", "audit:n2")
	if n := countLines(t, e.jsonl); n != 2 {
		t.Fatalf("#3: nextcloud.jsonl lines = %d, want 2", n)
	}
	expectMsgs(t, "#4", e.collect(t, "#4"))
	if n := countLines(t, e.jsonl); n != 2 {
		t.Fatalf("#4: nextcloud.jsonl lines = %d, want 2", n)
	}
}

// F6: 追記の後の位置の保存だけが失敗したとき、次の回に追記中の印から nextcloud.jsonl を切り詰めて
// 読み直す（重ねて足さない）。saveStateFn は修正で足した差し替え口なので、修正前では回せない。
func TestReviewF6RecoversWhenFinalStateSaveFails(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.auditLog, line(t, 0, "old"))
	e.collect(t, "#1")
	rotAppend(t, e.auditLog, line(t, 1, "n1")+line(t, 2, "n2"))

	saveStateFn = func(path string, st *tailState) error {
		if st.Appending == nil {
			return fmt.Errorf("injected: final state save failed")
		}
		return saveState(path, st)
	}
	t.Cleanup(func() { saveStateFn = saveState })
	if _, err := (&Collector{}).Collect(e.cfg); err == nil {
		t.Fatal("#2: want the injected save error")
	}
	if n := countLines(t, e.jsonl); n != 2 {
		t.Fatalf("#2: test setup: the append must have happened (jsonl lines = %d)", n)
	}
	saveStateFn = saveState

	expectMsgs(t, "#3", e.collect(t, "#3"), "audit:n1", "audit:n2")
	if n := countLines(t, e.jsonl); n != 2 {
		t.Fatalf("#3: nextcloud.jsonl lines = %d, want 2", n)
	}
	expectMsgs(t, "#4", e.collect(t, "#4"))
	if n := countLines(t, e.jsonl); n != 2 {
		t.Fatalf("#4: nextcloud.jsonl lines = %d, want 2", n)
	}
}

// F6: 追記で nextcloud.jsonl が 10MB を超えて .1 へ名前が変わった後に位置の保存が失敗しても、
// 次の回に .1（名前が変わった方）を切り詰めない。
func TestReviewF6RecoverDoesNotTruncateRotatedJSONL(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.auditLog, line(t, 0, "old"))
	e.collect(t, "#1")
	pad := `{"ts":"2000-01-01T00:00:00+09:00","source":"pad","msg":"` + strings.Repeat("x", 1000) + `"}` + "\n"
	rotAppend(t, e.jsonl, strings.Repeat(pad, 10600))
	rotAppend(t, e.auditLog, line(t, 1, "n1"))

	saveStateFn = func(path string, st *tailState) error {
		if st.Appending == nil {
			return fmt.Errorf("injected: final state save failed")
		}
		return saveState(path, st)
	}
	t.Cleanup(func() { saveStateFn = saveState })
	if _, err := (&Collector{}).Collect(e.cfg); err == nil {
		t.Fatal("#2: want the injected save error")
	}
	saveStateFn = saveState
	rotated, err := os.Stat(e.jsonl + ".1")
	if err != nil {
		t.Fatalf("#2: test setup: nextcloud.jsonl must have been rotated: %v", err)
	}

	expectMsgs(t, "#3", e.collect(t, "#3"), "audit:n1")
	after, err := os.Stat(e.jsonl + ".1")
	if err != nil || after.Size() != rotated.Size() {
		t.Fatalf("#3: nextcloud.jsonl.1 changed (before %d, after %v / %v)", rotated.Size(), after, err)
	}
	if n := countLines(t, e.jsonl); n != 1 {
		t.Fatalf("#3: new nextcloud.jsonl lines = %d, want 1", n)
	}
}

// F7: 状態ファイルの位置が負なら、そのファイルは初回扱い（末尾まで進めるだけ）。もう片方は止まらない。
func TestReviewF7NegativeOffsetTreatedAsFirstRun(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, line(t, 0, "app-old"))
	rotAppend(t, e.auditLog, line(t, 0, "audit-old"))
	e.collect(t, "#1")
	editState(t, e.state, func(files map[string]map[string]interface{}) { files["app"]["offset"] = -5 })

	rotAppend(t, e.auditLog, line(t, 1, "audit-new"))
	expectMsgs(t, "#2", e.collect(t, "#2"), "audit:audit-new")
	rotAppend(t, e.appLog, line(t, 1, "app-new"))
	expectMsgs(t, "#3", e.collect(t, "#3"), "app:app-new")
}

// F7: 状態ファイルに位置の項目が無いときも初回扱い（全部送り直さない）。
func TestReviewF7MissingOffsetTreatedAsFirstRun(t *testing.T) {
	e := newNCTestEnv(t)
	rotAppend(t, e.auditLog, line(t, 0, "audit-old-0")+line(t, 1, "audit-old-1"))
	e.collect(t, "#1")
	editState(t, e.state, func(files map[string]map[string]interface{}) { delete(files["audit"], "offset") })

	expectMsgs(t, "#2", e.collect(t, "#2"))
	rotAppend(t, e.auditLog, line(t, 2, "audit-new"))
	expectMsgs(t, "#3", e.collect(t, "#3"), "audit:audit-new")
}

// F8: nextcloud.log 側にたまった分があっても、audit.log 側の大きめの 1 件が先送りされ続けない。
func TestReviewF8LargeAuditEventNotStarvedByAppBacklog(t *testing.T) {
	setCap(t, 4096)
	e := newNCTestEnv(t)
	rotAppend(t, e.appLog, "")
	rotAppend(t, e.auditLog, "")
	e.collect(t, "#1")

	var app strings.Builder
	for i := 0; i < 200; i++ {
		app.WriteString(line(t, i, fmt.Sprintf("a%03d", i)))
	}
	rotAppend(t, e.appLog, app.String())
	// 上限の半分より大きく、全体よりは小さい 1 件
	rotAppend(t, e.auditLog, line(t, 500, "BIG "+strings.Repeat("z", 2600)))

	for round := 2; round <= 3; round++ {
		res := e.collect(t, fmt.Sprintf("#%d", round))
		for _, ev := range res.Events {
			if ev.Source == "audit" && strings.HasPrefix(ev.Msg, "BIG ") {
				return
			}
		}
		if !res.Truncated {
			t.Fatalf("test setup: app backlog must remain in #%d", round)
		}
	}
	t.Fatal("the large audit event was deferred for 2 rounds while the app backlog remained")
}
