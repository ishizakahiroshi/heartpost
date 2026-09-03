package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// このファイルはワイヤ仕様を固定する。落ちたときは「テストを直す」前に、
// **稼働中の agent が受信側から拒否されないか**を先に考える。すでに動いている
// agent は勝手には更新されないので、キー名の変更・削除・型変更は
// 「全台を入れ替えるまで受信できない期間ができる」ことと同義になる。

const goldenPath = "testdata/report_v1.json"

func fixture(t *testing.T) Payload {
	t.Helper()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	return Build(
		"demo-web-01",
		"demo web server",
		"rental",
		at,
		nil,
		map[string]json.RawMessage{
			"host":    json.RawMessage(`{"hostname":"demo-web-01.example.net","os":"FreeBSD demo 14.0"}`),
			"loadavg": json.RawMessage(`{"load1":0.12,"load5":0.34,"load15":0.56}`),
			"disk":    json.RawMessage(`[{"filesystem":"/dev/da0p2","size":"20G","used":"8.0G","avail":"12G","use_percent":"40%","mounted":"/"}]`),
			"cron":    json.RawMessage(`{"lines":["*/5 * * * * $HOME/bin/heartpost-agent --config $HOME/etc/agent.toml"]}`),
			"network": json.RawMessage(`null`),
			"memory":  json.RawMessage(`{"_error":"sysctl: unknown oid 'hw.physmem'"}`),
		},
	)
}

func TestPayloadMatchesGolden(t *testing.T) {
	got, err := json.Marshal(fixture(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	want, err := os.ReadFile(filepath.FromSlash(goldenPath))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}

	// golden は末尾に改行を 1 つ持つ。
	if len(want) > 0 && want[len(want)-1] == '\n' {
		want = want[:len(want)-1]
	}

	if string(got) != string(want) {
		t.Fatalf("wire format changed.\n got: %s\nwant: %s", got, want)
	}
}

// TestPayloadKeys はトップレベルのキー集合を固定する。フィールドを 1 つ足すだけでも落ちる。
func TestPayloadKeys(t *testing.T) {
	b, err := json.Marshal(fixture(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	got := make([]string, 0, len(m))
	for k := range m {
		got = append(got, k)
	}
	sort.Strings(got)

	want := []string{"agent_id", "agent_label", "agent_type", "collectors", "reported_at"}
	if len(got) != len(want) {
		t.Fatalf("top-level keys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("top-level keys = %v, want %v", got, want)
		}
	}
}

// TestHeaderNames はヘッダ名と既定パスを固定する。受信側の実装と 1 対 1 で対応する。
func TestHeaderNames(t *testing.T) {
	cases := map[string]string{
		HeaderAgentID:   "X-Agent-Id",
		HeaderTimestamp: "X-Agent-Timestamp",
		HeaderSignature: "X-Agent-Signature",
		DefaultPath:     "/api/agent/report",
		ErrorKey:        "_error",
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("constant = %q, want %q", got, want)
		}
	}
}

// TestFormatTime は既定が UTC であることと、loc 指定時にオフセットが付くことを固定する。
func TestFormatTime(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	if got := FormatTime(at, nil); got != "2026-01-02T03:04:05Z" {
		t.Fatalf("FormatTime(nil) = %q", got)
	}

	plus9 := time.FixedZone("+09", 9*60*60)
	if got := FormatTime(at, plus9); got != "2026-01-02T12:04:05+09:00" {
		t.Fatalf("FormatTime(+09) = %q", got)
	}
}

// TestCollectorError は収集失敗の表し方を固定する。null との使い分けが受信側の判定に効く。
func TestCollectorError(t *testing.T) {
	if CollectorError(nil) != nil {
		t.Fatal("CollectorError(nil) should be nil")
	}
	got := CollectorError(os.ErrNotExist)
	if got[ErrorKey] != os.ErrNotExist.Error() {
		t.Fatalf("CollectorError = %v", got)
	}
}
