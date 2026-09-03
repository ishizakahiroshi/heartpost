// Package report は agent から monitor へ送るレポートの形を定める。
//
// ここに書かれている JSON のキー名、HTTP ヘッダ名、既定のパス、時刻の書式は
// **ワイヤ仕様**であり、送信側と受信側の両方が同じ定義を参照する。
//
// 破壊的に変えると、稼働中の agent が受信側から一斉に拒否される。すでに動いている
// agent は勝手には更新されないので、フィールドのリネーム・削除・型変更は
// 「全台を入れ替えるまで受信できない期間ができる」ことと同義になる。
// report_golden_test.go がこの形を固定しているので、変更するとテストが落ちる。
package report

import (
	"encoding/json"
	"time"
)

// HTTP ヘッダ名。agent が付け、monitor が読む。
const (
	// HeaderAgentID は送信元 agent の識別子を運ぶ。
	HeaderAgentID = "X-Agent-Id"
	// HeaderTimestamp は署名対象の Unix 秒（10 進文字列）を運ぶ。
	// 受信側はここを見てリプレイを弾く。
	HeaderTimestamp = "X-Agent-Timestamp"
	// HeaderSignature は agentsig.Compute が返す 16 進文字列を運ぶ。
	HeaderSignature = "X-Agent-Signature"
)

// DefaultPath は monitor 側の受信エンドポイントの既定パス。
const DefaultPath = "/api/agent/report"

// TimeFormat は reported_at の書式。RFC3339 固定（オフセット付き）。
const TimeFormat = time.RFC3339

// Payload は 1 回の送信で運ばれる本体。JSON のキー名は変更しない。
//
// Collectors の値は collector ごとの任意の JSON。収集に失敗した collector は
// null ではなく ErrorKey を持つオブジェクトを入れる。「対象外だから nil」と
// 「取ろうとして失敗した」を受信側で区別するため。
type Payload struct {
	AgentID    string                     `json:"agent_id"`
	AgentLabel string                     `json:"agent_label"`
	AgentType  string                     `json:"agent_type"`
	ReportedAt string                     `json:"reported_at"`
	Collectors map[string]json.RawMessage `json:"collectors"`
}

// ErrorKey は collector の収集失敗を表すオブジェクトのキー。
//
//	"collectors": {"disk": {"_error": "df: command not found"}}
const ErrorKey = "_error"

// CollectorError は収集失敗を表す値を返す。
func CollectorError(err error) map[string]string {
	if err == nil {
		return nil
	}
	return map[string]string{ErrorKey: err.Error()}
}

// FormatTime は reported_at に入れる文字列を返す。
//
// loc が nil なら UTC を使う。既定を実行ホストのローカル時刻にしないのは、
// 複数のサーバーから届いたレポートを受信側で並べたときに、ホストごとに
// 基準が違うと読み違えるため。表示を特定の時間帯へ寄せたい場合だけ loc を渡す。
func FormatTime(t time.Time, loc *time.Location) string {
	if loc == nil {
		loc = time.UTC
	}
	return t.In(loc).Format(TimeFormat)
}

// Build は送信用の Payload を組み立てる。
func Build(agentID, agentLabel, agentType string, at time.Time, loc *time.Location, collectors map[string]json.RawMessage) Payload {
	if collectors == nil {
		collectors = map[string]json.RawMessage{}
	}
	return Payload{
		AgentID:    agentID,
		AgentLabel: agentLabel,
		AgentType:  agentType,
		ReportedAt: FormatTime(at, loc),
		Collectors: collectors,
	}
}
