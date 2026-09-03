package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/report"
)

// TestEncodeCollectorErrorUsesErrorKey は収集失敗が null ではなく _error を持つ
// オブジェクトになることを固定する。null にすると受信側で「この環境には無い項目」と
// 「取ろうとして失敗した」が区別できなくなる。
func TestEncodeCollectorErrorUsesErrorKey(t *testing.T) {
	raw := encodeCollectorError(errors.New("df: command not found"))

	var got map[string]string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got[report.ErrorKey] != "df: command not found" {
		t.Fatalf("payload = %v, want %s to carry the message", got, report.ErrorKey)
	}
}

// TestRunCollectorsSkipsDisabled は [collectors.jobs] で false にした collector を
// 実行も報告もしないことを確認する。
func TestRunCollectorsSkipsDisabled(t *testing.T) {
	cfg := &AgentConfig{}
	cfg.Agent.ID = "agent-example-01"
	cfg.Collectors.Jobs = map[string]bool{}
	for _, c := range registeredCollectors(cfg) {
		cfg.Collectors.Jobs[c.Name()] = false
	}

	results := runCollectors(context.Background(), cfg, collector.Config{}, discardLogger())
	if len(results) != 0 {
		t.Fatalf("all collectors disabled but got %d results", len(results))
	}
}

// TestRunCollectorsRecordsErrorOnExpiredContext は全体タイムアウト後の collector が
// 黙って消えず、_error として残ることを確認する。欠けたキーと失敗を混ぜない。
func TestRunCollectorsRecordsErrorOnExpiredContext(t *testing.T) {
	cfg := &AgentConfig{}
	cfg.Agent.ID = "agent-example-01"

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	results := runCollectors(ctx, cfg, collector.Config{}, discardLogger())
	if len(results) != len(registeredCollectors(cfg)) {
		t.Fatalf("results = %d, want one entry per collector", len(results))
	}
	for name, raw := range results {
		var got map[string]string
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("collector %s: unmarshal: %v", name, err)
		}
		if got[report.ErrorKey] == "" {
			t.Fatalf("collector %s: expected %s, got %v", name, report.ErrorKey, got)
		}
	}
}

// TestPayloadShape は送信する JSON のキー構成を固定する。ワイヤ仕様の一部。
func TestPayloadShape(t *testing.T) {
	payload := report.Build("agent-example-01", "example shared host", "rental",
		time.Now(), nil, map[string]json.RawMessage{"host": json.RawMessage(`{"hostname":"host.example.net"}`)})

	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, key := range []string{"agent_id", "agent_label", "agent_type", "reported_at", "collectors"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("payload is missing %q: %s", key, string(body))
		}
	}
}
