package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEncodingPreservesLegacyOrderLocationNullAndError(t *testing.T) {
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	loc := time.FixedZone("example", 9*3600)
	values := map[string]any{"absent": nil, "failed": map[string]string{"_error": "example"}}
	body, err := EncodePayload(Identity{ID: "example-agent", Label: "example", Type: "vps"}, at, loc, values, SortedCompact, false)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"agent_id":"example-agent","agent_label":"example","agent_type":"vps","collectors":{"absent":null,"failed":{"_error":"example"}},"reported_at":"2026-01-02T12:04:05+09:00"}`
	if string(body) != want {
		t.Fatalf("legacy wire changed: %s", body)
	}
	bad := map[string]any{"bad": make(chan int)}
	if body, err := EncodePayload(Identity{}, at, nil, bad, SortedCompact, true); err != nil || string(body) != "{}" {
		t.Fatal("legacy empty-object fallback changed")
	}
	if _, err := EncodePayload(Identity{}, at, nil, bad, SortedIndented, false); err == nil {
		t.Fatal("one-shot marshal failure ignored")
	}
}
func TestTypedCollectorEncodingAndNotes(t *testing.T) {
	opts := testOptions()
	opts.Tasks = []Task{task("bad", func(context.Context) (any, error) { return make(chan int), nil }), task("missing", func(context.Context) (any, error) { return nil, nil }), task("failed", func(context.Context) (any, error) { return nil, errors.New("example") })}
	r, _ := New(opts)
	values, err := r.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	body, err := r.encode(values)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(parsed["collectors"]), `"_error"`) {
		t.Fatal("marshal error not reported")
	}
	if !strings.Contains(string(parsed["collectors"]), `"missing": null`) {
		t.Fatal("normal nil changed")
	}
}
