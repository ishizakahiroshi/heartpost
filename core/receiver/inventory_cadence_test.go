package receiver

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"
	"time"
)

func TestPeriodicInventoryAndHeartbeatHistory(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const id = "sample-vps"
	for index, values := range []map[string]json.RawMessage{
		{"inventory": json.RawMessage(`{"observed_at":"2026-01-01T00:00:00Z","packages":{"status":"ok","value":[{"name":"first"}]}}`)},
		{"host": json.RawMessage(`{"hostname":"fixture"}`)},
		{"inventory": json.RawMessage(`{"observed_at":"2026-01-01T00:10:00Z","packages":{"status":"ok","value":[]}}`)},
	} {
		at := start.Add(time.Duration(index) * 5 * time.Minute)
		if err = store.Append(Record{AgentID: id, Collectors: values}, at); err != nil {
			t.Fatal(err)
		}
		states := store.States()
		if len(states) != 1 || !states[0].LastSeen.Equal(at) {
			t.Fatal("missing heartbeat")
		}
		if events := NewChecker(store, Thresholds{Default: 6 * time.Minute}, nil).Check(context.Background(), at.Add(5*time.Minute)); len(events) != 0 {
			t.Fatal(events)
		}
	}
	// A restarted consumer can replay every retained record. A missing key
	// leaves the previous snapshot intact; an explicit empty collection replaces it.
	reopened, err := NewStore(dir, 7)
	if err != nil {
		t.Fatal(err)
	}
	path, err := reopened.reportPath(id, start)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	var snapshot struct {
		ObservedAt string `json:"observed_at"`
		Packages   struct {
			Value []struct{ Name string } `json:"value"`
		} `json:"packages"`
	}
	for i, want := range []int{1, 1, 0} {
		var rec Record
		if err := dec.Decode(&rec); err != nil {
			t.Fatal(err)
		}
		raw, found := rec.Collectors["inventory"]
		if found != (i != 1) {
			t.Fatal("collector presence changed")
		}
		if found {
			if err := json.Unmarshal(raw, &snapshot); err != nil {
				t.Fatal(err)
			}
		}
		wantTime := start
		if i == 2 {
			wantTime = start.Add(10 * time.Minute)
		}
		if snapshot.ObservedAt != wantTime.Format(time.RFC3339) || len(snapshot.Packages.Value) != want {
			t.Fatalf("snapshot at row %d: %+v", i, snapshot)
		}
	}
	var extra Record
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected trailing record: %v", err)
	}
}
