package httpoutcome

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSinkFuncAndValidateReceipt(t *testing.T) {
	var got Receipt
	var s Sink = SinkFunc(func(r Receipt) error { got = r; return nil })
	good := Receipt{TS: "2026-01-02T03:04:05Z", RequestID: "0123456789abcdef0123456789abcdef", Method: "GET", PathHash: PathHash("/x"), Status: 200, Operation: OpFetchFile, Outcome: OutcomeSuccess}
	if err := ValidateReceipt(good); err != nil {
		t.Fatal(err)
	}
	if err := s.Record(good); err != nil || got != good {
		t.Fatalf("%v %+v", err, got)
	}
	bad := good
	bad.Status = 700
	if ValidateReceipt(bad) == nil {
		t.Fatal("bad status accepted")
	}
}

func TestNewFileSinkRejectsRelativeAndUncleanPaths(t *testing.T) {
	dir := t.TempDir()
	cwd, _ := os.Getwd()
	for _, p := range []string{
		"relative-path-is-invalid.jsonl",
		"./relative.jsonl",
		"",
		dir + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(dir) + string(filepath.Separator) + "r.jsonl",
		dir + string(filepath.Separator) + "." + string(filepath.Separator) + "r.jsonl",
		filepath.Join(dir, "r.jsonl") + string(filepath.Separator),
	} {
		if s, err := NewFileSink(p); err == nil {
			s.Close()
			t.Errorf("accepted %q", p)
		}
	}
	if _, err := os.Stat(filepath.Join(cwd, "relative-path-is-invalid.jsonl")); err == nil {
		t.Fatal("file created in cwd")
	}
}
