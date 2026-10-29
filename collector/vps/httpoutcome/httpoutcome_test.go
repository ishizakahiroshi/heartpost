package httpoutcome

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
	hp "github.com/ishizakahiroshi/heartpost/httpoutcome"
)

func line(id, op, outcome string, status string) string {
	return `{"ts":"2026-01-02T03:04:05Z","request_id":"` + id + `","method":"MKCOL","path_hash":"` +
		strings.Repeat("c", 64) + `","status":` + status + `,"operation":"` + op + `","outcome":"` + outcome + `"}`
}

func id(c string) string { return strings.Repeat(c, 32) }

func setup(t *testing.T, content string) (vps.Config, string) {
	t.Helper()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "r.jsonl")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	if err := os.Mkdir(data, 0o700); err != nil {
		t.Fatal(err)
	}
	return vps.Config{Paths: vps.PathConfig{HTTPOutcomeLogs: []string{p}, DataDir: data}}, p
}

func collect(t *testing.T, cfg vps.Config) *CollectResult {
	t.Helper()
	c := &Collector{Logf: func(string, ...any) {}}
	v, err := c.Collect(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v.(*CollectResult)
}

func TestName(t *testing.T) {
	if (&Collector{}).Name() != "http_outcome" {
		t.Fatal("name")
	}
}

func TestNoConfigReturnsNil(t *testing.T) {
	v, err := (&Collector{}).Collect(vps.Config{})
	if v != nil || err != nil {
		t.Fatalf("%v %v", v, err)
	}
}

func TestValidInvalidAndDedupe(t *testing.T) {
	content := strings.Join([]string{
		line(id("a"), "ensure_collection", "expected", "405"),
		line(id("a"), "ensure_collection", "expected", "405"), // duplicate id
		line(id("b"), "path_exists", "expected", "404"),
		line(id("C"), "path_exists", "expected", "404"), // uppercase id
		line(id("d"), "delete_all", "other", "500"),     // bad operation
		line(id("e"), "fetch_file", "great", "200"),     // bad outcome
		line(id("f"), "fetch_file", "success", "99"),    // bad status
		`{"ts":"2026-01-02T03:04:05Z","request_id":"` + id("1") + `","extra":1}`,
		`garbage`,
		"",
		line(id("2"), "fetch_file", "integration_error", "404"),
	}, "\n") + "\n"
	cfg, _ := setup(t, content)
	res := collect(t, cfg)
	if res.NewEvents != 3 || len(res.Events) != 3 {
		t.Fatalf("events=%d %+v", res.NewEvents, res.Events)
	}
	got := []string{res.Events[0].RequestID, res.Events[1].RequestID, res.Events[2].RequestID}
	if got[0] != id("a") || got[1] != id("b") || got[2] != id("2") {
		t.Fatalf("ids %v", got)
	}
	if res.Dropped == 0 {
		t.Fatal("dropped not counted")
	}
	// Second run ships nothing new.
	if res2 := collect(t, cfg); res2.NewEvents != 0 {
		t.Fatalf("re-sent %d events", res2.NewEvents)
	}
}

func TestLineCap(t *testing.T) {
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, line(strings.Repeat(string(rune('0'+i)), 32), "fetch_file", "success", "200"))
	}
	cfg, _ := setup(t, strings.Join(lines, "\n")+"\n")
	cfg.Rules.HTTPOutcomeLogLines = 4
	res := collect(t, cfg)
	if res.NewEvents != 4 {
		t.Fatalf("events=%d", res.NewEvents)
	}
	// Tail is kept: the newest four.
	if res.Events[3].RequestID != strings.Repeat("9", 32) {
		t.Fatalf("not the tail: %s", res.Events[3].RequestID)
	}
}

func TestMissingFileSkipped(t *testing.T) {
	cfg, p := setup(t, "")
	cfg.Paths.HTTPOutcomeLogs = []string{p + ".absent", p}
	res := collect(t, cfg)
	if len(res.Skipped) != 1 || res.Skipped[0].Reason != "file does not exist" {
		t.Fatalf("%+v", res.Skipped)
	}
	// Reasons never echo file content.
	if strings.Contains(res.Skipped[0].Reason, "{") {
		t.Fatal("reason leaks content")
	}
}

func TestSymlinkSkipped(t *testing.T) {
	cfg, p := setup(t, line(id("a"), "fetch_file", "success", "200")+"\n")
	link := filepath.Join(filepath.Dir(p), "link.jsonl")
	if err := os.Symlink(p, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	cfg.Paths.HTTPOutcomeLogs = []string{link}
	res := collect(t, cfg)
	if res.NewEvents != 0 || len(res.Skipped) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestDataDirRequired(t *testing.T) {
	cfg, _ := setup(t, "")
	cfg.Paths.DataDir = ""
	if _, err := (&Collector{Logf: func(string, ...any) {}}).Collect(cfg); err == nil {
		t.Fatal("no error without data_dir")
	}
}

func TestSinkOutputIsAccepted(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	p := filepath.Join(dir, "r.jsonl")
	s, err := hp.NewFileSink(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Record(hp.Receipt{TS: "2026-01-02T03:04:05Z", RequestID: id("9"), Method: "GET", PathHash: hp.PathHash("/x"), Status: 200, Operation: hp.OpFetchFile, Outcome: hp.OutcomeSuccess}); err != nil {
		t.Fatal(err)
	}
	s.Close()
	data := filepath.Join(dir, "data")
	_ = os.Mkdir(data, 0o700)
	res := collect(t, vps.Config{Paths: vps.PathConfig{HTTPOutcomeLogs: []string{p}, DataDir: data}})
	if res.NewEvents != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestRelativeAndUncleanPathsSkipped(t *testing.T) {
	cfg, p := setup(t, line(id("a"), "fetch_file", "success", "200")+"\n")
	rel := filepath.Base(p)
	sep := string(filepath.Separator)
	unclean := filepath.Dir(p) + sep + ".." + sep + filepath.Base(filepath.Dir(p)) + sep + rel
	cfg.Paths.HTTPOutcomeLogs = []string{rel, unclean}
	res := collect(t, cfg)
	if res.NewEvents != 0 || len(res.Skipped) != 2 {
		t.Fatalf("%+v", res)
	}
	for _, s := range res.Skipped {
		if s.Reason != "path must be absolute and clean" {
			t.Fatalf("reason %q", s.Reason)
		}
	}
}
