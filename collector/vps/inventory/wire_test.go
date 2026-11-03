package inventory

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
	"github.com/ishizakahiroshi/heartpost/report"
)

// Export only synthetic observations. The consumer's isolated test can read
// these bytes without a go.mod replace or a release of the producer module.
func TestInventoryWireFixture(t *testing.T) {
	proc := t.TempDir()
	now := time.Now().UTC()
	bodies := []json.RawMessage{}
	for i, version := range []string{"1.0", "2.0"} {
		at := now.Add(time.Duration(i-1) * time.Minute)
		c := &Collector{lookPath: func(name string) (string, error) { return name, nil }, goos: "linux", now: func() time.Time { return at }, readDir: func(string) ([]os.DirEntry, error) { return os.ReadDir(proc) }, readFile: func(string) ([]byte, error) { return []byte("ID=debian\nVERSION_ID=13\n"), nil }, run: func(name string, args ...string) ([]byte, error) {
			switch name {
			case "uname":
				return []byte("6.1-fixture\n"), nil
			case "dpkg-query":
				return []byte("sample\t" + version + "\tamd64\tinstalled\n"), nil
			default:
				return nil, exec.ErrNotFound
			}
		}}
		value, err := c.Collect(vps.Config{})
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		payload := report.Build("alpha-vps-example", "Synthetic host", "vps", at, time.UTC, map[string]json.RawMessage{"inventory": raw})
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	if dir := os.Getenv("HEARTPOST_INVENTORY_WIRE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		data, _ := json.MarshalIndent(bodies, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "inventory-wire.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
