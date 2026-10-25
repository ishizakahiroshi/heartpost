package optional_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ishizakahiroshi/heartpost/collector"
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
	"github.com/ishizakahiroshi/heartpost/collector/optional/audit_log_tail"
	"github.com/ishizakahiroshi/heartpost/collector/optional/fail2ban"
	"github.com/ishizakahiroshi/heartpost/collector/optional/nextcloud"
)

type fakeCollector struct{}

func (fakeCollector) Name() string                                     { return "example" }
func (fakeCollector) Interval() string                                 { return "log" }
func (fakeCollector) Collect(cfg optional.Config) (interface{}, error) { return cfg.Paths.DataDir, nil }

func TestAdaptBindsValueConfiguration(t *testing.T) {
	cfg := optional.Config{Paths: optional.PathConfig{DataDir: "example-dir"}}
	bound := optional.Adapt(fakeCollector{}, cfg)
	cfg.Paths.DataDir = "caller-change"
	got, err := bound.Collect(collector.Config{})
	if bound.Name() != "example" || got != "example-dir" || err != nil {
		t.Fatalf("adapter=%s %v %v", bound.Name(), got, err)
	}
}

func TestRequiredDataDirectoryPreventsWorkingDirectoryWrites(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	source := filepath.Join(base, "source.log")
	if err := os.WriteFile(source, []byte("{}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := optional.Config{Paths: optional.PathConfig{AuditLog: base, NextcloudLog: source, Fail2banLog: source}}
	for _, c := range []optional.Collector{&audit_log_tail.Collector{}, &nextcloud.Collector{}, &fail2ban.Collector{}} {
		if _, err := c.Collect(cfg); err == nil {
			t.Fatalf("%s accepted implicit working-directory output", c.Name())
		}
	}
	for _, name := range []string{"logs", "json"} {
		if _, err := os.Stat(filepath.Join(base, name)); !os.IsNotExist(err) {
			t.Fatalf("unconfigured output %s created", name)
		}
	}
}
