package fail2ban

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
)

func TestCollectorUsesSharedJSONLAndMockedCommand(t *testing.T) {
	oldRun, oldLocation := runWithTimeout, collector.Location()
	t.Cleanup(func() { runWithTimeout = oldRun; collector.SetLocation(oldLocation) })
	collector.SetLocation(time.FixedZone("Example", 2*3600))
	calls := 0
	runWithTimeout = func(timeout time.Duration, name string, args ...string) ([]byte, error) {
		calls++
		if timeout != 5*time.Second || name != "/usr/bin/fail2ban-client" {
			t.Fatal("command timeout changed")
		}
		if len(args) == 1 {
			return []byte("Jail list: example\n"), nil
		}
		if len(args) != 2 || args[1] != "example" {
			return nil, fmt.Errorf("unexpected mock command")
		}
		return []byte("Currently banned: 1\nTotal banned: 2\nTotal found: 3\nBanned IP list: 192.0.2.9\n"), nil
	}
	base := t.TempDir()
	path := filepath.Join(base, "input.log")
	if err := os.WriteFile(path, []byte("2026-01-02 03:04:05,001 fail2ban.actions [123]: NOTICE [example] Ban 192.0.2.9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := optional.Config{Paths: optional.PathConfig{DataDir: base, Fail2banLog: path}, Rules: optional.RulesConfig{Fail2banLogLines: 20}}
	for i := 0; i < 2; i++ {
		got, err := (&Collector{}).Collect(cfg)
		if err != nil {
			t.Fatal(err)
		}
		result := got.(*CollectResult)
		if result.NewEvents != 1-i || result.Active != 1 || len(result.Jails) != 1 {
			t.Fatalf("result=%+v", result)
		}
		if i == 0 && result.Events[0].TS != "2026-01-02T03:04:05+02:00" {
			t.Fatal("location lost")
		}
	}
	if calls != 4 {
		t.Fatalf("mock calls=%d", calls)
	}
}
