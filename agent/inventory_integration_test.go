package agent

import (
	"context"
	"errors"
	"io"
	"log"
	"testing"

	"github.com/ishizakahiroshi/heartpost/collector"
)

func TestInventoryRequiresExplicitVPSOptIn(t *testing.T) {
	for _, typ := range []string{"vps", "rental"} {
		for _, jobs := range []map[string]bool{nil, {"inventory": false}, {"inventory": true}} {
			cfg := &AgentConfig{}
			cfg.Agent.Type, cfg.Collectors.Jobs = typ, jobs
			found := false
			for _, c := range DefaultCollectors(cfg) {
				if c.Name() == "inventory" {
					found = true
				}
			}
			if found != (typ == "vps" && jobs["inventory"]) {
				t.Fatalf("type=%s jobs=%v inventory=%v", typ, jobs, found)
			}
		}
	}
}

func TestDisabledInventoryDoesNotEnterCollection(t *testing.T) {
	cfg := &AgentConfig{}
	cfg.Agent.Type = "vps"
	cfg.Collectors.Jobs = map[string]bool{"inventory": false}
	for _, c := range DefaultCollectors(cfg) {
		cfg.Collectors.Jobs[c.Name()] = false
	}
	// Inventory is absent from registration and all other collection is disabled:
	// the run cannot reach Collect or a command runner, even on a Linux host.
	if got := CollectConfig(context.Background(), cfg, collector.Config{}, log.New(io.Discard, "", 0)); len(got) != 0 {
		t.Fatalf("disabled collection produced observations: %v", got)
	}
}

type syntheticContextCollector struct{ calls int }

func (*syntheticContextCollector) Name() string { return "synthetic" }
func (*syntheticContextCollector) Collect(collector.Config) (interface{}, error) {
	return nil, errors.New("legacy path unexpectedly used")
}
func (c *syntheticContextCollector) CollectContext(ctx context.Context, _ collector.Config) (interface{}, error) {
	c.calls++
	return nil, ctx.Err()
}

func TestInventoryIntegrationForwardsRunContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &syntheticContextCollector{}
	if _, err := collectWithContext(ctx, c, collector.Config{}); !errors.Is(err, context.Canceled) || c.calls != 1 {
		t.Fatalf("run context not forwarded: calls=%d err=%v", c.calls, err)
	}
}
