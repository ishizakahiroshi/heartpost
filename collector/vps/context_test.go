package vps

import (
	"context"
	"errors"
	"testing"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type contextCollector struct{}

func (contextCollector) Name() string { return "synthetic" }
func (contextCollector) Collect(Config) (interface{}, error) {
	return nil, errors.New("legacy path used")
}
func (contextCollector) CollectContext(ctx context.Context, cfg Config) (interface{}, error) {
	if cfg.AgentID != "synthetic" {
		return nil, errors.New("lost config")
	}
	return nil, ctx.Err()
}

func TestAdapterPropagatesCancellation(t *testing.T) {
	wrapped := Adapt(contextCollector{}, Config{AgentID: "synthetic"})
	aware, ok := wrapped.(interface {
		CollectContext(context.Context, collector.Config) (interface{}, error)
	})
	if !ok {
		t.Fatal("context-aware adapter missing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := aware.CollectContext(ctx, collector.Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
}
