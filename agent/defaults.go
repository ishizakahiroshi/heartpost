package agent

import (
	"context"
	"encoding/json"
	"github.com/ishizakahiroshi/heartpost/collector"
	"log"
	"time"
)

func TargetFromConfig(cfg *AgentConfig) Target {
	return Target{Name: "monitor", Endpoint: cfg.Monitor.Endpoint, Path: cfg.Monitor.Path, APIKey: cfg.Monitor.APIKey, Timeout: time.Duration(cfg.Monitor.HTTPTimeoutSec) * time.Second, RetryCount: cfg.Monitor.RetryCount, TrimEndpoint: true, StopOnCancel: true}
}
func configTasks(cfg *AgentConfig, collCfg collector.Config) []Task {
	var tasks []Task
	for _, c := range DefaultCollectors(cfg) {
		current := c
		tasks = append(tasks, Task{Name: current.Name(), Collect: func(context.Context) (any, error) { return current.Collect(collCfg) }})
	}
	return tasks
}
func OptionsFromConfig(cfg *AgentConfig, logger *log.Logger) Options {
	collCfg := collector.Config{AgentID: cfg.Agent.ID, HomeDir: cfg.Paths.HomeDir, WWWDir: cfg.Paths.WWWDir, LogDir: cfg.Paths.LogDir}
	return Options{Identity: Identity{ID: cfg.Agent.ID, Label: cfg.Agent.Label, Type: cfg.Agent.Type}, Tasks: configTasks(cfg, collCfg), Jobs: cfg.Collectors.Jobs, Timeout: time.Duration(cfg.Runtime.TimeoutSec) * time.Second, Targets: []Target{TargetFromConfig(cfg)}, LockPath: cfg.LockPath(), CreateLockDirectory: true, Logger: logger, DryRun: cfg.Monitor.Endpoint == ""}
}
func RunConfig(ctx context.Context, cfg *AgentConfig, logger *log.Logger) error {
	runner, err := New(OptionsFromConfig(cfg, logger))
	if err != nil {
		return err
	}
	return runner.Run(ctx)
}

// CollectConfig is the non-lifecycle collection primitive used by the command's
// compatibility tests. It does not mutate package-wide collector configuration.
func CollectConfig(ctx context.Context, cfg *AgentConfig, collCfg collector.Config, logger *log.Logger) map[string]json.RawMessage {
	r := &Runner{opts: Options{Tasks: configTasks(cfg, collCfg), Jobs: cfg.Collectors.Jobs, Logger: logger}}
	values, _ := r.collect(ctx, r.opts.Tasks)
	out := make(map[string]json.RawMessage, len(values))
	for name, value := range values {
		raw, _ := json.Marshal(value)
		out[name] = raw
	}
	return out
}
