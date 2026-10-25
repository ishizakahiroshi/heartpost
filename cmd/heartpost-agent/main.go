// heartpost-agent collects and reports once; cron or a timer owns its schedule.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/ishizakahiroshi/heartpost/agent"
	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/report"
	"log"
	"os"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "path to agent.toml (required)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: heartpost-agent --config /path/to/agent.toml")
		os.Exit(2)
	}

	cfg, warnings, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger, closer, err := setupLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger setup error: %v\n", err)
		os.Exit(1)
	}
	defer closer.Close()

	for _, w := range warnings {
		logger.Printf("WARN: %s", w)
	}

	if err := run(cfg, logger); err != nil {
		logger.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run(cfg *AgentConfig, logger *log.Logger) error {
	return agent.RunConfig(context.Background(), (*agent.AgentConfig)(cfg), logger)
}
func runCollectors(ctx context.Context, cfg *AgentConfig, collCfg collector.Config, logger *log.Logger) map[string]json.RawMessage {
	return agent.CollectConfig(ctx, (*agent.AgentConfig)(cfg), collCfg, logger)
}
func encodeCollectorError(err error) json.RawMessage {
	raw, _ := json.Marshal(report.CollectorError(err))
	return raw
}
