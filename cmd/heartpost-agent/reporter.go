package main

import (
	"context"
	"github.com/ishizakahiroshi/heartpost/agent"
	"log"
)

type reportHTTPError = agent.HTTPStatusError

func sendReport(ctx context.Context, cfg *AgentConfig, body []byte, logger *log.Logger) error {
	return agent.SendOne(ctx, agent.TargetFromConfig((*agent.AgentConfig)(cfg)), body, cfg.Agent.ID, "", logger)
}
