package main

import (
	"github.com/ishizakahiroshi/heartpost/agent"
	"github.com/ishizakahiroshi/heartpost/collector"
)

func registeredCollectors(cfg *AgentConfig) []collector.Collector {
	return agent.DefaultCollectors((*agent.AgentConfig)(cfg))
}
