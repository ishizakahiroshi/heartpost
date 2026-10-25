package main

import (
	"github.com/ishizakahiroshi/heartpost/agent"
	"io/fs"
)

const secretsFileName = "agent_secrets.toml"

type AgentConfig agent.AgentConfig

func loadConfig(path string) (*AgentConfig, []string, error) {
	cfg, warnings, err := agent.LoadConfig(path)
	return (*AgentConfig)(cfg), warnings, err
}
func checkSecretsPerm(path string, mode fs.FileMode, goos string) (string, error) {
	return agent.CheckSecretsPerm(path, mode, goos)
}
func (c *AgentConfig) validate() error { return (*agent.AgentConfig)(c).Validate() }
func (c *AgentConfig) collectorEnabled(name string) bool {
	return (*agent.AgentConfig)(c).CollectorEnabled(name)
}
func (c *AgentConfig) lockPath() string { return (*agent.AgentConfig)(c).LockPath() }
