package main

import (
	"github.com/ishizakahiroshi/heartpost/agent"
	"io"
	"log"
)

func newRotatingWriter(path string, maxSize int64) (io.WriteCloser, error) {
	return agent.NewRotatingWriter(path, maxSize)
}
func setupLogger(cfg *AgentConfig) (*log.Logger, io.Closer, error) {
	return agent.OpenLogger(cfg.Runtime.LogFile, cfg.Runtime.LogMaxBytes)
}
