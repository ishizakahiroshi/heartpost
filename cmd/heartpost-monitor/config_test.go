package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "monitor.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const minimalConfig = `
[server]
data_dir = "/tmp/heartpost-test"

[notify]
webhook_url = "https://hooks.example.net/heartpost"

[agent_keys]
web-01 = "sample-shared-secret"
`

func TestLoadDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Listen != defaultListen {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.RetentionDays != defaultRetentionDays {
		t.Errorf("RetentionDays = %d", cfg.RetentionDays)
	}
	// 既定のしきい値は agent_interval (5m) の 3 倍。
	if got := cfg.Thresholds.For("web-01"); got != 15*time.Minute {
		t.Errorf("default threshold = %v, want 15m", got)
	}
	if cfg.CheckInterval != defaultCheckInterval {
		t.Errorf("CheckInterval = %v", cfg.CheckInterval)
	}
}

func TestLoadPerAgentThresholdAndLabel(t *testing.T) {
	cfg, err := Load(writeConfig(t, minimalConfig+`
[liveness]
agent_interval = "10m"

[agents.web-01]
label = "web-01 (front)"
down_threshold = "26h"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Thresholds.Default != 30*time.Minute {
		t.Errorf("default threshold = %v, want 30m", cfg.Thresholds.Default)
	}
	if got := cfg.Thresholds.For("web-01"); got != 26*time.Hour {
		t.Errorf("per-agent threshold = %v, want 26h", got)
	}
	if cfg.AgentLabels["web-01"] != "web-01 (front)" {
		t.Errorf("label = %q", cfg.AgentLabels["web-01"])
	}
}

func TestLoadRejects(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "通知先が無いのに disabled を明示していない",
			body: "[agent_keys]\nweb-01 = \"k\"\n",
			want: "notify.webhook_url",
		},
		{
			name: "agent_keys が空",
			body: "[notify]\nwebhook_url = \"https://hooks.example.net/x\"\n",
			want: "agent_keys",
		},
		{
			name: "agent id がパスとして危険",
			body: "[notify]\nwebhook_url = \"https://hooks.example.net/x\"\n\n[agent_keys]\n\"../evil\" = \"k\"\n",
			want: "invalid agent id",
		},
		{
			name: "未知のキー",
			body: "[server]\nunknown_key = 1\n\n[notify]\nwebhook_url = \"https://hooks.example.net/x\"\n\n[agent_keys]\nweb-01 = \"k\"\n",
			want: "unknown key",
		},
		{
			name: "解釈できない duration",
			body: minimalConfig + "\n[liveness]\nagent_interval = \"5 minutes\"\n",
			want: "liveness.agent_interval",
		},
		{
			name: "user だけあって password が無い",
			body: minimalConfig + "\n[auth]\nuser = \"monitor\"\n",
			want: "auth.password",
		},
		{
			name: "agents に対応する鍵が無い",
			body: minimalConfig + "\n[agents.db-01]\nlabel = \"x\"\n",
			want: "agent_keys",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, c.body))
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error = %v, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestLoadAllowsExplicitlyDisabledNotify(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
[notify]
disabled = true

[agent_keys]
web-01 = "sample-shared-secret"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.NotifyDisabled || cfg.NotifyWebhookURL != "" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

// TestExampleConfigParses は同梱のサンプル設定がそのまま読めることを確かめる。
// サンプルが腐ると、利用者は最初の 1 歩で詰まる。
func TestExampleConfigParses(t *testing.T) {
	path := filepath.Join("..", "..", "config", "monitor.example.toml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("example config not found: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("example config does not load: %v", err)
	}
	if len(cfg.AgentKeys) != 3 {
		t.Errorf("example agent_keys = %d, want 3", len(cfg.AgentKeys))
	}
	if got := cfg.Thresholds.For("db-01"); got != 26*time.Hour {
		t.Errorf("example db-01 threshold = %v, want 26h", got)
	}
}
