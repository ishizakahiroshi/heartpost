package main

import "testing"

// TestRegisteredCollectorsByType は agent.type で collector 一式が切り替わることを固定する。
// 共有ホスティングへ VPS 用の収集（systemctl / journalctl 等）が混ざると、
// 権限が無いので毎回失敗して _error だけが積み上がる。
func TestRegisteredCollectorsByType(t *testing.T) {
	rentalWant := []string{
		"host", "loadavg", "memory", "disk", "cron",
		"process", "cpu", "network", "apache_log",
	}
	vpsWant := []string{
		"system", "process", "cron", "services",
		"ssl", "ssh", "nginx", "updates",
	}

	cases := []struct {
		agentType string
		want      []string
	}{
		{"rental", rentalWant},
		{"", rentalWant}, // 既定は rental
		{"vps", vpsWant},
	}

	for _, tc := range cases {
		cfg := &AgentConfig{}
		cfg.Agent.Type = tc.agentType

		got := make([]string, 0, len(tc.want))
		for _, c := range registeredCollectors(cfg) {
			got = append(got, c.Name())
		}

		if len(got) != len(tc.want) {
			t.Fatalf("type=%q: %d collectors %v, want %d %v", tc.agentType, len(got), got, len(tc.want), tc.want)
		}
		for i := range tc.want {
			if got[i] != tc.want[i] {
				t.Fatalf("type=%q: collector[%d] = %q, want %q", tc.agentType, i, got[i], tc.want[i])
			}
		}
	}
}

// TestAllCollectorsAreSwitchable は全 collector が [collectors.jobs] で切れることを固定する。
// 常時有効の collector を足すと、対象外のホストで毎回エラーが出続ける。
func TestAllCollectorsAreSwitchable(t *testing.T) {
	for _, agentType := range []string{"rental", "vps"} {
		cfg := &AgentConfig{}
		cfg.Agent.Type = agentType
		cfg.Collectors.Jobs = map[string]bool{}
		for _, c := range registeredCollectors(cfg) {
			cfg.Collectors.Jobs[c.Name()] = false
		}
		for _, c := range registeredCollectors(cfg) {
			if cfg.collectorEnabled(c.Name()) {
				t.Fatalf("type=%s: collector %q cannot be disabled", agentType, c.Name())
			}
		}
	}
}
