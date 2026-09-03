package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

const minimalAgentTOML = `
[agent]
id = "agent-example-01"
label = "example shared host"
type = "rental"

[monitor]
endpoint = "https://monitor.example.net"

[paths]
home_dir = "/home/<user>"
`

// TestLoadConfigMergesSecrets は api_key を別ファイルへ分けられることを固定する。
// 共有ホスティングでは agent.toml をバックアップや共有ディレクトリへ写す場面があるので、
// 鍵だけを別ファイルに切り出せることが前提になる。
func TestLoadConfigMergesSecrets(t *testing.T) {
	dir := t.TempDir()
	configPath := writeFile(t, dir, "agent.toml", minimalAgentTOML)
	writeFile(t, dir, secretsFileName, "[monitor]\napi_key = \"test-key-not-real\"\n")

	cfg, _, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Monitor.APIKey != "test-key-not-real" {
		t.Fatalf("api_key not merged from %s: %q", secretsFileName, cfg.Monitor.APIKey)
	}
	if cfg.Agent.ID != "agent-example-01" {
		t.Fatalf("agent.id lost after merge: %q", cfg.Agent.ID)
	}
}

// TestLoadConfigDefaults は省略時の既定値を固定する。
func TestLoadConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	configPath := writeFile(t, dir, "agent.toml", "[agent]\nid = \"agent-example-01\"\n")

	cfg, _, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Monitor.Path != "/api/agent/report" {
		t.Fatalf("default monitor.path = %q", cfg.Monitor.Path)
	}
	if cfg.Runtime.TimeoutSec != 30 {
		t.Fatalf("default runtime.timeout_sec = %d", cfg.Runtime.TimeoutSec)
	}
	if cfg.Runtime.LogMaxBytes != 5*1024*1024 {
		t.Fatalf("default runtime.log_max_bytes = %d", cfg.Runtime.LogMaxBytes)
	}
	if cfg.Agent.Type != "rental" {
		t.Fatalf("default agent.type = %q", cfg.Agent.Type)
	}
}

// TestValidateRequiresAPIKeyWhenSending は「送るのに鍵が無い」設定を起動時に止めることを固定する。
// 送信時まで気づけないと、cron が 5 分おきに失敗ログだけを積む状態になる。
func TestValidateRequiresAPIKeyWhenSending(t *testing.T) {
	dir := t.TempDir()
	configPath := writeFile(t, dir, "agent.toml", minimalAgentTOML)

	if _, _, err := loadConfig(configPath); err == nil {
		t.Fatal("expected error when endpoint is set without api_key")
	}
}

// TestValidateAllowsDryRunWithoutAPIKey は endpoint 空（dry-run）なら鍵が無くても起動できることを固定する。
func TestValidateAllowsDryRunWithoutAPIKey(t *testing.T) {
	dir := t.TempDir()
	configPath := writeFile(t, dir, "agent.toml", "[agent]\nid = \"agent-example-01\"\n")

	if _, _, err := loadConfig(configPath); err != nil {
		t.Fatalf("dry-run config should load: %v", err)
	}
}

// TestCheckSecretsPerm は鍵ファイルの権限判定を OS に依存せず固定する。
//
// 実ファイルの mode を作らず fs.FileMode を直接渡すのは、Windows では 600 の
// ファイルを作れず、この判定自体をテストできなくなるため。
func TestCheckSecretsPerm(t *testing.T) {
	cases := []struct {
		name     string
		mode     fs.FileMode
		goos     string
		wantErr  bool
		wantWarn bool
	}{
		{name: "0600 on unix is accepted", mode: 0o600, goos: "freebsd"},
		{name: "0400 on unix is accepted", mode: 0o400, goos: "linux"},
		{name: "0644 on unix is rejected", mode: 0o644, goos: "freebsd", wantErr: true},
		{name: "0640 on unix is rejected", mode: 0o640, goos: "linux", wantErr: true},
		{name: "0666 on windows only warns", mode: 0o666, goos: "windows", wantWarn: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			warn, err := checkSecretsPerm("/tmp/agent_secrets.toml", tc.mode, tc.goos)
			if tc.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantWarn && warn == "" {
				t.Fatal("expected a warning")
			}
			if !tc.wantWarn && warn != "" {
				t.Fatalf("unexpected warning: %s", warn)
			}
			if tc.wantErr && !strings.Contains(err.Error(), "chmod 600") {
				t.Fatalf("error should tell the operator how to fix it: %v", err)
			}
		})
	}
}

// TestLoadConfigRejectsWorldReadableSecrets は実ファイル経由でも起動を拒否することを確認する。
// Windows では mode ビットが ACL を表さないので、この経路は unix 系でだけ検証する。
func TestLoadConfigRejectsWorldReadableSecrets(t *testing.T) {
	if os.PathSeparator == '\\' {
		t.Skip("file mode bits do not reflect ACLs on windows")
	}
	dir := t.TempDir()
	configPath := writeFile(t, dir, "agent.toml", minimalAgentTOML)
	secretsPath := writeFile(t, dir, secretsFileName, "[monitor]\napi_key = \"test-key-not-real\"\n")
	if err := os.Chmod(secretsPath, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	_, _, err := loadConfig(configPath)
	if err == nil {
		t.Fatal("expected loadConfig to reject a group/world readable secrets file")
	}
	if !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("error should tell the operator how to fix it: %v", err)
	}
}

// TestCollectorEnabled は [collectors.jobs] の解釈を固定する。
// 未記載は有効。collector が増えたときに既存の設定ファイルを書き直させないため。
func TestCollectorEnabled(t *testing.T) {
	cfg := &AgentConfig{}
	if !cfg.collectorEnabled("disk") {
		t.Fatal("no [collectors.jobs] section should enable everything")
	}

	cfg.Collectors.Jobs = map[string]bool{"disk": false}
	if cfg.collectorEnabled("disk") {
		t.Fatal("explicit false should disable")
	}
	if !cfg.collectorEnabled("memory") {
		t.Fatal("unlisted collector should stay enabled")
	}
}

// TestLockPathFallback はロックファイルの置き場所の優先順位を固定する。
func TestLockPathFallback(t *testing.T) {
	cfg := &AgentConfig{ConfigDir: filepath.FromSlash("/etc/heartpost")}
	if got, want := cfg.lockPath(), filepath.FromSlash("/etc/heartpost/heartpost-agent.lock"); got != want {
		t.Fatalf("config dir fallback: got %q want %q", got, want)
	}

	cfg.Paths.HomeDir = filepath.FromSlash("/home/<user>")
	if got, want := cfg.lockPath(), filepath.FromSlash("/home/<user>/heartpost/heartpost-agent.lock"); got != want {
		t.Fatalf("home dir fallback: got %q want %q", got, want)
	}

	cfg.Runtime.LogFile = filepath.FromSlash("/home/<user>/heartpost/agent.log")
	if got, want := cfg.lockPath(), filepath.FromSlash("/home/<user>/heartpost/heartpost-agent.lock"); got != want {
		t.Fatalf("log dir: got %q want %q", got, want)
	}
}
