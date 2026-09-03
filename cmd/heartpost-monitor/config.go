package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/ishizakahiroshi/heartpost/core/receiver"
)

// fileConfig は monitor.toml をそのまま写した形。既定値の補完と検証は Load で行う。
type fileConfig struct {
	Server   serverSection            `toml:"server"`
	Auth     authSection              `toml:"auth"`
	Receiver receiverSection          `toml:"receiver"`
	Liveness livenessSection          `toml:"liveness"`
	Notify   notifySection            `toml:"notify"`
	Keys     map[string]string        `toml:"agent_keys"`
	Agents   map[string]agentOverride `toml:"agents"`
}

type serverSection struct {
	Listen   string `toml:"listen"`
	DataDir  string `toml:"data_dir"`
	Timezone string `toml:"timezone"`
}

type authSection struct {
	User     string `toml:"user"`
	Password string `toml:"password"`
}

type receiverSection struct {
	RetentionDays     int      `toml:"retention_days"`
	MaxBodyBytes      int64    `toml:"max_body_bytes"`
	TimestampSkew     string   `toml:"timestamp_skew"`
	AllowedIPs        []string `toml:"allowed_ips"`
	TrustForwardedFor bool     `toml:"trust_forwarded_for"`
}

type livenessSection struct {
	AgentInterval string `toml:"agent_interval"`
	DownThreshold string `toml:"down_threshold"`
	CheckInterval string `toml:"check_interval"`
}

type notifySection struct {
	WebhookURL string            `toml:"webhook_url"`
	Timeout    string            `toml:"timeout"`
	Headers    map[string]string `toml:"headers"`
	// Disabled は「通知先を置かないことを承知している」という明示。
	// 未設定のまま webhook_url も空だと起動しない（死活監視が黙って無言になるのを防ぐ）。
	Disabled bool `toml:"disabled"`
}

type agentOverride struct {
	Label         string `toml:"label"`
	DownThreshold string `toml:"down_threshold"`
}

// Config は検証済みの設定。
type Config struct {
	Listen   string
	DataDir  string
	Location *time.Location

	Auth receiver.BasicAuth

	RetentionDays     int
	MaxBodyBytes      int64
	TimestampSkew     time.Duration
	AllowedIPs        []string
	TrustForwardedFor bool

	Thresholds    receiver.Thresholds
	CheckInterval time.Duration

	NotifyWebhookURL string
	NotifyTimeout    time.Duration
	NotifyHeaders    map[string]string
	NotifyDisabled   bool

	AgentKeys   map[string]string
	AgentLabels map[string]string
}

const (
	defaultListen        = "127.0.0.1:8770"
	defaultDataDir       = "./data"
	defaultAgentInterval = 5 * time.Minute
	defaultCheckInterval = 30 * time.Second
	defaultRetentionDays = 90
	defaultNotifyTimeout = 10 * time.Second
)

// Load は TOML を読み、既定値を埋め、検証したうえで Config を返す。
//
// 「設定を間違えたまま静かに動く」状態を作らない。未知のキーや解釈できない値は
// 既定へ倒さずエラーにする。
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var fc fileConfig
	md, err := toml.Decode(string(b), &fc)
	if err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, 0, len(undecoded))
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		return nil, fmt.Errorf("config: unknown key(s) in %s: %s", path, strings.Join(keys, ", "))
	}

	cfg := &Config{
		Listen:            firstNonEmpty(fc.Server.Listen, defaultListen),
		DataDir:           firstNonEmpty(fc.Server.DataDir, defaultDataDir),
		AllowedIPs:        fc.Receiver.AllowedIPs,
		TrustForwardedFor: fc.Receiver.TrustForwardedFor,
		MaxBodyBytes:      fc.Receiver.MaxBodyBytes,
		RetentionDays:     fc.Receiver.RetentionDays,
		NotifyWebhookURL:  strings.TrimSpace(fc.Notify.WebhookURL),
		NotifyHeaders:     fc.Notify.Headers,
		NotifyDisabled:    fc.Notify.Disabled,
		AgentKeys:         map[string]string{},
		AgentLabels:       map[string]string{},
	}
	if fc.Receiver.RetentionDays == 0 {
		cfg.RetentionDays = defaultRetentionDays
	}

	cfg.Location = time.Local
	if tz := strings.TrimSpace(fc.Server.Timezone); tz != "" {
		loc, err := time.LoadLocation(tz)
		if err != nil {
			return nil, fmt.Errorf("config: server.timezone: %w", err)
		}
		cfg.Location = loc
	}

	if cfg.TimestampSkew, err = parseDuration("receiver.timestamp_skew", fc.Receiver.TimestampSkew, receiver.DefaultTimestampSkew); err != nil {
		return nil, err
	}
	if cfg.CheckInterval, err = parseDuration("liveness.check_interval", fc.Liveness.CheckInterval, defaultCheckInterval); err != nil {
		return nil, err
	}
	if cfg.NotifyTimeout, err = parseDuration("notify.timeout", fc.Notify.Timeout, defaultNotifyTimeout); err != nil {
		return nil, err
	}

	agentInterval, err := parseDuration("liveness.agent_interval", fc.Liveness.AgentInterval, defaultAgentInterval)
	if err != nil {
		return nil, err
	}
	// 既定のしきい値は cron の実行間隔の 3 倍。1 回の取りこぼしで鳴らさないため。
	defaultThreshold := time.Duration(receiver.DefaultIntervalMultiplier) * agentInterval
	if defaultThreshold, err = parseDuration("liveness.down_threshold", fc.Liveness.DownThreshold, defaultThreshold); err != nil {
		return nil, err
	}
	cfg.Thresholds = receiver.Thresholds{
		Default:  defaultThreshold,
		PerAgent: map[string]time.Duration{},
	}

	for id, key := range fc.Keys {
		if !receiver.ValidAgentID(id) {
			return nil, fmt.Errorf("config: agent_keys: invalid agent id %q (英数字とハイフンのみ・64 文字以内)", id)
		}
		if strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("config: agent_keys: empty key for %q", id)
		}
		cfg.AgentKeys[id] = key
	}
	if len(cfg.AgentKeys) == 0 {
		return nil, errors.New("config: agent_keys が空です。1 台も受信できません")
	}

	for id, ov := range fc.Agents {
		if !receiver.ValidAgentID(id) {
			return nil, fmt.Errorf("config: agents: invalid agent id %q", id)
		}
		if _, ok := cfg.AgentKeys[id]; !ok {
			return nil, fmt.Errorf("config: agents.%s に対応する agent_keys がありません", id)
		}
		if ov.Label != "" {
			cfg.AgentLabels[id] = ov.Label
		}
		if ov.DownThreshold != "" {
			d, err := parseDuration("agents."+id+".down_threshold", ov.DownThreshold, 0)
			if err != nil {
				return nil, err
			}
			cfg.Thresholds.PerAgent[id] = d
		}
	}

	if fc.Auth.User != "" {
		if fc.Auth.Password == "" {
			return nil, errors.New("config: auth.user を設定したら auth.password も設定してください")
		}
		cfg.Auth = receiver.BasicAuth{User: fc.Auth.User, Password: fc.Auth.Password}
	}

	// 通知先が無い死活監視は、静かに何もしない道具になる。事故なので明示を要求する。
	if cfg.NotifyWebhookURL == "" && !cfg.NotifyDisabled {
		return nil, errors.New("config: notify.webhook_url が未設定です。通知先を置かないなら notify.disabled = true を明示してください")
	}

	return cfg, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseDuration は "5m" 形式を time.Duration にする。空文字なら def を返す。
func parseDuration(key, raw string, def time.Duration) (time.Duration, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("config: %s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("config: %s は正の値にしてください: %q", key, v)
	}
	return d, nil
}
