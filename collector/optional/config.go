// Package optional defines explicit configuration for optional collectors.
package optional

import "github.com/ishizakahiroshi/heartpost/collector"

// Config contains only inputs consumed by the optional collectors.
// Applications provide deployment paths explicitly; no application home is assumed.
type Config struct {
	Paths      PathConfig
	Rules      RulesConfig
	Database   DatabaseConfig
	Cloudflare CloudflareConfig
	Honeypot   HoneypotConfig
}

type PathConfig struct {
	DataDir, Fail2banLog, AuditLog, NextcloudLog, NcAuditLog, NcExtractDir string
}

type RulesConfig struct {
	Fail2banLogLines, HoneypotDays int
}

type DatabaseConfig struct {
	DSN, BackupDir, NCBackupDir string
}

type CloudflareConfig struct {
	AccountID, AccessKeyID, SecretAccessKey, Bucket, Profile string
}

type HoneypotConfig struct{ JSONLPath string }

// Collector reports its legacy collection group alongside the shared name.
type Collector interface {
	Name() string
	Interval() string
	Collect(Config) (interface{}, error)
}

// Adapt binds optional configuration to the shared collector interface.
func Adapt(c Collector, cfg Config) collector.Collector { return adapter{inner: c, cfg: cfg} }

type adapter struct {
	inner Collector
	cfg   Config
}

func (a adapter) Name() string                                  { return a.inner.Name() }
func (a adapter) Collect(collector.Config) (interface{}, error) { return a.inner.Collect(a.cfg) }
