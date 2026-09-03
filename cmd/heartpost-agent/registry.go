package main

import (
	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/rental"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
	"github.com/ishizakahiroshi/heartpost/collector/vps/cron"
	"github.com/ishizakahiroshi/heartpost/collector/vps/nginx"
	"github.com/ishizakahiroshi/heartpost/collector/vps/process"
	"github.com/ishizakahiroshi/heartpost/collector/vps/services"
	"github.com/ishizakahiroshi/heartpost/collector/vps/ssh"
	"github.com/ishizakahiroshi/heartpost/collector/vps/ssl"
	"github.com/ishizakahiroshi/heartpost/collector/vps/system"
	"github.com/ishizakahiroshi/heartpost/collector/vps/updates"
)

// registeredCollectors は agent.type に応じた collector を実行順に返す。
//
// 並び順は「外部コマンドを叩かない or 軽いものから」。全体タイムアウトに
// かかったときでも、素早く取れる値だけは入ったレポートが残るようにする。
// ここに載る名前が agent.toml の [collectors.jobs] のキーになる。
//
// **常時有効の collector は置かない。** どれも [collectors.jobs] で切れる。
// nginx が入っていないホストで nginx collector が毎回走る意味は無いし、
// 切れないと「対象外なのにエラーが出続ける」ログを人が読み飛ばすようになる。
func registeredCollectors(cfg *AgentConfig) []collector.Collector {
	if cfg.Agent.Type == "vps" {
		return vpsCollectors(cfg)
	}
	return rentalCollectors()
}

func rentalCollectors() []collector.Collector {
	return []collector.Collector{
		&rental.HostCollector{},
		&rental.LoadavgCollector{},
		&rental.MemoryCollector{},
		&rental.DiskCollector{},
		&rental.CronCollector{},
		&rental.ProcessCollector{},
		&rental.CPUCollector{},
		&rental.NetworkCollector{},
		&rental.ApacheLogCollector{},
	}
}

func vpsCollectors(cfg *AgentConfig) []collector.Collector {
	vc := vps.Config{
		AgentID:      cfg.Agent.ID,
		ServiceNames: cfg.VPS.ServiceNames,
		Paths: vps.PathConfig{
			AuthLog:  cfg.VPS.AuthLog,
			NginxLog: cfg.VPS.NginxLog,
			DataDir:  cfg.VPS.DataDir,
		},
		Rules: vps.RulesConfig{
			AuthLogLines:  cfg.VPS.AuthLogLines,
			NginxLogLines: cfg.VPS.NginxLogLines,
		},
		Domain:     cfg.VPS.Domain,
		RenewTimer: cfg.VPS.RenewTimer,
	}

	inner := []vps.Collector{
		&system.Collector{},
		&process.Collector{},
		&cron.Collector{},
		&services.Collector{},
		&ssl.Collector{},
		&ssh.Collector{},
		&nginx.Collector{},
		&updates.Collector{},
	}

	out := make([]collector.Collector, 0, len(inner))
	for _, c := range inner {
		out = append(out, vps.Adapt(c, vc))
	}
	return out
}
