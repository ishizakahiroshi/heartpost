package main

import (
	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/rental"
)

// registeredCollectors は実行順に collector を返す。
//
// 並び順は「外部コマンドを叩かない or 軽いものから」。全体タイムアウトに
// かかったときでも、素早く取れる値だけは入ったレポートが残るようにする。
// ここに載る名前が agent.toml の [collectors.jobs] のキーになる。
func registeredCollectors() []collector.Collector {
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
