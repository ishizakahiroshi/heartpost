// heartpost-agent は 1 台のサーバーの状態を 1 回だけ集めて monitor へ送る。
//
// 常駐しない。cron から起動され、集めて、送って、終わる。共有ホスティングでは
// 常駐プロセスを置けないことがあり、置ける環境でも「監視の常駐プロセスが死んで
// いたことに気づかない」が起きる。one-shot なら起動しなくなったこと自体が
// monitor 側の欠報として出る。
//
// root 権限は要らない。収集は読むだけで、サーバーへ書き込む操作は持たない。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/internal/filelock"
	"github.com/ishizakahiroshi/heartpost/report"
)

func main() {
	configPath := flag.String("config", "", "path to agent.toml (required)")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: heartpost-agent --config /path/to/agent.toml")
		os.Exit(2)
	}

	cfg, warnings, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	logger, closer, err := setupLogger(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger setup error: %v\n", err)
		os.Exit(1)
	}
	defer closer.Close()

	for _, w := range warnings {
		logger.Printf("WARN: %s", w)
	}

	if err := run(cfg, logger); err != nil {
		logger.Printf("ERROR: %v", err)
		os.Exit(1)
	}
}

func run(cfg *AgentConfig, logger *log.Logger) error {
	lockPath := cfg.lockPath()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return fmt.Errorf("create lock directory: %w", err)
	}
	unlock, err := filelock.Acquire(lockPath)
	if err != nil {
		if errors.Is(err, filelock.ErrLocked) {
			// 前回の実行がまだ終わっていない。cron は次の周期でまた起動するので、
			// 待たずに降りる。二重に集めて二重に送るほうが害が大きい。
			return fmt.Errorf("another agent is already running (lock: %s)", lockPath)
		}
		return fmt.Errorf("acquire lock %s: %w", lockPath, err)
	}
	defer unlock()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(cfg.Runtime.TimeoutSec)*time.Second,
	)
	defer cancel()

	// collector の中の待ち（CPU サンプリングの 1 秒待機など）を
	// 全体タイムアウトで打ち切れるようにする。
	collector.SetShutdownCh(ctx.Done())

	logger.Printf("INFO: agent=%s start", cfg.Agent.ID)

	collCfg := collector.Config{
		AgentID: cfg.Agent.ID,
		HomeDir: cfg.Paths.HomeDir,
		WWWDir:  cfg.Paths.WWWDir,
		LogDir:  cfg.Paths.LogDir,
	}

	results := runCollectors(ctx, cfg, collCfg, logger)

	payload := report.Build(cfg.Agent.ID, cfg.Agent.Label, cfg.Agent.Type, time.Now(), nil, results)
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	if cfg.Monitor.Endpoint == "" {
		logger.Printf("DEBUG: payload (dry-run):\n%s", string(body))
		logger.Printf("INFO: agent=%s done (dry-run)", cfg.Agent.ID)
		return nil
	}

	if err := sendReport(ctx, cfg, body, logger); err != nil {
		return fmt.Errorf("report failed: %w", err)
	}

	logger.Printf("INFO: agent=%s done", cfg.Agent.ID)
	return nil
}

// runCollectors は有効な collector を順に実行し、結果を JSON 断片のマップで返す。
//
// 1 つの collector の失敗で全体を落とさない。1 項目が取れないことと、
// サーバーが死んでいることは別で、レポートが届くこと自体が生存の合図だから。
// 失敗した項目は null ではなく _error を持つオブジェクトにする。null にすると
// 受信側で「この環境には無い項目」と「取ろうとして失敗した」が区別できない。
func runCollectors(ctx context.Context, cfg *AgentConfig, collCfg collector.Config, logger *log.Logger) map[string]json.RawMessage {
	collectors := registeredCollectors(cfg)
	results := make(map[string]json.RawMessage, len(collectors))

	for _, c := range collectors {
		if !cfg.collectorEnabled(c.Name()) {
			continue
		}
		if ctx.Err() != nil {
			logger.Printf("WARN: collector=%s skipped: %v", c.Name(), ctx.Err())
			results[c.Name()] = encodeCollectorError(ctx.Err())
			continue
		}

		val, err := c.Collect(collCfg)
		if err != nil {
			logger.Printf("WARN: collector=%s error: %v", c.Name(), err)
			results[c.Name()] = encodeCollectorError(err)
			continue
		}

		raw, err := json.Marshal(val)
		if err != nil {
			logger.Printf("WARN: collector=%s marshal error: %v", c.Name(), err)
			results[c.Name()] = encodeCollectorError(err)
			continue
		}
		results[c.Name()] = raw
		logger.Printf("INFO: collector=%s ok", c.Name())
	}

	return results
}

// encodeCollectorError は収集失敗を表す JSON 断片を作る。
// ここでの marshal は map[string]string なので失敗しないが、
// 万一失敗しても収集全体を落とさずに固定の形へ落とす。
func encodeCollectorError(err error) json.RawMessage {
	raw, mErr := json.Marshal(report.CollectorError(err))
	if mErr != nil {
		return json.RawMessage(`{"` + report.ErrorKey + `":"collector failed"}`)
	}
	return raw
}
