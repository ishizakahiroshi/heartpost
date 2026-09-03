package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/report"
)

// reportHTTPError は 2xx 以外が返ったことを表す。ステータスを保持するのは、
// ログに何が起きたのかを残すため（呼び出し側での分岐には使っていない）。
type reportHTTPError struct {
	StatusCode int
}

func (e *reportHTTPError) Error() string {
	return fmt.Sprintf("server returned %d", e.StatusCode)
}

// sendReport は monitor へレポートを 1 回 POST し、失敗したら RetryCount 回まで再送する。
//
// 送信先は 1 つしか持たない。宛先を増やすと、片方だけ落ちているときの扱い
// （どちらの成功をもって成功とするか）を agent 側に持ち込むことになり、
// 「収集して送るだけ」から外れる。宛先を分けたいなら monitor 側で受けて転送する。
//
// 署名はリトライのたびに計算し直す。タイムスタンプは署名対象に入っていて、
// 受信側はそこを見てリプレイを弾く。最初の試行の時刻を使い回すと、
// リトライで時間が経った分だけ受信側の許容窓から外れて弾かれる。
func sendReport(ctx context.Context, cfg *AgentConfig, body []byte, logger *log.Logger) error {
	client := &http.Client{Timeout: time.Duration(cfg.Monitor.HTTPTimeoutSec) * time.Second}
	endpoint := strings.TrimSuffix(cfg.Monitor.Endpoint, "/") + cfg.Monitor.Path

	var lastErr error
	for attempt := 0; attempt <= cfg.Monitor.RetryCount; attempt++ {
		// 全体タイムアウトを超えたら再送をやめる。cron は次の周期でまた起動するので、
		// 期限切れの ctx で残りの回数を空打ちしても意味がない。
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return lastErr
			}
			return err
		}
		if attempt > 0 {
			logger.Printf("INFO: report retry attempt=%d", attempt)
		}

		tsStr := strconv.FormatInt(time.Now().Unix(), 10)
		sig := agentsig.Compute(cfg.Monitor.APIKey, tsStr, body)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(report.HeaderAgentID, cfg.Agent.ID)
		req.Header.Set(report.HeaderTimestamp, tsStr)
		req.Header.Set(report.HeaderSignature, sig)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("http post: %w", err)
			logger.Printf("WARN: report failed: %v", lastErr)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			lastErr = &reportHTTPError{StatusCode: resp.StatusCode}
			logger.Printf("WARN: report failed: %v", lastErr)
			continue
		}

		logger.Printf("INFO: report posted status=%d", resp.StatusCode)
		return nil
	}
	return lastErr
}
