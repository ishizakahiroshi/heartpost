package agent

import (
	"bytes"
	"context"
	"fmt"
	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/report"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Target struct {
	Name, Endpoint, Path, APIKey string
	Timeout                      time.Duration
	RetryCount                   int
	TrimEndpoint, StopOnCancel   bool
}
type TargetResult struct {
	Name string
	Err  error
}
type HTTPStatusError struct{ StatusCode int }

func (e *HTTPStatusError) Error() string { return fmt.Sprintf("server returned %d", e.StatusCode) }

// SendOne signs each attempt independently and sends the exact caller-supplied body.
// A nil logger discards messages. Negative retry counts and timeouts are invalid.
func SendOne(ctx context.Context, target Target, body []byte, agentID, token string, logger *log.Logger) error {
	if target.RetryCount < 0 || target.Timeout < 0 {
		return fmt.Errorf("agent: invalid target retry count or timeout")
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	client := &http.Client{Timeout: target.Timeout}
	endpoint := target.Endpoint
	if target.TrimEndpoint {
		endpoint = strings.TrimSuffix(endpoint, "/")
	}
	endpoint += target.Path
	var last error
	for attempt := 0; attempt <= target.RetryCount; attempt++ {
		if target.StopOnCancel && ctx.Err() != nil {
			if last != nil {
				return last
			}
			return ctx.Err()
		}
		if attempt > 0 {
			logger.Printf("INFO: report retry target=%s attempt=%d", target.Name, attempt)
		}
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(report.HeaderAgentID, agentID)
		req.Header.Set(report.HeaderTimestamp, ts)
		req.Header.Set(report.HeaderSignature, agentsig.Compute(target.APIKey, ts, body))
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			last = fmt.Errorf("http post: %w", err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			last = &HTTPStatusError{StatusCode: resp.StatusCode}
			continue
		}
		logger.Printf("INFO: report posted target=%s status=%d", target.Name, resp.StatusCode)
		return nil
	}
	return last
}

// SendReports preserves target order in its result while sending concurrently.
func SendReports(ctx context.Context, targets []Target, body []byte, agentID, token string, logger *log.Logger) []TargetResult {
	results := make([]TargetResult, len(targets))
	var wg sync.WaitGroup
	for i, target := range targets {
		wg.Add(1)
		go func(index int, t Target) {
			defer wg.Done()
			results[index] = TargetResult{Name: t.Name, Err: SendOne(ctx, t, body, agentID, token, logger)}
		}(i, target)
	}
	wg.Wait()
	return results
}
