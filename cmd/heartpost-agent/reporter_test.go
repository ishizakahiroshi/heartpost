package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/report"
)

const testAPIKey = "test-key-not-real"

func testConfig(endpoint string) *AgentConfig {
	cfg := &AgentConfig{}
	cfg.Agent.ID = "agent-example-01"
	cfg.Monitor.Endpoint = endpoint
	cfg.Monitor.Path = report.DefaultPath
	cfg.Monitor.APIKey = testAPIKey
	cfg.Monitor.HTTPTimeoutSec = 5
	return cfg
}

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

// TestSendReportSignsRequest は受信側が検証できる形で送っていることを固定する。
// ヘッダ名と署名の形はワイヤ仕様なので、ここが変わると稼働中の agent が一斉に弾かれる。
func TestSendReportSignsRequest(t *testing.T) {
	body := []byte(`{"agent_id":"agent-example-01"}`)

	var verified atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path != report.DefaultPath {
			t.Errorf("path = %q, want %q", r.URL.Path, report.DefaultPath)
		}
		if r.Header.Get(report.HeaderAgentID) != "agent-example-01" {
			t.Errorf("%s = %q", report.HeaderAgentID, r.Header.Get(report.HeaderAgentID))
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("agent must not send an Authorization header")
		}
		ts := r.Header.Get(report.HeaderTimestamp)
		if _, err := strconv.ParseInt(ts, 10, 64); err != nil {
			t.Errorf("%s is not a unix timestamp: %q", report.HeaderTimestamp, ts)
		}
		if !agentsig.Verify(testAPIKey, ts, got, r.Header.Get(report.HeaderSignature)) {
			t.Error("signature did not verify on the receiving side")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		verified.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := sendReport(context.Background(), testConfig(srv.URL), body, discardLogger()); err != nil {
		t.Fatalf("sendReport: %v", err)
	}
	if !verified.Load() {
		t.Fatal("server never verified the request")
	}
}

// TestSendReportRetriesExactlyRetryCount は再送回数を固定する。
// 共有ホスティングから無限に叩き続けないことがここの要点。
func TestSendReportRetriesExactlyRetryCount(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Monitor.RetryCount = 2

	err := sendReport(context.Background(), cfg, []byte(`{}`), discardLogger())
	if err == nil {
		t.Fatal("expected an error when the server keeps returning 500")
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("attempts = %d, want 3 (1 initial + retry_count 2)", got)
	}
}

// TestSendReportNoRetryWhenZero は retry_count = 0 で 1 回しか送らないことを固定する。
func TestSendReportNoRetryWhenZero(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Monitor.RetryCount = 0

	if err := sendReport(context.Background(), cfg, []byte(`{}`), discardLogger()); err == nil {
		t.Fatal("expected an error")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("attempts = %d, want 1", got)
	}
}

// TestSendReportSignsEachAttemptFreshly はリトライごとに署名し直していることを固定する。
// タイムスタンプは署名対象に入っていて受信側のリプレイ窓の判定に使われるので、
// 最初の試行の値を使い回すと、時間が経ったリトライだけが弾かれる。
func TestSendReportSignsEachAttemptFreshly(t *testing.T) {
	var mu sync.Mutex
	var stamps []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get(report.HeaderTimestamp)
		if !agentsig.Verify(testAPIKey, ts, body, r.Header.Get(report.HeaderSignature)) {
			t.Errorf("attempt with ts=%s did not verify", ts)
		}
		mu.Lock()
		stamps = append(stamps, ts)
		n := len(stamps)
		mu.Unlock()
		if n < 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Monitor.RetryCount = 3

	if err := sendReport(context.Background(), cfg, []byte(`{}`), discardLogger()); err != nil {
		t.Fatalf("sendReport: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(stamps) != 2 {
		t.Fatalf("attempts = %d, want 2", len(stamps))
	}
}

// TestSendReportStopsOnContextCancel は全体タイムアウトが送信にも効くことを確認する。
func TestSendReportStopsOnContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := testConfig(srv.URL)
	cfg.Monitor.RetryCount = 100

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		_ = sendReport(ctx, cfg, []byte(`{}`), discardLogger())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendReport ignored the cancelled context")
	}
}
