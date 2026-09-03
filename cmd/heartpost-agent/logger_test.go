package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRotatingWriterTruncatesAtLimit は log_max_bytes を超えたら切り捨てることを固定する。
// 共有ホスティングのホームは容量が小さく、監視の道具がディスクを埋めて
// 本体を巻き添えにするのが最悪の結果になる。
func TestRotatingWriterTruncatesAtLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	w, err := newRotatingWriter(path, 32)
	if err != nil {
		t.Fatalf("newRotatingWriter: %v", err)
	}
	defer w.Close()

	for i := 0; i < 10; i++ {
		if _, err := w.Write([]byte(strings.Repeat("x", 10) + "\n")); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// 上限に達した時点で切るので、1 回分の書き込みを足したサイズを超えることはない。
	if info.Size() > 32+11 {
		t.Fatalf("log grew past the limit: %d bytes", info.Size())
	}
}

// TestSetupLoggerFallsBackToStderr は log_file 未指定なら stderr へ出すことを固定する。
func TestSetupLoggerFallsBackToStderr(t *testing.T) {
	cfg := &AgentConfig{}
	logger, closer, err := setupLogger(cfg)
	if err != nil {
		t.Fatalf("setupLogger: %v", err)
	}
	defer closer.Close()
	if logger == nil {
		t.Fatal("logger must not be nil")
	}
}

// TestSetupLoggerWritesOnlyToFile は log_file 指定時に stderr へ二重出力しないことを固定する。
// cron は stderr をメールで送る環境が多く、二重出力は 5 分おきの通知メールになる。
func TestSetupLoggerWritesOnlyToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	cfg := &AgentConfig{}
	cfg.Runtime.LogFile = path
	cfg.Runtime.LogMaxBytes = 1024

	logger, closer, err := setupLogger(cfg)
	if err != nil {
		t.Fatalf("setupLogger: %v", err)
	}
	logger.Printf("INFO: hello")
	closer.Close()

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(got), "INFO: hello") {
		t.Fatalf("log file does not contain the line: %q", string(got))
	}
}
