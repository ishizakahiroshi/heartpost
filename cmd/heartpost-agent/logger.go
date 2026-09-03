package main

import (
	"fmt"
	"log"
	"os"
)

// rotatingWriter はログが max を超えたら切り捨てる書き込み先。
//
// 世代を残さず truncate するのは、共有ホスティングのホームは容量が小さく、
// 監視の道具がディスクを食って本体を巻き添えにするのが最悪だから。
// 過去ログを長く残したい用途はここでは持たない（監視の記録は monitor 側にある）。
type rotatingWriter struct {
	path    string
	maxSize int64
	file    *os.File
}

func newRotatingWriter(path string, maxSize int64) (*rotatingWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log file: %w", err)
	}
	return &rotatingWriter{path: path, maxSize: maxSize, file: f}, nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	info, err := w.file.Stat()
	if err == nil && info.Size() >= w.maxSize {
		w.file.Close()
		f, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return 0, fmt.Errorf("rotate log file: %w", err)
		}
		w.file = f
	}
	return w.file.Write(p)
}

func (w *rotatingWriter) Close() error {
	return w.file.Close()
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

type closer interface {
	Close() error
}

// setupLogger は log_file が指定されていればそこへ、無ければ stderr へ書くロガーを返す。
//
// ファイル指定時に stderr へも書かないのは、cron が stderr をメールで送る環境が多く、
// 5 分おきに正常ログのメールが届く事故になるため。異常は monitor 側の欠報検知で気づく。
func setupLogger(cfg *AgentConfig) (*log.Logger, closer, error) {
	if cfg.Runtime.LogFile == "" {
		return log.New(os.Stderr, "", log.LstdFlags), nopCloser{}, nil
	}

	rw, err := newRotatingWriter(cfg.Runtime.LogFile, cfg.Runtime.LogMaxBytes)
	if err != nil {
		return nil, nil, err
	}
	return log.New(rw, "", log.LstdFlags), rw, nil
}
