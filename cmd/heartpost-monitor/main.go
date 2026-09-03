// Command heartpost-monitor は agent からのレポートを受け取り、保存し、
// 来なくなったら通知する受信側の本体。
//
// 外部 DB を要求せず、単一バイナリと 1 つのデータディレクトリだけで動く。
//
// この monitor 自身が落ちていると欠報に気づけない。自己参照で詰む構図があるので、
// monitor の生存は別の手段（外形監視サービス等）で外から見ること。
// /healthz を認証なしで開けてあるのはそのため。
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ishizakahiroshi/heartpost/core/notify"
	"github.com/ishizakahiroshi/heartpost/core/receiver"
	"github.com/ishizakahiroshi/heartpost/report"
)

func main() {
	configPath := flag.String("config", "", "monitor の設定ファイル（TOML）へのパス")
	flag.Parse()

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: heartpost-monitor -config <monitor.toml>")
		os.Exit(2)
	}

	if err := run(*configPath); err != nil {
		log.Printf("heartpost-monitor: %v", err)
		os.Exit(1)
	}
}

func run(configPath string) error {
	cfg, err := Load(configPath)
	if err != nil {
		return err
	}

	store, err := receiver.NewStore(cfg.DataDir, cfg.RetentionDays)
	if err != nil {
		return err
	}
	// 設定に載っている agent は、まだ 1 通も受け取っていなくても一覧へ出す。
	// 「設定したのに一度も届いていない」が画面から消えないようにする。
	for id := range cfg.AgentKeys {
		if err := store.EnsureAgent(id, cfg.AgentLabels[id]); err != nil {
			return err
		}
	}

	handler, err := receiver.NewHandler(store, receiver.Config{
		AgentKeys:         cfg.AgentKeys,
		AllowedIPs:        cfg.AllowedIPs,
		TrustForwardedFor: cfg.TrustForwardedFor,
		TimestampSkew:     cfg.TimestampSkew,
		MaxBodyBytes:      cfg.MaxBodyBytes,
	})
	if err != nil {
		return err
	}

	dashboard, err := receiver.NewDashboard(store, cfg.Thresholds, cfg.Auth, cfg.Location)
	if err != nil {
		return err
	}
	if cfg.Auth.User == "" {
		log.Printf("heartpost-monitor: WARNING 一覧画面に認証がかかっていません（auth.user 未設定）")
	}

	var notifier notify.Notifier = notify.Discard{}
	if cfg.NotifyWebhookURL != "" {
		wh := notify.NewWebhook(cfg.NotifyWebhookURL, cfg.NotifyTimeout)
		wh.Header = cfg.NotifyHeaders
		notifier = wh
	} else {
		log.Printf("heartpost-monitor: WARNING notify.disabled = true のため欠報を誰にも知らせません")
	}
	checker := receiver.NewChecker(store, cfg.Thresholds, notifier)

	mux := http.NewServeMux()
	mux.Handle(report.DefaultPath, handler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	})
	mux.Handle("/", dashboard)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go checker.Run(ctx, cfg.CheckInterval)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("heartpost-monitor: listening on %s (data_dir=%s, agents=%d)", cfg.Listen, store.Dir(), len(cfg.AgentKeys))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		log.Printf("heartpost-monitor: shutting down")
		return srv.Shutdown(shutdownCtx)
	}
}
