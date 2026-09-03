// Package notify は死活状態が変わったことを外へ知らせる出口を定める。
//
// この道具の主機能は「レポートが来なくなったら知らせる」ことなので、通知の出口は
// 必ず 1 つ以上ある前提で組む。ただし通知先ごとの分岐条件を組み立てる仕組みは持たない
// （webhook を 1 本出すところまで）。振り分けは受け取った側でやる。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Kind は状態遷移の向きを表す。欠報と復帰の 2 つしかない。
type Kind string

const (
	// KindDown は「生存 → 欠報」の遷移。
	KindDown Kind = "down"
	// KindRecovered は「欠報 → 復帰」の遷移。
	KindRecovered Kind = "recovered"
)

// Event は 1 回の状態遷移。JSON のキー名はそのまま webhook の body になるので、
// 受け取り側のスクリプトを壊さないよう気軽に変えない。
type Event struct {
	Kind Kind `json:"kind"`

	AgentID    string `json:"agent_id"`
	AgentLabel string `json:"agent_label"`

	// LastSeen は最後にレポートを受け取った時刻。まだ 1 通も受け取っていない場合はゼロ値。
	LastSeen time.Time `json:"last_seen"`
	// SilenceSeconds は判定時点での無通信秒数。
	SilenceSeconds int64 `json:"silence_seconds"`
	// ThresholdSeconds は欠報と判定するしきい値（秒）。
	ThresholdSeconds int64 `json:"threshold_seconds"`

	OccurredAt time.Time `json:"occurred_at"`

	// Text は人が読む 1 行。チャットへそのまま流せるようにしてある。
	Text string `json:"text"`
}

// Notifier は状態遷移を 1 件送る。
type Notifier interface {
	Notify(ctx context.Context, ev Event) error
}

// Webhook は Event を JSON で 1 本 POST する。
type Webhook struct {
	URL    string
	Client *http.Client
	// Header は追加で付けるヘッダ（認証トークン等）。
	Header map[string]string
}

// NewWebhook は timeout 付きの Webhook を返す。timeout が 0 以下なら 10 秒。
func NewWebhook(url string, timeout time.Duration) *Webhook {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Webhook{
		URL:    url,
		Client: &http.Client{Timeout: timeout},
	}
}

// Notify は Event を webhook へ POST する。2xx 以外はエラーにする。
//
// エラーを返した通知は「未通知」のまま残り、次の判定でもう一度試される。
// 送れなかったものを送れたことにしない。
func (w *Webhook) Notify(ctx context.Context, ev Event) error {
	if w == nil || strings.TrimSpace(w.URL) == "" {
		return errors.New("notify: webhook url is empty")
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("notify: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("notify: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.Header {
		req.Header.Set(k, v)
	}

	client := w.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("notify: post: %w", err)
	}
	defer resp.Body.Close()
	// body は読み捨てるが、接続を再利用させるため最後まで読む。
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("notify: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// Multi は複数の出口へ同じ Event を送る。1 つでも失敗したらエラーを返す
// （= その遷移は未通知のまま残り、次の判定で再送される）。
type Multi []Notifier

// Notify は登録された全 Notifier へ送る。
func (m Multi) Notify(ctx context.Context, ev Event) error {
	var errs []error
	for _, n := range m {
		if n == nil {
			continue
		}
		if err := n.Notify(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Discard は何もしない Notifier。通知先が 1 つも設定されていない場合に使う。
type Discard struct{}

// Notify は何もしない。
func (Discard) Notify(context.Context, Event) error { return nil }

// FormatText は人が読む 1 行を組み立てる。
func FormatText(kind Kind, label string, silence, threshold time.Duration) string {
	switch kind {
	case KindRecovered:
		return fmt.Sprintf("[復帰] %s からレポートが再開しました", label)
	default:
		return fmt.Sprintf("[欠報] %s から %s レポートが届いていません（しきい値 %s）",
			label, roundDur(silence), roundDur(threshold))
	}
}

func roundDur(d time.Duration) time.Duration {
	if d < 0 {
		return 0
	}
	return d.Round(time.Second)
}
