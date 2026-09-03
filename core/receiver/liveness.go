package receiver

import (
	"context"
	"log"
	"time"

	"github.com/ishizakahiroshi/heartpost/core/notify"
)

// DefaultIntervalMultiplier は cron の実行間隔から既定のしきい値を出すときの倍率。
//
// 3 倍にしているのは、1 回の取りこぼし（cron の遅延・一時的なネットワーク断）で
// 鳴らないようにするため。1 倍にすると誤報だらけになり、誰も見なくなる。
const DefaultIntervalMultiplier = 3

// Thresholds は欠報と判定するまでの無通信時間。
type Thresholds struct {
	// Default は agent ごとの指定が無いときに使う。
	Default time.Duration
	// PerAgent は agent_id ごとの上書き。cron の間隔が違う agent が混ざるため必要。
	PerAgent map[string]time.Duration
}

// For は agent_id に適用するしきい値を返す。
func (t Thresholds) For(agentID string) time.Duration {
	if d, ok := t.PerAgent[agentID]; ok && d > 0 {
		return d
	}
	if t.Default > 0 {
		return t.Default
	}
	return DefaultIntervalMultiplier * 5 * time.Minute
}

// Checker は last_seen としきい値から欠報を判定し、状態が変わったときだけ通知する。
//
// 「繰り返し鳴らさない」ことがこの型の主目的なので、通知するかどうかは
// 現在の状態ではなく **前回どちらを通知したか**（AgentState.Notified）で決める。
// この値は state.json に永続化されるため、monitor を再起動しても再通知しない。
type Checker struct {
	store      *Store
	thresholds Thresholds
	notifier   notify.Notifier
	logf       func(format string, args ...any)
}

// NewChecker は死活判定器を作る。notifier が nil なら通知を捨てる。
func NewChecker(store *Store, thresholds Thresholds, notifier notify.Notifier) *Checker {
	if notifier == nil {
		notifier = notify.Discard{}
	}
	return &Checker{store: store, thresholds: thresholds, notifier: notifier}
}

// SetLogf はログ出力先を差し替える（テスト用）。
func (c *Checker) SetLogf(f func(format string, args ...any)) { c.logf = f }

func (c *Checker) printf(format string, args ...any) {
	if c.logf != nil {
		c.logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Check は全 agent の死活を判定し、遷移したものだけ通知する。
// 実際に送れた通知の一覧を返す。
//
// 通知に失敗した遷移は「未通知」のまま残す。次の Check でもう一度試される。
// 送れなかったものを送れたことにすると、その欠報は永久に誰にも届かない。
func (c *Checker) Check(ctx context.Context, now time.Time) []notify.Event {
	var sent []notify.Event

	for _, st := range c.store.States() {
		th := c.thresholds.For(st.AgentID)

		// last_seen がゼロ値（1 通も受け取っていない）の agent は判定しない。
		// monitor を建てたばかりの時刻を起点に、まだ設定していない agent が
		// 一斉に欠報になるのを避ける。
		if st.LastSeen.IsZero() {
			continue
		}

		silence := now.Sub(st.LastSeen)
		down := silence > th

		downSince := st.DownSince
		if down && downSince.IsZero() {
			downSince = now
		}
		if !down {
			downSince = time.Time{}
		}

		notified := st.Notified
		var ev *notify.Event

		switch {
		case down && notified != NotifyDown:
			ev = &notify.Event{
				Kind:             notify.KindDown,
				AgentID:          st.AgentID,
				AgentLabel:       st.Label(),
				LastSeen:         st.LastSeen,
				SilenceSeconds:   int64(silence / time.Second),
				ThresholdSeconds: int64(th / time.Second),
				OccurredAt:       now,
				Text:             notify.FormatText(notify.KindDown, st.Label(), silence, th),
			}
		case !down && notified == NotifyDown:
			ev = &notify.Event{
				Kind:             notify.KindRecovered,
				AgentID:          st.AgentID,
				AgentLabel:       st.Label(),
				LastSeen:         st.LastSeen,
				SilenceSeconds:   int64(silence / time.Second),
				ThresholdSeconds: int64(th / time.Second),
				OccurredAt:       now,
				Text:             notify.FormatText(notify.KindRecovered, st.Label(), silence, th),
			}
		}

		if ev != nil {
			if err := c.notifier.Notify(ctx, *ev); err != nil {
				c.printf("heartpost: notify failed agent=%s kind=%s: %v", st.AgentID, ev.Kind, err)
				// 通知済みフラグは進めない。状態（down 表示）だけ更新する。
				if err := c.store.SetLiveness(st.AgentID, down, downSince, notified); err != nil {
					c.printf("heartpost: state update failed agent=%s: %v", st.AgentID, err)
				}
				continue
			}
			if ev.Kind == notify.KindDown {
				notified = NotifyDown
			} else {
				notified = NotifyUp
			}
			sent = append(sent, *ev)
		}

		if down == st.Down && downSince.Equal(st.DownSince) && notified == st.Notified {
			continue
		}
		if err := c.store.SetLiveness(st.AgentID, down, downSince, notified); err != nil {
			c.printf("heartpost: state update failed agent=%s: %v", st.AgentID, err)
		}
	}

	return sent
}

// Run は interval ごとに Check を回す。ctx が終わるまで戻らない。
func (c *Checker) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.Check(ctx, now)
		}
	}
}
