package receiver

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/core/notify"
)

type fakeNotifier struct {
	mu     sync.Mutex
	events []notify.Event
	err    error
}

func (f *fakeNotifier) Notify(_ context.Context, ev notify.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeNotifier) kinds() []notify.Kind {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]notify.Kind, 0, len(f.events))
	for _, e := range f.events {
		out = append(out, e.Kind)
	}
	return out
}

func report1(t *testing.T, store *Store, agentID string, at time.Time) {
	t.Helper()
	if err := store.Append(Record{AgentID: agentID, AgentLabel: "sample host"}, at); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

// TestLivenessNotifiesOnceOnDownAndOnceOnRecovery は、欠報で 1 回だけ通知が飛び、
// 欠報が続く間は鳴らず、復帰でもう 1 回だけ飛ぶことを確かめる。
func TestLivenessNotifiesOnceOnDownAndOnceOnRecovery(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	th := Thresholds{Default: 15 * time.Minute}
	fake := &fakeNotifier{}
	checker := NewChecker(store, th, fake)
	checker.SetLogf(func(string, ...any) {})
	ctx := context.Background()

	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	report1(t, store, testAgentID, base)

	// しきい値内: 何も起きない。
	if got := checker.Check(ctx, base.Add(10*time.Minute)); len(got) != 0 {
		t.Fatalf("within threshold: sent %d events, want 0", len(got))
	}

	// しきい値超え: 欠報通知が 1 回。
	got := checker.Check(ctx, base.Add(20*time.Minute))
	if len(got) != 1 || got[0].Kind != notify.KindDown {
		t.Fatalf("first down check: %+v", got)
	}

	// 欠報が続く間は鳴らさない。
	for _, d := range []time.Duration{25, 40, 120} {
		if sent := checker.Check(ctx, base.Add(d*time.Minute)); len(sent) != 0 {
			t.Fatalf("still down at +%dm: sent %d events, want 0", d, len(sent))
		}
	}

	// 復帰: レポートが届いたら復帰通知が 1 回。
	resume := base.Add(130 * time.Minute)
	report1(t, store, testAgentID, resume)
	got = checker.Check(ctx, resume.Add(time.Minute))
	if len(got) != 1 || got[0].Kind != notify.KindRecovered {
		t.Fatalf("recovery check: %+v", got)
	}

	// 復帰後も鳴らさない。
	if sent := checker.Check(ctx, resume.Add(2*time.Minute)); len(sent) != 0 {
		t.Fatalf("after recovery: sent %d events, want 0", len(sent))
	}

	kinds := fake.kinds()
	if len(kinds) != 2 || kinds[0] != notify.KindDown || kinds[1] != notify.KindRecovered {
		t.Fatalf("notifier received %v, want [down recovered]", kinds)
	}
}

// TestLivenessDoesNotRenotifyAfterRestart は monitor を再起動しても
// 通知済みの欠報が再通知されないことを確かめる（state.json の永続化）。
func TestLivenessDoesNotRenotifyAfterRestart(t *testing.T) {
	dir := t.TempDir()
	th := Thresholds{Default: 15 * time.Minute}
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)

	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	report1(t, store, testAgentID, base)

	first := &fakeNotifier{}
	c1 := NewChecker(store, th, first)
	c1.SetLogf(func(string, ...any) {})
	if got := c1.Check(context.Background(), base.Add(20*time.Minute)); len(got) != 1 {
		t.Fatalf("first check sent %d events, want 1", len(got))
	}

	// 再起動相当: 同じディレクトリから状態を読み直す。
	restarted, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	states := restarted.States()
	if len(states) != 1 {
		t.Fatalf("reloaded states = %d, want 1", len(states))
	}
	if states[0].Notified != NotifyDown || !states[0].Down {
		t.Fatalf("reloaded state lost the notified flag: %+v", states[0])
	}

	second := &fakeNotifier{}
	c2 := NewChecker(restarted, th, second)
	c2.SetLogf(func(string, ...any) {})
	if got := c2.Check(context.Background(), base.Add(30*time.Minute)); len(got) != 0 {
		t.Fatalf("after restart sent %d events, want 0", len(got))
	}
	if len(second.kinds()) != 0 {
		t.Fatalf("after restart notifier got %v, want none", second.kinds())
	}
}

// TestLivenessRetriesAfterNotifyFailure は通知に失敗した遷移が
// 「通知済み」にされず、次の判定で再送されることを確かめる。
func TestLivenessRetriesAfterNotifyFailure(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	report1(t, store, testAgentID, base)

	fake := &fakeNotifier{err: errors.New("webhook unreachable")}
	checker := NewChecker(store, Thresholds{Default: 15 * time.Minute}, fake)
	checker.SetLogf(func(string, ...any) {})
	ctx := context.Background()

	if got := checker.Check(ctx, base.Add(20*time.Minute)); len(got) != 0 {
		t.Fatalf("failed notify should not count as sent: %+v", got)
	}
	if st := store.States()[0]; st.Notified == NotifyDown {
		t.Fatal("failed notify must not mark the transition as notified")
	}

	fake.err = nil
	got := checker.Check(ctx, base.Add(25*time.Minute))
	if len(got) != 1 || got[0].Kind != notify.KindDown {
		t.Fatalf("retry check: %+v", got)
	}
}

// TestLivenessIgnoresAgentsWithoutAnyReport は、まだ 1 通も受け取っていない agent を
// 起動直後に一斉に欠報扱いしないことを確かめる。
func TestLivenessIgnoresAgentsWithoutAnyReport(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureAgent("web-02", "not yet reporting"); err != nil {
		t.Fatal(err)
	}
	fake := &fakeNotifier{}
	checker := NewChecker(store, Thresholds{Default: time.Minute}, fake)
	checker.SetLogf(func(string, ...any) {})

	if got := checker.Check(context.Background(), time.Now()); len(got) != 0 {
		t.Fatalf("never-reported agent should not notify: %+v", got)
	}
}

func TestThresholdsPerAgentOverride(t *testing.T) {
	th := Thresholds{
		Default:  15 * time.Minute,
		PerAgent: map[string]time.Duration{"db-01": 26 * time.Hour},
	}
	if got := th.For("web-01"); got != 15*time.Minute {
		t.Errorf("For(web-01) = %v", got)
	}
	if got := th.For("db-01"); got != 26*time.Hour {
		t.Errorf("For(db-01) = %v", got)
	}

	empty := Thresholds{}
	if got := empty.For("web-01"); got != 15*time.Minute {
		t.Errorf("zero-value default = %v, want 15m", got)
	}
}

// TestLivenessPerAgentThreshold は agent ごとのしきい値上書きが効くことを確かめる。
func TestLivenessPerAgentThreshold(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	report1(t, store, "web-01", base)
	report1(t, store, "db-01", base)

	th := Thresholds{
		Default:  15 * time.Minute,
		PerAgent: map[string]time.Duration{"db-01": 26 * time.Hour},
	}
	fake := &fakeNotifier{}
	checker := NewChecker(store, th, fake)
	checker.SetLogf(func(string, ...any) {})

	got := checker.Check(context.Background(), base.Add(time.Hour))
	if len(got) != 1 || got[0].AgentID != "web-01" {
		t.Fatalf("only web-01 should be down: %+v", got)
	}
}
