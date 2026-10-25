package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestConfiguredTickerPeriodAndSameGroupSerialExecution(t *testing.T) {
	ticks := make(chan time.Time, 2)
	started := make(chan struct{}, 4)
	var count atomic.Int32
	var durations []time.Duration
	var mu sync.Mutex
	opts := testOptions()
	opts.Mode = Intervals
	opts.Intervals = map[string]time.Duration{"example": 17 * time.Second}
	opts.CancelPolicy = DropCanceled
	opts.Tasks = []Task{{Name: "first", Group: "example", Collect: func(context.Context) (any, error) {
		if count.Add(1)%2 != 1 {
			t.Error("same-group order changed")
		}
		return nil, nil
	}}, {Name: "second", Group: "example", Collect: func(context.Context) (any, error) {
		if count.Add(1)%2 != 0 {
			t.Error("same-group order changed")
		}
		started <- struct{}{}
		return nil, nil
	}}}
	r, _ := New(opts)
	r.newTicker = func(duration time.Duration) (<-chan time.Time, func()) {
		mu.Lock()
		durations = append(durations, duration)
		mu.Unlock()
		return ticks, func() {}
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	<-started
	ticks <- time.Now()
	<-started
	if count.Load() != 4 {
		t.Fatal("tick did not schedule exactly one batch")
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(durations) != 1 || durations[0] != 17*time.Second {
		t.Fatalf("period changed: %v", durations)
	}
}
