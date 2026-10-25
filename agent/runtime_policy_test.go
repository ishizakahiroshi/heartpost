package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/filelock"
)

func TestIntervalsAndOnceHonorFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   RunMode
		policy FailurePolicy
	}{{"once_return", Once, ReturnFailure}, {"intervals_return", Intervals, ReturnFailure}, {"intervals_warn", Intervals, WarnFailure}} {
		t.Run(tc.name, func(t *testing.T) {
			sent := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(503)
				select {
				case sent <- struct{}{}:
				default:
				}
			}))
			defer server.Close()
			opts := testOptions()
			opts.DryRun = false
			opts.Mode = tc.mode
			opts.SendFailurePolicy = tc.policy
			opts.Tasks = []Task{{Name: "fixture", Group: "fixture", Collect: func(context.Context) (any, error) { return true, nil }}}
			opts.Targets = []Target{{Name: "fixture", Endpoint: server.URL, Timeout: time.Second}}
			r, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- r.Run(ctx) }()
			defer func() {
				cancel()
				closeCtx, stop := context.WithTimeout(context.Background(), time.Second)
				defer stop()
				if err := r.Close(closeCtx); err != nil {
					t.Error(err)
				}
			}()
			select {
			case <-sent:
			case <-time.After(time.Second):
				t.Fatal("no localhost report")
			}
			if tc.policy == ReturnFailure {
				select {
				case err := <-done:
					var status *HTTPStatusError
					if !errors.As(err, &status) || status.StatusCode != 503 {
						t.Fatalf("all-target failure=%v", err)
					}
				case <-time.After(250 * time.Millisecond):
					t.Fatal("ReturnFailure did not return after failed interval cycle")
				}
			} else {
				select {
				case err := <-done:
					t.Fatalf("WarnFailure stopped: %v", err)
				case <-time.After(40 * time.Millisecond):
				}
				cancel()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

type failurePolicyTransport func(*http.Request) (*http.Response, error)

func (f failurePolicyTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestIntervalFailureJoinsWorkersHeartbeatAndReleasesResources(t *testing.T) {
	workerStarted, workerCanceled, releaseWorker := make(chan struct{}), make(chan struct{}), make(chan struct{})
	heartbeatStarted, heartbeatCanceled, releaseHeartbeat := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseWorkerOnce, releaseHeartbeatOnce sync.Once
	releaseAll := func() {
		releaseWorkerOnce.Do(func() { close(releaseWorker) })
		releaseHeartbeatOnce.Do(func() { close(releaseHeartbeat) })
	}
	defer releaseAll()
	oldTransport := http.DefaultTransport
	http.DefaultTransport = failurePolicyTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/license/heartbeat" {
			close(heartbeatStarted)
			<-r.Context().Done()
			close(heartbeatCanceled)
			<-releaseHeartbeat
			return nil, r.Context().Err()
		}
		select {
		case <-workerStarted:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		select {
		case <-heartbeatStarted:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return &http.Response{StatusCode: 503, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})
	defer func() { http.DefaultTransport = oldTransport }()
	var stopped atomic.Int32
	opts := testOptions()
	opts.Mode = Intervals
	opts.DryRun = false
	opts.CancelPolicy = DropCanceled
	opts.SendFailurePolicy = ReturnFailure
	opts.LockPath = filepath.Join(t.TempDir(), "runner.lock")
	opts.Targets = []Target{{Name: "fixture", Endpoint: "http://127.0.0.1/report", Timeout: time.Second, StopOnCancel: true}}
	opts.License = &LicenseOptions{Verifier: &fakeVerifier{}, Key: "synthetic", PrimaryEndpoint: "http://127.0.0.1", HeartbeatInterval: time.Millisecond}
	opts.Services = []BackgroundService{func(context.Context) (func(context.Context) error, error) {
		return func(context.Context) error { stopped.Add(1); return nil }, nil
	}}
	opts.Tasks = []Task{
		{Name: "failing", Group: "one", Collect: func(context.Context) (any, error) { return true, nil }},
		{Name: "blocking", Group: "two", Collect: func(ctx context.Context) (any, error) {
			close(workerStarted)
			<-ctx.Done()
			close(workerCanceled)
			<-releaseWorker
			return true, nil
		}},
	}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	defer func() {
		releaseAll()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	for _, ch := range []<-chan struct{}{workerCanceled, heartbeatCanceled} {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("failure did not cancel worker/heartbeat")
		}
	}
	select {
	case err := <-done:
		t.Fatalf("returned before worker join: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseWorkerOnce.Do(func() { close(releaseWorker) })
	select {
	case err := <-done:
		t.Fatalf("returned before heartbeat join: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	releaseHeartbeatOnce.Do(func() { close(releaseHeartbeat) })
	select {
	case err := <-done:
		var status *HTTPStatusError
		if !errors.As(err, &status) || status.StatusCode != 503 {
			t.Fatalf("first cause replaced by cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failure did not return after joins")
	}
	if stopped.Load() != 1 {
		t.Fatalf("service stop count=%d", stopped.Load())
	}
	unlock, err := filelock.Acquire(opts.LockPath)
	if err != nil {
		t.Fatalf("lock not released: %v", err)
	}
	unlock()
	other, err := New(testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := other.Run(context.Background()); err != nil {
		t.Fatalf("active guard not released: %v", err)
	}
}

func TestSendReportsRejectsInvalidTargetsAndAcceptsNilLogger(t *testing.T) {
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	results := SendReports(context.Background(), []Target{{Name: "valid", Endpoint: server.URL}, {Name: "negative_timeout", Endpoint: server.URL, Timeout: -time.Second}, {Name: "negative_retry", Endpoint: server.URL, RetryCount: -1}}, []byte(`{}`), "fixture", "", nil)
	if len(results) != 3 || results[0].Name != "valid" || results[0].Err != nil || results[1].Name != "negative_timeout" || results[1].Err == nil || results[2].Name != "negative_retry" || results[2].Err == nil || hits.Load() != 1 {
		t.Fatalf("direct SendReports results=%+v hits=%d", results, hits.Load())
	}
}

func TestWarnFailureContinuesNextInterval(t *testing.T) {
	requests := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503); requests <- struct{}{} }))
	defer server.Close()
	opts := testOptions()
	opts.Mode = Intervals
	opts.DryRun = false
	opts.CancelPolicy = DropCanceled
	opts.SendFailurePolicy = WarnFailure
	opts.Tasks = []Task{{Name: "fixture", Group: "fixture", Collect: func(context.Context) (any, error) { return true, nil }}}
	opts.Targets = []Target{{Name: "fixture", Endpoint: server.URL, Timeout: time.Second}}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	ticks := make(chan time.Time, 1)
	r.newTicker = func(time.Duration) (<-chan time.Time, func()) { return ticks, func() {} }
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := r.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-requests:
		case <-time.After(time.Second):
			t.Fatal("WarnFailure did not continue collection")
		}
		if i == 0 {
			ticks <- time.Now()
		}
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("WarnFailure returned target error: %v", err)
	}
}

func TestReturnFailureStillAcceptsPartialDelivery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/failed" {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	}))
	defer server.Close()
	opts := testOptions()
	opts.DryRun = false
	opts.SendFailurePolicy = ReturnFailure
	opts.Targets = []Target{{Name: "failed", Endpoint: server.URL, Path: "/failed", Timeout: time.Second}, {Name: "delivered", Endpoint: server.URL, Path: "/ok", Timeout: time.Second}}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("partial delivery was incorrectly fatal: %v", err)
	}
}

func TestSendOneAcceptsNilLoggerAndRejectsNegativeRetry(t *testing.T) {
	for _, retry := range []int{0, 1, -1} {
		t.Run(fmt.Sprintf("retry_%d", retry), func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n := hits.Add(1)
				if retry == 1 && n == 1 {
					w.WriteHeader(503)
					return
				}
				w.WriteHeader(204)
			}))
			defer server.Close()
			var err error
			var panicValue any
			func() {
				defer func() { panicValue = recover() }()
				err = SendOne(context.Background(), Target{Name: "fixture", Endpoint: server.URL, Timeout: time.Second, RetryCount: retry}, []byte(`{}`), "fixture", "", nil)
			}()
			if panicValue != nil {
				t.Fatalf("nil logger panicked: %v", panicValue)
			}
			if retry < 0 {
				if err == nil || hits.Load() != 0 {
					t.Fatalf("invalid retry accepted: err=%v hits=%d", err, hits.Load())
				}
			} else if err != nil || hits.Load() != int32(retry+1) {
				t.Fatalf("valid send err=%v hits=%d", err, hits.Load())
			}
		})
	}
}
