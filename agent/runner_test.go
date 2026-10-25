package agent

import (
	"context"
	"errors"
	license "github.com/ishizakahiroshi/heartpost/agentlicense"
	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/filelock"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func testOptions() Options {
	return Options{Identity: Identity{ID: "example-agent", Type: "rental"}, Logger: log.New(io.Discard, "", 0), DryRun: true}
}
func task(name string, f func(context.Context) (any, error)) Task {
	return Task{Name: name, Collect: f}
}
func TestNewSnapshotsAndHasNoEffects(t *testing.T) {
	opts := testOptions()
	opts.LockPath = filepath.Join(t.TempDir(), "agent.lock")
	opts.Jobs = map[string]bool{"example": false}
	opts.Tasks = []Task{task("example", func(context.Context) (any, error) { t.Error("disabled task called"); return nil, nil })}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	opts.Jobs["example"] = true
	opts.Tasks[0].Collect = func(context.Context) (any, error) { t.Error("mutated task called"); return nil, nil }
	if _, err := os.Stat(opts.LockPath); !os.IsNotExist(err) {
		t.Fatal("New opened lock")
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("repeat: %v", err)
	}
}
func TestCloseBeforeRunAndDuplicateValidation(t *testing.T) {
	opts := testOptions()
	r, _ := New(opts)
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	opts.Tasks = []Task{task("same", func(context.Context) (any, error) { return nil, nil }), task("same", func(context.Context) (any, error) { return nil, nil })}
	if _, err := New(opts); err == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestCloseWaitsAndActiveRunnersDoNotMix(t *testing.T) {
	entered := make(chan struct{})
	canceled := make(chan struct{})
	release := make(chan struct{})
	opts := testOptions()
	opts.LockPath = filepath.Join(t.TempDir(), "agent.lock")
	opts.Tasks = []Task{task("blocked", func(ctx context.Context) (any, error) {
		close(entered)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	})}
	r, _ := New(opts)
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	<-entered
	other, _ := New(testOptions())
	if err := other.Run(context.Background()); !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("active guard: %v", err)
	}
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := r.Close(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	<-canceled
	if unlock, err := filelock.Acquire(opts.LockPath); !errors.Is(err, filelock.ErrLocked) {
		if err == nil {
			unlock()
		}
		t.Fatalf("lock released before callback exit: %v", err)
	}
	close(release)
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	unlock, err := filelock.Acquire(opts.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
func TestCancellationPoliciesAndErrors(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, policy := range []CancelPolicy{ReportCanceled, FailCanceled, DropCanceled} {
		opts := testOptions()
		opts.CancelPolicy = policy
		opts.Tasks = []Task{task("example", func(context.Context) (any, error) { t.Fatal("canceled task called"); return nil, nil })}
		r, _ := New(opts)
		got, err := r.Collect(ctx)
		if policy == ReportCanceled {
			if err != nil || len(got) != 1 {
				t.Fatalf("report: %v %+v", err, got)
			}
		} else if !errors.Is(err, context.Canceled) {
			t.Fatalf("policy %d: %v", policy, err)
		}
	}
}
func TestIntervalGroupsStartImmediatelyAndConcurrently(t *testing.T) {
	first := make(chan struct{})
	second := make(chan struct{})
	var firstCount, secondCount atomic.Int32
	opts := testOptions()
	opts.Mode = Intervals
	opts.Intervals = map[string]time.Duration{"one": time.Hour, "two": time.Hour}
	opts.Tasks = []Task{{Name: "first", Group: "one", Collect: func(ctx context.Context) (any, error) {
		firstCount.Add(1)
		close(first)
		select {
		case <-second:
		case <-ctx.Done():
		}
		return nil, nil
	}}, {Name: "second", Group: "two", Collect: func(context.Context) (any, error) { secondCount.Add(1); close(second); return nil, nil }}}
	r, _ := New(opts)
	done := make(chan error, 1)
	go func() { done <- r.Run(context.Background()) }()
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("first not immediate")
	}
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("groups serialized")
	}
	if err := r.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if firstCount.Load() != 1 || secondCount.Load() != 1 {
		t.Fatal("unexpected extra tick")
	}
}

type fakeVerifier struct {
	mu                     sync.Mutex
	token                  string
	verifications          int
	monitorErr, offlineErr error
}

func (v *fakeVerifier) Verify(string, string) error { return nil }
func (v *fakeVerifier) VerifyWithMonitor(context.Context, string, string, string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.verifications++
	if v.monitorErr != nil {
		return "", v.monitorErr
	}
	if v.verifications == 1 {
		return "first-token", nil
	}
	return "second-token", nil
}
func (v *fakeVerifier) StartHeartbeat(context.Context, string, string, string, string, time.Duration) {
}
func (v *fakeVerifier) VerifyToken(string, string) (*license.Claims, error) {
	return nil, errors.New("not used")
}
func (v *fakeVerifier) VerifyOfflineLicense(string, string) (*license.Claims, error) {
	return &license.Claims{}, v.offlineErr
}
func (v *fakeVerifier) CurrentToken() string         { v.mu.Lock(); defer v.mu.Unlock(); return v.token }
func (v *fakeVerifier) SetCurrentToken(token string) { v.mu.Lock(); v.token = token; v.mu.Unlock() }

func TestPrimary401RefreshesOnceWithoutResendingSecondary(t *testing.T) {
	var primary, secondary atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !agentsig.Verify("example-key", r.Header.Get("X-Agent-Timestamp"), body, r.Header.Get("X-Agent-Signature")) {
			t.Error("invalid HMAC")
		}
		if r.URL.Path == "/primary" {
			attempt := primary.Add(1)
			if attempt == 1 {
				if r.Header.Get("Authorization") != "Bearer first-token" {
					t.Error("first token missing")
				}
				w.WriteHeader(401)
				return
			}
			if r.Header.Get("Authorization") != "Bearer second-token" {
				t.Error("renewed token missing")
			}
		} else {
			secondary.Add(1)
			w.WriteHeader(401)
		}
	}))
	defer server.Close()
	verifier := &fakeVerifier{}
	opts := testOptions()
	opts.DryRun = false
	opts.SendFailurePolicy = WarnFailure
	opts.License = &LicenseOptions{Verifier: verifier, Key: "example", PrimaryEndpoint: server.URL, RefreshPrimary401: true, PrimaryTargetName: "primary"}
	opts.Targets = []Target{{Name: "primary", Endpoint: server.URL, Path: "/primary", APIKey: "example-key", Timeout: time.Second}, {Name: "secondary", Endpoint: server.URL, Path: "/secondary", APIKey: "example-key", Timeout: time.Second}}
	r, _ := New(opts)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if primary.Load() != 2 || secondary.Load() != 1 || verifier.verifications != 2 {
		t.Fatalf("attempts: %d %d %d", primary.Load(), secondary.Load(), verifier.verifications)
	}
}
func TestDeliveryFailurePolicies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer server.Close()
	for _, policy := range []FailurePolicy{ReturnFailure, WarnFailure} {
		opts := testOptions()
		opts.DryRun = false
		opts.Targets = []Target{{Name: "example", Endpoint: server.URL, Timeout: time.Second}}
		opts.SendFailurePolicy = policy
		r, _ := New(opts)
		err := r.Run(context.Background())
		if (err != nil) != (policy == ReturnFailure) {
			t.Fatalf("policy %d: %v", policy, err)
		}
	}
}
func TestOfflineFailureDoesNotFallThroughToRelaxed(t *testing.T) {
	opts := testOptions()
	opts.License = &LicenseOptions{Verifier: &fakeVerifier{monitorErr: errors.New("offline"), offlineErr: errors.New("invalid")}, OfflineFile: "example.lic", Relaxed: true}
	r, _ := New(opts)
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("invalid configured offline license ignored")
	}
	opts.License.OfflineFile = ""
	r, _ = New(opts)
	if err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestServiceStartupFailureCleansUpAndReleasesActiveGuard(t *testing.T) {
	sentinel := errors.New("synthetic startup failure")
	var stopped atomic.Int32
	opts := testOptions()
	opts.Services = []BackgroundService{func(context.Context) (func(context.Context) error, error) {
		return func(context.Context) error { stopped.Add(1); return nil }, nil
	}, func(context.Context) (func(context.Context) error, error) { return nil, sentinel }}
	r, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Run(context.Background()); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	if stopped.Load() != 1 {
		t.Fatal("earlier service was not stopped")
	}
	other, _ := New(testOptions())
	if err := other.Run(context.Background()); err != nil {
		t.Fatalf("active guard leaked: %v", err)
	}
}
