package agent

import (
	"context"
	"errors"
	"fmt"
	license "github.com/ishizakahiroshi/heartpost/agentlicense"
	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/filelock"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var ErrAlreadyRunning = errors.New("agent: already running")
var ErrClosed = errors.New("agent: closed")
var active sync.Mutex

type Runner struct {
	opts            Options
	mu              sync.Mutex
	started, closed bool
	cancel          context.CancelFunc
	done            chan struct{}
	newTicker       func(time.Duration) (<-chan time.Time, func())
}

// New validates and snapshots configuration without starting work or opening files.
// Collector globals permit one active Run per process; concurrent runs are rejected.
func New(opts Options) (*Runner, error) {
	if opts.Identity.ID == "" {
		return nil, fmt.Errorf("agent: ID is required")
	}
	if opts.Mode > Intervals || opts.CancelPolicy > DropCanceled || opts.SendFailurePolicy > WarnFailure || opts.Encoding > SortedCompact {
		return nil, fmt.Errorf("agent: invalid runtime policy")
	}
	names := map[string]bool{}
	opts.Tasks = append([]Task(nil), opts.Tasks...)
	for _, task := range opts.Tasks {
		if task.Name == "" || task.Collect == nil || names[task.Name] {
			return nil, fmt.Errorf("agent: invalid or duplicate task %q", task.Name)
		}
		names[task.Name] = true
	}
	opts.Targets = append([]Target(nil), opts.Targets...)
	targetNames := map[string]bool{}
	for index, target := range opts.Targets {
		if target.Name == "" || target.RetryCount < 0 || target.Timeout < 0 || targetNames[target.Name] {
			return nil, fmt.Errorf("agent: invalid or duplicate target %q", target.Name)
		}
		targetNames[target.Name] = true
		if target.Timeout == 0 {
			opts.Targets[index].Timeout = 10 * time.Second
		}
	}
	if !opts.DryRun && len(opts.Targets) == 0 {
		return nil, fmt.Errorf("agent: report target required")
	}
	jobs := make(map[string]bool, len(opts.Jobs))
	for k, v := range opts.Jobs {
		jobs[k] = v
	}
	opts.Jobs = jobs
	intervals := make(map[string]time.Duration, len(opts.Intervals))
	for k, v := range opts.Intervals {
		intervals[k] = v
	}
	opts.Intervals = intervals
	opts.Services = append([]BackgroundService(nil), opts.Services...)
	for _, service := range opts.Services {
		if service == nil {
			return nil, fmt.Errorf("agent: nil background service")
		}
	}
	if opts.UnknownInterval <= 0 {
		opts.UnknownInterval = 5 * time.Minute
	}
	if opts.Logger == nil {
		opts.Logger = log.New(io.Discard, "", 0)
	}
	if opts.License != nil {
		cfg := *opts.License
		if cfg.Verifier == nil {
			return nil, fmt.Errorf("agent: license verifier required")
		}
		if cfg.VerifyTimeout <= 0 {
			cfg.VerifyTimeout = 30 * time.Second
		}
		opts.License = &cfg
	}
	return &Runner{opts: opts, done: make(chan struct{}), newTicker: func(duration time.Duration) (<-chan time.Time, func()) {
		ticker := time.NewTicker(duration)
		return ticker.C, ticker.Stop
	}}, nil
}

// Collect executes one ordered batch. Callbacks receive ctx directly; this lower
// level operation does not configure collector globals or start any services.
func (r *Runner) Collect(ctx context.Context) (map[string]any, error) {
	return r.collect(ctx, r.opts.Tasks)
}

func (r *Runner) Run(parent context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return ErrAlreadyRunning
	}
	r.started = true
	ctx, cancel := context.WithCancel(parent)
	r.cancel = cancel
	r.mu.Unlock()
	defer func() { cancel(); r.mu.Lock(); r.closed = true; r.mu.Unlock(); close(r.done) }()
	if !active.TryLock() {
		return ErrAlreadyRunning
	}
	defer active.Unlock()
	if r.opts.LockPath != "" {
		if r.opts.CreateLockDirectory {
			if err := os.MkdirAll(filepath.Dir(r.opts.LockPath), 0755); err != nil {
				return fmt.Errorf("create lock directory: %w", err)
			}
		}
		release, err := filelock.Acquire(r.opts.LockPath)
		if err != nil {
			return fmt.Errorf("acquire lock: %w", err)
		}
		defer release()
	}
	token, err := r.verify(ctx)
	if err != nil {
		return err
	}
	// As in the existing one-shot commands, collection timeout begins after verification.
	if r.opts.Timeout > 0 {
		var timeoutCancel context.CancelFunc
		ctx, timeoutCancel = context.WithTimeout(ctx, r.opts.Timeout)
		defer timeoutCancel()
	}
	collector.SetShutdownCh(ctx.Done())
	location := r.opts.Location
	if location == nil {
		location = time.Local
	}
	collector.SetLocation(location)
	if r.opts.Initialize != nil {
		r.opts.Initialize(ctx)
	}
	var stops []func(context.Context) error
	defer func() {
		cancel()
		for i := len(stops) - 1; i >= 0; i-- {
			stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := stops[i](stopCtx); err != nil {
				r.opts.Logger.Printf("WARN: service close: %v", err)
			}
			stopCancel()
		}
	}()
	for _, service := range r.opts.Services {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stop, err := service(ctx)
		if err != nil {
			return err
		}
		if stop != nil {
			stops = append(stops, stop)
		}
	}
	var heartbeat sync.WaitGroup
	if cfg := r.opts.License; cfg != nil && cfg.HeartbeatInterval > 0 && token != "" {
		heartbeat.Add(1)
		go func() {
			defer heartbeat.Done()
			license.RunHeartbeat(ctx, cfg.Verifier, r.opts.Identity.ID, cfg.Key, cfg.PrimaryEndpoint, cfg.HeartbeatInterval)
		}()
	}
	defer func() { cancel(); heartbeat.Wait() }()
	if r.opts.Mode == Once {
		return r.cycle(ctx, r.opts.Tasks)
	}
	groups := GroupBy(r.opts.Tasks, func(task Task) string { return task.Group })
	failures := make(chan error, 1)
	var workers sync.WaitGroup
	for group, tasks := range groups {
		duration := r.opts.Intervals[group]
		if duration <= 0 {
			duration = r.opts.UnknownInterval
		}
		workers.Add(1)
		go func(tasks []Task, d time.Duration) {
			defer workers.Done()
			ticks, stop := r.newTicker(d)
			defer stop()
			for {
				if err := r.cycle(ctx, tasks); err != nil {
					r.opts.Logger.Printf("WARN: report failed: %v", err)
					if r.opts.SendFailurePolicy == ReturnFailure {
						// Preserve the first failure before canceling other groups;
						// their cancellation errors must not replace its cause.
						select {
						case failures <- err:
						default:
						}
						cancel()
						return
					}
				}
				select {
				case <-ctx.Done():
					return
				case <-ticks:
				}
			}
		}(tasks, duration)
	}
	if len(groups) == 0 {
		return nil
	}
	<-ctx.Done()
	workers.Wait()
	select {
	case err := <-failures:
		return err
	default:
	}
	return nil
}

func (r *Runner) cycle(ctx context.Context, tasks []Task) error {
	values, err := r.collect(ctx, tasks)
	if err != nil {
		if r.opts.CancelPolicy == DropCanceled {
			return nil
		}
		return err
	}
	body, err := r.encode(values)
	if err != nil {
		return err
	}
	if r.opts.DryRun {
		r.opts.Logger.Printf("DEBUG: payload (dry-run):\n%s", body)
		return nil
	}
	token := ""
	if r.opts.License != nil {
		token = r.opts.License.Verifier.CurrentToken()
	}
	results := SendReports(ctx, r.opts.Targets, body, r.opts.Identity.ID, token, r.opts.Logger)
	successes := 0
	var failure error
	for index, result := range results {
		if result.Err == nil {
			successes++
			continue
		}
		cfg := r.opts.License
		var status *HTTPStatusError
		if cfg != nil && cfg.RefreshPrimary401 && result.Name == cfg.PrimaryTargetName && errors.As(result.Err, &status) && status.StatusCode == 401 {
			if cfg.CachePath != "" {
				if err := ClearTokenCache(cfg.CachePath); err != nil {
					r.opts.Logger.Printf("WARN: token cache clear failed: %v", err)
				}
			}
			refreshCtx, cancel := context.WithTimeout(ctx, cfg.VerifyTimeout)
			token, err := r.resolveToken(refreshCtx, true)
			cancel()
			if err != nil {
				return fmt.Errorf("license refresh failed after 401: %w", err)
			}
			cfg.Verifier.SetCurrentToken(token)
			if err := SendOne(ctx, r.opts.Targets[index], body, r.opts.Identity.ID, token, r.opts.Logger); err != nil {
				return fmt.Errorf("report retry failed: %w", err)
			}
			successes++
			continue
		}
		failure = result.Err
		r.opts.Logger.Printf("WARN: report target=%s failed: %v", result.Name, result.Err)
	}
	if successes == 0 && failure != nil && r.opts.SendFailurePolicy == ReturnFailure {
		return failure
	}
	return nil
}

// Close cancels an active run and waits for its collectors and requests to exit.
func (r *Runner) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	started := r.started
	if r.cancel != nil {
		r.cancel()
	}
	r.mu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-r.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
