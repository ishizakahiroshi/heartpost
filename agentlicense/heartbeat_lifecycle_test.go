package license

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestStartHeartbeatPublishesInitialTokenSynchronously(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	verifier := New()
	verifier.StartHeartbeat(ctx, "example", "example", "initial-token", "http://example.test", time.Hour)
	if got := verifier.CurrentToken(); got != "initial-token" {
		t.Fatalf("initial token was deferred: %q", got)
	}
	verifier.StartHeartbeat(ctx, "example", "example", "ignored", "", time.Hour)
	if got := verifier.CurrentToken(); got != "initial-token" {
		t.Fatalf("skipped heartbeat changed token: %q", got)
	}
}

type lifecycleTransport func(*http.Request) (*http.Response, error)

func (f lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestRunHeartbeatJoinsCanceledInFlightRequest(t *testing.T) {
	entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	old := http.DefaultTransport
	http.DefaultTransport = lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		close(entered)
		<-r.Context().Done()
		close(canceled)
		<-release
		return nil, r.Context().Err()
	})
	defer func() { http.DefaultTransport = old }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	verifier := New()
	verifier.SetCurrentToken("token")
	go func() {
		defer close(done)
		RunHeartbeat(ctx, verifier, "example", "example", "http://example.test", time.Millisecond)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("request did not start")
	}
	cancel()
	<-canceled
	select {
	case <-done:
		t.Fatal("returned before request completed")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not join")
	}
}
