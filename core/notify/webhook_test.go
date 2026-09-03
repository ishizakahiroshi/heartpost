package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebhookPostsEvent(t *testing.T) {
	var got Event
	var contentType, auth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contentType = r.Header.Get("Content-Type")
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, 5*time.Second)
	wh.Header = map[string]string{"Authorization": "Bearer sample-token"}

	ev := Event{
		Kind:             KindDown,
		AgentID:          "web-01",
		AgentLabel:       "web-01 (front)",
		LastSeen:         time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC),
		SilenceSeconds:   1200,
		ThresholdSeconds: 900,
		OccurredAt:       time.Date(2026, 3, 1, 9, 20, 0, 0, time.UTC),
		Text:             FormatText(KindDown, "web-01 (front)", 20*time.Minute, 15*time.Minute),
	}
	if err := wh.Notify(context.Background(), ev); err != nil {
		t.Fatalf("Notify: %v", err)
	}

	if got.Kind != KindDown || got.AgentID != "web-01" || got.SilenceSeconds != 1200 {
		t.Fatalf("received event = %+v", got)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q", contentType)
	}
	if auth != "Bearer sample-token" {
		t.Errorf("Authorization = %q", auth)
	}
}

func TestWebhookNonSuccessStatusIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	wh := NewWebhook(srv.URL, 5*time.Second)
	if err := wh.Notify(context.Background(), Event{Kind: KindDown, AgentID: "web-01"}); err == nil {
		t.Fatal("500 response should be an error")
	}
}

func TestWebhookEmptyURLIsError(t *testing.T) {
	wh := NewWebhook("  ", time.Second)
	if err := wh.Notify(context.Background(), Event{}); err == nil {
		t.Fatal("empty url should be an error")
	}
}

func TestMultiAggregatesErrors(t *testing.T) {
	ok := &countingNotifier{}
	bad := NewWebhook("", time.Second)
	m := Multi{ok, bad, nil}
	if err := m.Notify(context.Background(), Event{}); err == nil {
		t.Fatal("Multi should return the failure")
	}
	if ok.n != 1 {
		t.Errorf("healthy notifier called %d times, want 1", ok.n)
	}
}

func TestDiscardIsSilent(t *testing.T) {
	if err := (Discard{}).Notify(context.Background(), Event{}); err != nil {
		t.Fatalf("Discard should never fail: %v", err)
	}
}

func TestFormatText(t *testing.T) {
	down := FormatText(KindDown, "web-01", 20*time.Minute, 15*time.Minute)
	if down == "" || !contains(down, "欠報") || !contains(down, "web-01") {
		t.Errorf("down text = %q", down)
	}
	up := FormatText(KindRecovered, "web-01", 0, 15*time.Minute)
	if !contains(up, "復帰") {
		t.Errorf("recovered text = %q", up)
	}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }

type countingNotifier struct{ n int }

func (c *countingNotifier) Notify(context.Context, Event) error {
	c.n++
	return nil
}
