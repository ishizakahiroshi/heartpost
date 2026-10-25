package r2

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOperationsClassificationsWithMockTransport(t *testing.T) {
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	http.DefaultTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.Host != "api.cloudflare.com" || r.Header.Get("Authorization") != "Bearer synthetic" {
			t.Fatal("unexpected provider request")
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "example123") {
			t.Fatal("account filter lost")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"accounts":[{"r2OperationsAdaptiveGroups":[{"dimensions":{"actionType":"PutObject"},"sum":{"requests":3}},{"dimensions":{"actionType":"GetObject"},"sum":{"requests":4}},{"dimensions":{"actionType":"Unknown"},"sum":{"requests":9}}]}]}}}`))}, nil
	})
	got, err := CollectOperations("example123", "synthetic")
	if err != nil || got.ClassA != 3 || got.ClassB != 4 || got.Month != time.Now().UTC().Format("2006-01") || calls != 1 {
		t.Fatalf("result=%+v %v calls%d", got, err, calls)
	}
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"data":{"viewer":{"accounts":[]}}}`))}, nil
	})
	if _, err := CollectOperations("example123", "synthetic"); err == nil {
		t.Fatal("empty account response accepted")
	}
}
