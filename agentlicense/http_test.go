package license

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestVerifyWithMonitorWireAndErrors(t *testing.T) {
	const agentID = "tenant-vps-example"
	v := New()
	for _, endpoint := range []string{"", "http://localhost"} {
		if token, err := v.VerifyWithMonitor(context.Background(), agentID, "test-key", endpoint); err != nil || token != "" {
			t.Fatal("unset endpoint semantics changed")
		}
	}
	for _, tc := range []struct {
		name   string
		status int
		body   string
		ok     bool
	}{
		{"success", 200, `{"ok":true,"token":"test-token"}`, true},
		{"unauthorized", 401, `{}`, false}, {"forbidden", 403, `{}`, false},
		{"server error", 500, `{}`, false}, {"malformed", 200, `invalid`, false},
		{"false", 200, `{"ok":false,"token":"test-token"}`, false},
		{"empty token", 200, `{"ok":true,"token":""}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/prefix/api/license/verify" || r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Error("verify request wire changed")
				}
				var payload map[string]string
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["agent_id"] != agentID || payload["license_key"] != "test-key" {
					t.Error("verify payload changed")
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			token, err := v.VerifyWithMonitor(context.Background(), agentID, "test-key", srv.URL+"/prefix/")
			if tc.ok {
				if err != nil || token != "test-token" {
					t.Fatal("verify failed", err)
				}
			} else if err == nil {
				t.Fatal("failed verification accepted")
			}
		})
	}
}

func TestHeartbeatReauthAndTokenRefresh(t *testing.T) {
	const agentID = "tenant-vps-example"
	var verifies atomic.Int32
	seen := make(chan string, 32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Error("heartbeat method changed")
		}
		switch r.URL.Path {
		case "/api/license/heartbeat":
			if r.Header.Get("X-Agent-Id") != agentID {
				t.Error("heartbeat agent header missing")
			}
			auth := r.Header.Get("Authorization")
			select {
			case seen <- auth:
			default:
			}
			if auth == "Bearer old.test.token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if auth != "Bearer new.test.token" && auth != "Bearer latest.test.token" {
				t.Error("unexpected heartbeat token")
			}
			_, _ = w.Write([]byte(`{"ok":true,"token":"latest.test.token"}`))
		case "/api/license/verify":
			verifies.Add(1)
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["agent_id"] != agentID || payload["license_key"] != "test-key" {
				t.Error("reauth payload changed")
			}
			_, _ = w.Write([]byte(`{"ok":true,"token":"new.test.token"}`))
		default:
			t.Error("unexpected license URL")
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	v := New()
	v.StartHeartbeat(ctx, agentID, "test-key", "old.test.token", srv.URL, 5*time.Millisecond)
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case auth := <-seen:
			if auth == "Bearer latest.test.token" {
				cancel()
				if verifies.Load() != 1 || v.CurrentToken() != "latest.test.token" {
					t.Fatal("heartbeat reauth or refreshed token not retained")
				}
				return
			}
		case <-deadline.C:
			t.Fatal("heartbeat did not reauthenticate and refresh")
		}
	}
}
