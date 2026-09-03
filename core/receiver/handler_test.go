package receiver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/agentsig"
	"github.com/ishizakahiroshi/heartpost/report"
)

const (
	testAgentID = "web-01"
	testKey     = "test-shared-secret-not-a-real-key"
)

func newTestHandler(t *testing.T, dir string, cfg Config) (*Handler, *Store) {
	t.Helper()
	store, err := NewStore(dir, 90)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if cfg.AgentKeys == nil {
		cfg.AgentKeys = map[string]string{testAgentID: testKey}
	}
	h, err := NewHandler(store, cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, store
}

// samplePayload は合成データのレポート本体を返す（実サーバー由来の値は含めない）。
func samplePayload(agentID string) []byte {
	p := report.Payload{
		AgentID:    agentID,
		AgentLabel: "sample web server",
		AgentType:  "rental",
		ReportedAt: "2026-01-02T03:04:05Z",
		Collectors: map[string]json.RawMessage{
			"host":    json.RawMessage(`{"hostname":"web-01.example.net","os":"FreeBSD sample 14.0"}`),
			"disk":    json.RawMessage(`[{"filesystem":"/dev/da0p2","size":"20G","used":"8.0G","avail":"12G","use_percent":"40%","mounted":"/"}]`),
			"loadavg": json.RawMessage(`{"load1":0.12,"load5":0.34,"load15":0.56}`),
		},
	}
	b, _ := json.Marshal(p)
	return b
}

func signedRequest(agentID, key string, ts time.Time, body []byte) *http.Request {
	tsStr := strconv.FormatInt(ts.Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, report.DefaultPath, strings.NewReader(string(body)))
	req.Header.Set(report.HeaderAgentID, agentID)
	req.Header.Set(report.HeaderTimestamp, tsStr)
	req.Header.Set(report.HeaderSignature, agentsig.Compute(key, tsStr, body))
	req.RemoteAddr = "203.0.113.10:54321"
	return req
}

func TestReportAcceptedWithValidSignature(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	h, store := newTestHandler(t, dir, Config{Now: func() time.Time { return now }})

	body := samplePayload(testAgentID)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(testAgentID, testKey, now, body))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	path := filepath.Join(dir, reportsDirName, "report_"+testAgentID+"_20260102.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("report file not written: %v", err)
	}
	if !strings.Contains(string(data), `"agent_id":"`+testAgentID+`"`) {
		t.Fatalf("report file does not contain the record: %s", data)
	}

	states := store.States()
	if len(states) != 1 {
		t.Fatalf("states = %d, want 1", len(states))
	}
	st := states[0]
	if !st.LastSeen.Equal(now) {
		t.Errorf("LastSeen = %v, want %v", st.LastSeen, now)
	}
	if st.Hostname != "web-01.example.net" {
		t.Errorf("Hostname = %q", st.Hostname)
	}
	if st.RootDiskPercent != "40%" {
		t.Errorf("RootDiskPercent = %q, want 40%%", st.RootDiskPercent)
	}
	if !st.HasLoad || st.Load1 != 0.12 || st.Load15 != 0.56 {
		t.Errorf("load not captured: %+v", st)
	}
}

func TestReportRejected(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	body := samplePayload(testAgentID)

	tests := []struct {
		name     string
		mutate   func(r *http.Request)
		wantCode int
	}{
		{
			name: "鍵が違う",
			mutate: func(r *http.Request) {
				tsStr := r.Header.Get(report.HeaderTimestamp)
				r.Header.Set(report.HeaderSignature, agentsig.Compute("wrong-key", tsStr, body))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "ボディが改竄されている",
			mutate: func(r *http.Request) {
				tampered := strings.Replace(string(body), "sample web server", "tampered label", 1)
				r.Body = newBody(tampered)
				r.ContentLength = int64(len(tampered))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "タイムスタンプが古い",
			mutate: func(r *http.Request) {
				old := now.Add(-10 * time.Minute)
				tsStr := strconv.FormatInt(old.Unix(), 10)
				r.Header.Set(report.HeaderTimestamp, tsStr)
				r.Header.Set(report.HeaderSignature, agentsig.Compute(testKey, tsStr, body))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "タイムスタンプが未来すぎる",
			mutate: func(r *http.Request) {
				future := now.Add(10 * time.Minute)
				tsStr := strconv.FormatInt(future.Unix(), 10)
				r.Header.Set(report.HeaderTimestamp, tsStr)
				r.Header.Set(report.HeaderSignature, agentsig.Compute(testKey, tsStr, body))
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "署名ヘッダが無い",
			mutate: func(r *http.Request) {
				r.Header.Del(report.HeaderSignature)
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "未登録の agent",
			mutate: func(r *http.Request) {
				r.Header.Set(report.HeaderAgentID, "unregistered-agent")
			},
			wantCode: http.StatusUnauthorized,
		},
		{
			name: "本文の agent_id がヘッダと食い違う",
			mutate: func(r *http.Request) {
				other := samplePayload("web-02")
				tsStr := r.Header.Get(report.HeaderTimestamp)
				r.Body = newBody(string(other))
				r.ContentLength = int64(len(other))
				r.Header.Set(report.HeaderSignature, agentsig.Compute(testKey, tsStr, other))
			},
			wantCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			h, store := newTestHandler(t, dir, Config{
				Now:  func() time.Time { return now },
				Logf: func(string, ...any) {},
			})
			req := signedRequest(testAgentID, testKey, now, body)
			tt.mutate(req)

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tt.wantCode, rec.Body.String())
			}
			for _, st := range store.States() {
				if !st.LastSeen.IsZero() {
					t.Fatalf("rejected report updated last_seen for %s", st.AgentID)
				}
			}
			entries, _ := os.ReadDir(filepath.Join(dir, reportsDirName))
			if len(entries) != 0 {
				t.Fatalf("rejected report wrote %d file(s)", len(entries))
			}
		})
	}
}

func TestReportRejectsMethodAndOversizedBody(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	h, _ := newTestHandler(t, dir, Config{MaxBodyBytes: 512, Logf: func(string, ...any) {}})

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, report.DefaultPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}

	big := make([]byte, 4096)
	for i := range big {
		big[i] = 'x'
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, signedRequest(testAgentID, testKey, now, big))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized status = %d, want 413", rec.Code)
	}
}

// TestReportRejectsPathTraversalAgentID は agent_id にパス脱出を仕込んでも
// base ディレクトリの外へファイルが作られないことを確かめる。
func TestReportRejectsPathTraversalAgentID(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	now := time.Now()

	evilIDs := []string{
		"../evil",
		"..\\evil",
		"../../etc/evil",
		"web-01/../../evil",
		"..",
		".",
		"web 01",
		"web_01",
		strings.Repeat("a", 65),
	}

	keys := map[string]string{testAgentID: testKey}
	for _, id := range evilIDs {
		// 鍵まで登録された状態でも入口の形式検証で落ちることを見る。
		keys[id] = testKey
	}
	h, _ := newTestHandler(t, dataDir, Config{AgentKeys: keys, Logf: func(string, ...any) {}})

	for _, id := range evilIDs {
		body := samplePayload(id)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, signedRequest(id, testKey, now, body))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("agent_id %q: status = %d, want 400", id, rec.Code)
		}
	}

	// data ディレクトリの外に何も作られていないこと。
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "data" {
			t.Errorf("unexpected entry outside data dir: %s", e.Name())
		}
	}
	reports, err := os.ReadDir(filepath.Join(dataDir, reportsDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 0 {
		t.Errorf("reports dir should be empty, got %d entries", len(reports))
	}
}

// TestStoreRefusesEscapingAgentID は入口の検証を素通りさせても、
// 保存レイヤ単体で base の外へ書かないことを確かめる（多層防御）。
func TestStoreRefusesEscapingAgentID(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	store, err := NewStore(dataDir, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = store.Append(Record{AgentID: "../../escaped"}, time.Now())
	if err == nil {
		t.Fatal("Append with escaping agent_id should fail")
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.Name() != "data" {
			t.Errorf("unexpected entry outside data dir: %s", e.Name())
		}
	}
}

func TestIPAllowlist(t *testing.T) {
	now := time.Now()
	body := samplePayload(testAgentID)

	t.Run("allowlist 未設定なら制限しない", func(t *testing.T) {
		h, _ := newTestHandler(t, t.TempDir(), Config{Logf: func(string, ...any) {}})
		req := signedRequest(testAgentID, testKey, now, body)
		req.RemoteAddr = "198.51.100.77:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("allowlist 外は 403", func(t *testing.T) {
		h, _ := newTestHandler(t, t.TempDir(), Config{
			AllowedIPs: []string{"203.0.113.10", "198.51.100.0/24"},
			Logf:       func(string, ...any) {},
		})
		req := signedRequest(testAgentID, testKey, now, body)
		req.RemoteAddr = "192.0.2.5:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("allowlist 内は通る", func(t *testing.T) {
		h, _ := newTestHandler(t, t.TempDir(), Config{
			AllowedIPs: []string{"198.51.100.0/24"},
			Logf:       func(string, ...any) {},
		})
		req := signedRequest(testAgentID, testKey, now, body)
		req.RemoteAddr = "198.51.100.200:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("X-Forwarded-For は既定では見ない", func(t *testing.T) {
		h, _ := newTestHandler(t, t.TempDir(), Config{
			AllowedIPs: []string{"198.51.100.0/24"},
			Logf:       func(string, ...any) {},
		})
		req := signedRequest(testAgentID, testKey, now, body)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "198.51.100.200")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", rec.Code)
		}
	})

	t.Run("trust_forwarded_for を明示すれば見る", func(t *testing.T) {
		h, _ := newTestHandler(t, t.TempDir(), Config{
			AllowedIPs:        []string{"198.51.100.0/24"},
			TrustForwardedFor: true,
			Logf:              func(string, ...any) {},
		})
		req := signedRequest(testAgentID, testKey, now, body)
		req.RemoteAddr = "127.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "198.51.100.200")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
	})
}

func TestNewHandlerRejectsBadAllowlist(t *testing.T) {
	store, err := NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewHandler(store, Config{AllowedIPs: []string{"not-an-ip"}}); err == nil {
		t.Fatal("NewHandler should reject an unparsable allowed_ips entry")
	}
}

// TestRetentionDeletesOldReports は保持期間を過ぎた JSONL が削除されることを確かめる。
func TestRetentionDeletesOldReports(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 30)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	old := filepath.Join(dir, reportsDirName, "report_"+testAgentID+"_20260101.jsonl")
	recent := filepath.Join(dir, reportsDirName, "report_"+testAgentID+"_20260525.jsonl")
	unrelated := filepath.Join(dir, reportsDirName, "notes.txt")
	for _, p := range []string{old, recent, unrelated} {
		if err := os.WriteFile(p, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := store.Append(Record{AgentID: testAgentID}, now); err != nil {
		t.Fatalf("Append: %v", err)
	}

	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Errorf("old report should be deleted, stat err = %v", err)
	}
	if _, err := os.Stat(recent); err != nil {
		t.Errorf("recent report should be kept: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Errorf("unrelated file should be kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, reportsDirName, "report_"+testAgentID+"_20260601.jsonl")); err != nil {
		t.Errorf("today's report should exist: %v", err)
	}
}

func TestRetentionDisabled(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, reportsDirName, "report_"+testAgentID+"_20200101.jsonl")
	if err := os.WriteFile(old, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(Record{AgentID: testAgentID}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Errorf("retention disabled should keep old files: %v", err)
	}
}

// newBody は httptest.NewRequest が作った Body を差し替えるための小さなヘルパ。
func newBody(s string) readCloser {
	return readCloser{strings.NewReader(s)}
}

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }
