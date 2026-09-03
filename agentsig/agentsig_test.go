package agentsig

import (
	"strconv"
	"testing"
	"time"
)

// TestComputeDeterministic は同じ入力で同じ署名になることを確認する。
func TestComputeDeterministic(t *testing.T) {
	key := "test-key-abc"
	ts := "1700000000"
	body := []byte(`{"agent_id":"demo-web-01","collectors":{}}`)

	a := Compute(key, ts, body)
	b := Compute(key, ts, body)
	if a != b {
		t.Fatalf("Compute not deterministic: %q != %q", a, b)
	}
	if a == "" {
		t.Fatal("Compute returned empty signature")
	}
}

// TestRoundTrip は「Agent が署名 → Monitor が検証 OK」「鍵違いで検証失敗」を確認する。
// 送信側と受信側が同じ Compute を経由することの整合性を、この 1 本で固定する。
func TestRoundTrip(t *testing.T) {
	key := "shared-secret-key"
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	body := []byte(`{"agent_id":"demo-web-01","reported_at":"2026-01-02T03:04:05Z"}`)

	// Agent 側: 署名生成
	sig := Compute(key, ts, body)

	// Monitor 側: 同じ鍵で検証 → OK
	if !Verify(key, ts, body, sig) {
		t.Fatal("Verify failed for matching key (sign->verify round-trip broken)")
	}

	// 鍵違いでは検証失敗
	if Verify("wrong-key", ts, body, sig) {
		t.Fatal("Verify succeeded with wrong key (must fail)")
	}

	// body 改ざんでは検証失敗
	if Verify(key, ts, []byte(`{"tampered":true}`), sig) {
		t.Fatal("Verify succeeded with tampered body (must fail)")
	}

	// timestamp 違いでは検証失敗
	if Verify(key, "1", body, sig) {
		t.Fatal("Verify succeeded with wrong timestamp (must fail)")
	}
}
