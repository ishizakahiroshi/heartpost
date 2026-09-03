package filelock

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// TestErrLockedIsSentinel は ErrLocked が errors.Is で識別できる sentinel であり、
// 無関係なエラー（open 失敗等）と混ざらないことを固定する。
// 呼び出し側はこの区別に依存して「既に走っている」と「設定が壊れている」を分けている。
func TestErrLockedIsSentinel(t *testing.T) {
	if !errors.Is(ErrLocked, ErrLocked) {
		t.Fatal("ErrLocked should match itself via errors.Is")
	}
	wrapped := fmt.Errorf("agent lock: %w", ErrLocked)
	if !errors.Is(wrapped, ErrLocked) {
		t.Fatal("wrapped ErrLocked should be detectable via errors.Is")
	}
	if errors.Is(errors.New("permission denied"), ErrLocked) {
		t.Fatal("unrelated error must not match ErrLocked")
	}
}

// TestAcquireRejectsSecondHolder は二重起動防止の本体。
// ロックを握ったまま同じパスを取りに行くと ErrLocked になること。
func TestAcquireRejectsSecondHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")

	unlock, err := Acquire(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	defer unlock()

	if _, err := TryAcquire(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire should return ErrLocked, got %v", err)
	}
}

// TestAcquireReleaseRoundTrip は解放後に再取得できることを確認する。
// ロックファイルを消さない実装なので、ファイルが残っていても次回が通ることが要件。
func TestAcquireReleaseRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "round.lock")

	unlock, err := Acquire(path)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	unlock()

	unlock2, err := Acquire(path)
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	unlock2()
}
