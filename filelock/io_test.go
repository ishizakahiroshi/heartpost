package filelock

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestAcquireIOErrorsAreNotContention(t *testing.T) {
	for _, path := range []string{t.TempDir(), filepath.Join(t.TempDir(), "absent", "agent.lock")} {
		unlock, err := Acquire(path)
		if unlock != nil {
			unlock()
		}
		if err == nil || errors.Is(err, ErrLocked) {
			t.Fatalf("I/O error misclassified: %v", err)
		}
	}
}
