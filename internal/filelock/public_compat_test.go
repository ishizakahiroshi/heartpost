package filelock

import (
	"errors"
	"path/filepath"
	"testing"

	publiclock "github.com/ishizakahiroshi/heartpost/filelock"
)

func TestInternalAndPublicLocksShareSentinelAndState(t *testing.T) {
	if ErrLocked != publiclock.ErrLocked {
		t.Fatal("contention sentinel differs")
	}
	path := filepath.Join(t.TempDir(), "shared.lock")
	unlock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	if extra, err := publiclock.TryAcquire(path); !errors.Is(err, ErrLocked) {
		if extra != nil {
			extra()
		}
		unlock()
		t.Fatal("public path did not contend with internal path", err)
	}
	unlock()
	publicUnlock, err := publiclock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer publicUnlock()
	if extra, err := TryAcquire(path); !errors.Is(err, publiclock.ErrLocked) {
		if extra != nil {
			extra()
		}
		t.Fatal("internal path did not contend with public path", err)
	}
}
