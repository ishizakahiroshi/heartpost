//go:build !windows

package httpoutcome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSinkCreatesMode0600(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "r.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestFileSinkRefusesWritableFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "r.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileSink(path); err == nil {
			t.Fatalf("mode %o accepted", mode)
		}
	}
}

func TestFileSinkRefusesWritableParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSink(filepath.Join(dir, "r.jsonl")); err == nil {
		t.Fatal("group-writable parent accepted")
	}
}
