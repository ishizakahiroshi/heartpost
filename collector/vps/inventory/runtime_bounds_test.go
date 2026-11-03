package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type syntheticPIDEntry string

func (e syntheticPIDEntry) Name() string               { return string(e) }
func (e syntheticPIDEntry) IsDir() bool                { return true }
func (e syntheticPIDEntry) Type() os.FileMode          { return os.ModeDir }
func (e syntheticPIDEntry) Info() (os.FileInfo, error) { return nil, os.ErrNotExist }

func syntheticPIDs(count int) []os.DirEntry {
	entries := make([]os.DirEntry, count)
	for i := range entries {
		entries[i] = syntheticPIDEntry(fmt.Sprint(100000 + i))
	}
	return entries
}

func TestRuntimeProcScanIsBounded(t *testing.T) {
	entries := syntheticPIDs(20000)
	calls := 0
	c := &Collector{lookPath: func(name string) (string, error) { return name, nil },
		readDir:  func(string) ([]os.DirEntry, error) { return entries, nil },
		readlink: func(string) (string, error) { calls++; return "/usr/bin/unrelated", nil },
	}
	var o Observation
	start := time.Now()
	c.collectRuntimes(&o, func(string, ...string) ([]byte, error) { return nil, exec.ErrNotFound })
	t.Logf("synthetic entries=%d readlinks=%d elapsed=%s status=%s code=%s", len(entries), calls, time.Since(start), o.Status, o.ErrorCode)
	if calls > 4096 || o.Status != "partial" || o.ErrorCode != "process_scan_limit" {
		t.Fatalf("unbounded process discovery: readlinks=%d status=%s code=%s", calls, o.Status, o.ErrorCode)
	}
}

func TestRuntimePIDReportIsBounded(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-executable")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	c := &Collector{lookPath: func(name string) (string, error) { return name, nil },
		readDir:  func(string) ([]os.DirEntry, error) { return syntheticPIDs(3000), nil },
		readlink: func(string) (string, error) { return "/usr/sbin/php-fpm8.3", nil },
		stat:     func(string) (os.FileInfo, error) { return info, nil },
	}
	var o Observation
	c.collectRuntimes(&o, func(name string, _ ...string) ([]byte, error) {
		if name == "php-fpm" {
			return []byte("PHP 8.3.6"), nil
		}
		return nil, exec.ErrNotFound
	})
	body, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	items := o.Value.([]Runtime)
	last := items[len(items)-1]
	t.Logf("synthetic processes=%d json_bytes=%d status=%s code=%s", len(last.Processes), len(body), o.Status, o.ErrorCode)
	if len(last.Processes) > 128 || len(body) > 16<<10 || o.Status != "partial" || o.ErrorCode != "runtime_process_limit" {
		t.Fatalf("unbounded PID evidence: processes=%d bytes=%d status=%s code=%s", len(last.Processes), len(body), o.Status, o.ErrorCode)
	}
}

func TestRuntimeScanBoundaryDoesNotClaimTruncationAtExactLimit(t *testing.T) {
	for _, count := range []int{maxRuntimeProcEntries - 1, maxRuntimeProcEntries, maxRuntimeProcEntries + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			calls := 0
			c := &Collector{lookPath: func(name string) (string, error) { return name, nil },
				readDir:  func(string) ([]os.DirEntry, error) { return syntheticPIDs(count), nil },
				readlink: func(string) (string, error) { calls++; return "/usr/bin/unrelated", nil },
			}
			var o Observation
			c.collectRuntimes(&o, func(string, ...string) ([]byte, error) { return nil, exec.ErrNotFound })
			if count <= maxRuntimeProcEntries {
				if calls != count || o.Status != "ok" {
					t.Fatalf("exact boundary became partial: calls=%d status=%s", calls, o.Status)
				}
			} else if calls != maxRuntimeProcEntries || o.Status != "partial" || o.ErrorCode != "process_scan_limit" {
				t.Fatalf("lookahead did not mark truncation: calls=%d status=%s code=%s", calls, o.Status, o.ErrorCode)
			}
		})
	}
}

func TestRuntimeProcReaderUsesSyntheticDirectory(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"1", "2", "not-a-pid"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := readRuntimeProcEntries(dir)
	if err != nil || len(entries) != 3 {
		t.Fatalf("short directory: entries=%d err=%v", len(entries), err)
	}
	if _, err := readRuntimeProcEntries(filepath.Join(dir, "missing")); !os.IsNotExist(err) {
		t.Fatalf("missing directory error=%v", err)
	}
}

func TestRuntimePIDBoundaryPreservesExactCount(t *testing.T) {
	file := filepath.Join(t.TempDir(), "synthetic-executable")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{maxRuntimeProcesses, maxRuntimeProcesses + 1} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			c := &Collector{lookPath: func(name string) (string, error) { return name, nil },
				readDir:  func(string) ([]os.DirEntry, error) { return syntheticPIDs(count), nil },
				readlink: func(string) (string, error) { return "/usr/sbin/php-fpm8.3", nil },
				stat:     func(string) (os.FileInfo, error) { return info, nil },
			}
			var o Observation
			c.collectRuntimes(&o, func(name string, _ ...string) ([]byte, error) {
				if name == "php-fpm" {
					return []byte("PHP 8.3.6"), nil
				}
				return nil, exec.ErrNotFound
			})
			items := o.Value.([]Runtime)
			if len(items[len(items)-1].Processes) != maxRuntimeProcesses {
				t.Fatal("PID examples lost below the bound")
			}
			if count == maxRuntimeProcesses && o.Status != "ok" {
				t.Fatalf("exact boundary status=%s", o.Status)
			}
			if count > maxRuntimeProcesses && (o.Status != "partial" || o.ErrorCode != "runtime_process_limit") {
				t.Fatalf("PID truncation status=%s code=%s", o.Status, o.ErrorCode)
			}
		})
	}
}
