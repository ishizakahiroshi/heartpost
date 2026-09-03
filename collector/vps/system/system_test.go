package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectSwap(t *testing.T) {
	dir := t.TempDir()
	meminfo := filepath.Join(dir, "meminfo")
	vmstat := filepath.Join(dir, "vmstat")
	mustWrite(t, meminfo, "MemTotal: 4096000 kB\nSwapTotal: 1024000 kB\nSwapFree: 768000 kB\n")
	mustWrite(t, vmstat, "pswpin 12\npswpout 34\n")

	oldMeminfo, oldVmstat := procMeminfoPath, procVmstatPath
	procMeminfoPath, procVmstatPath = meminfo, vmstat
	defer func() {
		procMeminfoPath, procVmstatPath = oldMeminfo, oldVmstat
	}()

	got, err := collectSwap()
	if err != nil {
		t.Fatalf("collectSwap() error = %v", err)
	}
	if got.TotalKB != 1024000 || got.FreeKB != 768000 || got.UsedKB != 256000 {
		t.Fatalf("unexpected swap sizes: %+v", got)
	}
	if got.UsagePercent != 25 || got.SwapInPages != 12 || got.SwapOutPages != 34 {
		t.Fatalf("unexpected swap counters: %+v", got)
	}
}

func TestCollectDiskIO(t *testing.T) {
	dir := t.TempDir()
	diskstats := filepath.Join(dir, "diskstats")
	mustWrite(t, diskstats, ""+
		"   7       0 loop0 1 0 8 1 0 0 0 0 0 1 1 0 0 0 0 0\n"+
		" 252       0 vda 10 0 20 3 30 0 40 5 0 6 7 0 0 0 0 0\n")

	old := procDiskstatsPath
	procDiskstatsPath = diskstats
	defer func() { procDiskstatsPath = old }()

	got, err := collectDiskIO()
	if err != nil {
		t.Fatalf("collectDiskIO() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(collectDiskIO()) = %d, want 1: %+v", len(got), got)
	}
	if got[0].Device != "vda" || got[0].ReadBytes != 20*512 || got[0].WriteBytes != 40*512 {
		t.Fatalf("unexpected disk io: %+v", got[0])
	}
}

func TestCollectOpenFiles(t *testing.T) {
	dir := t.TempDir()
	fileNR := filepath.Join(dir, "file-nr")
	mustWrite(t, fileNR, "1000 250 9999\n")

	old := procFileNRPath
	procFileNRPath = fileNR
	defer func() { procFileNRPath = old }()

	got, err := collectOpenFiles()
	if err != nil {
		t.Fatalf("collectOpenFiles() error = %v", err)
	}
	if got.Allocated != 1000 || got.Unused != 250 || got.Used != 750 || got.Max != 9999 {
		t.Fatalf("unexpected open files: %+v", got)
	}
}

func TestCollectNetworkErrors(t *testing.T) {
	dir := t.TempDir()
	netdev := filepath.Join(dir, "dev")
	mustWrite(t, netdev, ""+
		"Inter-|   Receive                                                |  Transmit\n"+
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
		"    lo: 100 1 0 0 0 0 0 0 100 1 0 0 0 0 0 0\n"+
		"  eth0: 200 2 3 4 0 0 0 0 300 3 5 6 0 0 0 0\n")

	old := procNetDevPath
	procNetDevPath = netdev
	defer func() { procNetDevPath = old }()

	got, err := collectNetworkErrors()
	if err != nil {
		t.Fatalf("collectNetworkErrors() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(collectNetworkErrors()) = %d, want 1: %+v", len(got), got)
	}
	if got[0].Interface != "eth0" || got[0].RxErrors != 3 || got[0].RxDropped != 4 || got[0].TxErrors != 5 || got[0].TxDropped != 6 {
		t.Fatalf("unexpected network errors: %+v", got[0])
	}
}

func mustWrite(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
