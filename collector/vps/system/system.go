package system

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

type Collector struct{}

func (c *Collector) Name() string { return "system" }

type Result struct {
	CPU           CPUResult             `json:"cpu"`
	CPUTimes      CPUTimesResult        `json:"cpu_times,omitempty"`
	Memory        MemoryResult          `json:"memory"`
	Disk          []DiskResult          `json:"disk"`
	Load          LoadResult            `json:"load"`
	Uptime        UptimeResult          `json:"uptime"`
	Swap          SwapResult            `json:"swap"`
	DiskIO        []DiskIOResult        `json:"disk_io"`
	OpenFiles     OpenFilesResult       `json:"open_files"`
	NetworkErrors []NetworkErrorsResult `json:"network_errors"`
	NetworkIO     []NetworkIOResult     `json:"network_io,omitempty"`
	Host          HostResult            `json:"host"`
}

type CPUResult struct {
	UsagePercent float64 `json:"usage_percent"`
}

type CPUTimesResult struct {
	UserPct    float64 `json:"user_pct"`
	NicePct    float64 `json:"nice_pct"`
	SystemPct  float64 `json:"system_pct"`
	IdlePct    float64 `json:"idle_pct"`
	IowaitPct  float64 `json:"iowait_pct"`
	IrqPct     float64 `json:"irq_pct"`
	SoftirqPct float64 `json:"softirq_pct"`
	StealPct   float64 `json:"steal_pct"`
}

type NetworkIOResult struct {
	Interface string `json:"interface"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
}

type MemoryResult struct {
	TotalKB      int64   `json:"total_kb"`
	AvailableKB  int64   `json:"available_kb"`
	UsedKB       int64   `json:"used_kb"`
	UsagePercent float64 `json:"usage_percent"`
}

type DiskResult struct {
	MountPoint   string  `json:"mount_point"`
	TotalKB      int64   `json:"total_kb"`
	UsedKB       int64   `json:"used_kb"`
	AvailableKB  int64   `json:"available_kb"`
	UsagePercent float64 `json:"usage_percent"`
}

type LoadResult struct {
	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
}

type UptimeResult struct {
	UptimeSeconds int64 `json:"uptime_seconds"`
}

type SwapResult struct {
	TotalKB      int64   `json:"total_kb"`
	FreeKB       int64   `json:"free_kb"`
	UsedKB       int64   `json:"used_kb"`
	UsagePercent float64 `json:"usage_percent"`
	SwapInPages  int64   `json:"swap_in_pages"`
	SwapOutPages int64   `json:"swap_out_pages"`
}

type DiskIOResult struct {
	Device       string `json:"device"`
	ReadIOs      int64  `json:"read_ios"`
	ReadSectors  int64  `json:"read_sectors"`
	ReadBytes    int64  `json:"read_bytes"`
	WriteIOs     int64  `json:"write_ios"`
	WriteSectors int64  `json:"write_sectors"`
	WriteBytes   int64  `json:"write_bytes"`
	InFlight     int64  `json:"in_flight"`
	IOMs         int64  `json:"io_ms"`
	WeightedIOMs int64  `json:"weighted_io_ms"`
}

type OpenFilesResult struct {
	Allocated int64 `json:"allocated"`
	Unused    int64 `json:"unused"`
	Max       int64 `json:"max"`
	Used      int64 `json:"used"`
}

type NetworkErrorsResult struct {
	Interface string `json:"interface"`
	RxErrors  int64  `json:"rx_errors"`
	RxDropped int64  `json:"rx_dropped"`
	TxErrors  int64  `json:"tx_errors"`
	TxDropped int64  `json:"tx_dropped"`
}

type HostResult struct {
	Hostname      string `json:"hostname"`
	OSName        string `json:"os_name"`
	OSVersion     string `json:"os_version"`
	OSPrettyName  string `json:"os_pretty_name"`
	KernelVersion string `json:"kernel_version"`
	CPUModel      string `json:"cpu_model"`
	CPUCores      int    `json:"cpu_cores"`
	RAMTotalKB    int64  `json:"ram_total_kb"`
}

var (
	procStatPath      = "/proc/stat"
	procMeminfoPath   = "/proc/meminfo"
	procVmstatPath    = "/proc/vmstat"
	procDiskstatsPath = "/proc/diskstats"
	procFileNRPath    = "/proc/sys/fs/file-nr"
	procNetDevPath    = "/proc/net/dev"
	procLoadavgPath   = "/proc/loadavg"
	procUptimePath    = "/proc/uptime"
	procCPUInfoPath   = "/proc/cpuinfo"
	osReleasePath     = "/etc/os-release"
)

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	res := &Result{}

	cpu, err := collectCPU()
	if err != nil {
		return nil, fmt.Errorf("cpu: %w", err)
	}
	res.CPU = cpu

	mem, err := collectMemory()
	if err != nil {
		return nil, fmt.Errorf("memory: %w", err)
	}
	res.Memory = mem

	disk, err := collectDisk()
	if err != nil {
		return nil, fmt.Errorf("disk: %w", err)
	}
	res.Disk = disk

	load, err := collectLoad()
	if err != nil {
		return nil, fmt.Errorf("load: %w", err)
	}
	res.Load = load

	uptime, err := collectUptime()
	if err != nil {
		return nil, fmt.Errorf("uptime: %w", err)
	}
	res.Uptime = uptime

	if swap, err := collectSwap(); err == nil {
		res.Swap = swap
	}
	if diskIO, err := collectDiskIO(); err == nil {
		res.DiskIO = diskIO
	}
	if openFiles, err := collectOpenFiles(); err == nil {
		res.OpenFiles = openFiles
	}
	if networkErrors, err := collectNetworkErrors(); err == nil {
		res.NetworkErrors = networkErrors
	}
	if networkIO, err := collectNetworkIO(); err == nil {
		res.NetworkIO = networkIO
	}
	if cpuTimes, err := collectCPUTimes(); err == nil {
		res.CPUTimes = cpuTimes
	}
	if host, err := collectHost(); err == nil {
		res.Host = host
	}

	return res, nil
}

// collectCPU は /proc/stat を 200ms 間隔で 2 回サンプリングし、その差分から
// 瞬間 CPU 使用率を計算する。単一スナップショットでは起動以来の平均になり
// 監視に使えないため、コメント通りの 2 スナップショット差分を実装する。
func collectCPU() (CPUResult, error) {
	s1, err := readCPUStat()
	if err != nil {
		return CPUResult{}, err
	}
	// 200ms のサンプリング間隔。素の time.Sleep ではシャットダウン要求を無視して必ず
	// 完走してしまうため、collector.ShutdownCh() を見る select で待ち、SIGTERM 等で
	// 即座に中断できるようにする（C1: blocking-sleep-ignores-shutdown）。
	select {
	case <-time.After(200 * time.Millisecond):
	case <-collector.ShutdownCh():
		return CPUResult{}, nil
	}
	s2, err := readCPUStat()
	if err != nil {
		return CPUResult{}, err
	}

	sum8 := func(s [8]int64) int64 {
		return s[0] + s[1] + s[2] + s[3] + s[4] + s[5] + s[6] + s[7]
	}
	totalDelta := sum8(s2) - sum8(s1)
	idleDelta := (s2[3] + s2[4]) - (s1[3] + s1[4]) // idle + iowait
	if totalDelta <= 0 {
		return CPUResult{}, nil
	}
	usage := float64(totalDelta-idleDelta) / float64(totalDelta) * 100
	return CPUResult{UsagePercent: roundF(usage, 1)}, nil
}

// readCPUStat は /proc/stat の cpu 行を読んで各フィールドの値を返す
// [user, nice, system, idle, iowait, irq, softirq, steal]
func readCPUStat() ([8]int64, error) {
	var fields [8]int64
	f, err := os.Open(procStatPath)
	if err != nil {
		return fields, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		parts := strings.Fields(line)
		// parts[0] = "cpu", parts[1..] = values
		for i := 0; i < 8 && i+1 < len(parts); i++ {
			fields[i], _ = strconv.ParseInt(parts[i+1], 10, 64)
		}
		return fields, nil
	}
	return fields, fmt.Errorf("cpu line not found in %s", procStatPath)
}

// collectMemory は /proc/meminfo からメモリ情報を取得する
func collectMemory() (MemoryResult, error) {
	f, err := os.Open(procMeminfoPath)
	if err != nil {
		return MemoryResult{}, err
	}
	defer f.Close()

	values := make(map[string]int64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		val, _ := strconv.ParseInt(parts[1], 10, 64)
		values[key] = val
	}

	total := values["MemTotal"]
	available := values["MemAvailable"]
	used := total - available
	var usage float64
	if total > 0 {
		usage = float64(used) / float64(total) * 100
	}

	return MemoryResult{
		TotalKB:      total,
		AvailableKB:  available,
		UsedKB:       used,
		UsagePercent: roundF(usage, 1),
	}, nil
}

// collectDisk は df コマンドからディスク使用量を取得する。
// df のハングで系統ループ全体が止まるのを防ぐため RunWithTimeout 経由で実行する
// （C1: exec-no-timeout-blocks-loop）。除外は mount point 前方一致でなく fstype ベースに
// 統一し、rental の disk collector と同一基準にする（C5: disk-filter-inconsistent-dev）。
func collectDisk() ([]DiskResult, error) {
	// --output に fstype を含めることで除外判定を fstype ベースにできる。
	out, err := collector.RunWithTimeout(5*time.Second, "df", "-k", "--output=target,fstype,size,used,avail,pcent")
	if err != nil {
		return nil, err
	}

	var results []DiskResult
	lines := strings.Split(string(out), "\n")
	for _, line := range lines[1:] { // ヘッダーをスキップ
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		mount := fields[0]
		fstype := fields[1]
		// tmpfs・devtmpfs・squashfs・overlay 等の仮想FSを fstype ベースで除外。
		if collector.IsExcludedDiskFSType(fstype) {
			continue
		}

		totalKB, _ := strconv.ParseInt(fields[2], 10, 64)
		usedKB, _ := strconv.ParseInt(fields[3], 10, 64)
		availKB, _ := strconv.ParseInt(fields[4], 10, 64)
		pct := strings.TrimSuffix(fields[5], "%")
		usage, _ := strconv.ParseFloat(pct, 64)

		results = append(results, DiskResult{
			MountPoint:   mount,
			TotalKB:      totalKB,
			UsedKB:       usedKB,
			AvailableKB:  availKB,
			UsagePercent: usage,
		})
	}
	return results, nil
}

// collectLoad は /proc/loadavg からロードアベレージを取得する
func collectLoad() (LoadResult, error) {
	data, err := os.ReadFile(procLoadavgPath)
	if err != nil {
		return LoadResult{}, err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return LoadResult{}, fmt.Errorf("unexpected /proc/loadavg format")
	}
	l1, _ := strconv.ParseFloat(parts[0], 64)
	l5, _ := strconv.ParseFloat(parts[1], 64)
	l15, _ := strconv.ParseFloat(parts[2], 64)
	return LoadResult{Load1: l1, Load5: l5, Load15: l15}, nil
}

// collectUptime は /proc/uptime からアップタイムを取得する
func collectUptime() (UptimeResult, error) {
	data, err := os.ReadFile(procUptimePath)
	if err != nil {
		return UptimeResult{}, err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 1 {
		return UptimeResult{}, fmt.Errorf("unexpected /proc/uptime format")
	}
	f, _ := strconv.ParseFloat(parts[0], 64)
	return UptimeResult{UptimeSeconds: int64(f)}, nil
}

func collectSwap() (SwapResult, error) {
	values, err := readKeyValueKB(procMeminfoPath)
	if err != nil {
		return SwapResult{}, err
	}
	total := values["SwapTotal"]
	free := values["SwapFree"]
	used := total - free
	if used < 0 {
		used = 0
	}

	vmstat, err := readKeyValue(procVmstatPath)
	if err != nil {
		vmstat = map[string]int64{}
	}

	var usage float64
	if total > 0 {
		usage = float64(used) / float64(total) * 100
	}

	return SwapResult{
		TotalKB:      total,
		FreeKB:       free,
		UsedKB:       used,
		UsagePercent: roundF(usage, 1),
		SwapInPages:  vmstat["pswpin"],
		SwapOutPages: vmstat["pswpout"],
	}, nil
}

func collectDiskIO() ([]DiskIOResult, error) {
	f, err := os.Open(procDiskstatsPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []DiskIOResult
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 14 {
			continue
		}
		device := parts[2]
		if isVirtualBlockDevice(device) {
			continue
		}
		readIOs := parseInt64(parts[3])
		readSectors := parseInt64(parts[5])
		writeIOs := parseInt64(parts[7])
		writeSectors := parseInt64(parts[9])
		results = append(results, DiskIOResult{
			Device:       device,
			ReadIOs:      readIOs,
			ReadSectors:  readSectors,
			ReadBytes:    readSectors * 512,
			WriteIOs:     writeIOs,
			WriteSectors: writeSectors,
			WriteBytes:   writeSectors * 512,
			InFlight:     parseInt64(parts[11]),
			IOMs:         parseInt64(parts[12]),
			WeightedIOMs: parseInt64(parts[13]),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func collectOpenFiles() (OpenFilesResult, error) {
	data, err := os.ReadFile(procFileNRPath)
	if err != nil {
		return OpenFilesResult{}, err
	}
	parts := strings.Fields(string(data))
	if len(parts) < 3 {
		return OpenFilesResult{}, fmt.Errorf("unexpected %s format", procFileNRPath)
	}
	allocated := parseInt64(parts[0])
	unused := parseInt64(parts[1])
	used := allocated - unused
	if used < 0 {
		used = 0
	}
	return OpenFilesResult{
		Allocated: allocated,
		Unused:    unused,
		Max:       parseInt64(parts[2]),
		Used:      used,
	}, nil
}

func collectNetworkErrors() ([]NetworkErrorsResult, error) {
	f, err := os.Open(procNetDevPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []NetworkErrorsResult
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue
		}
		line := sc.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if iface == "lo" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 16 {
			continue
		}
		results = append(results, NetworkErrorsResult{
			Interface: iface,
			RxErrors:  parseInt64(fields[2]),
			RxDropped: parseInt64(fields[3]),
			TxErrors:  parseInt64(fields[10]),
			TxDropped: parseInt64(fields[11]),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func collectNetworkIO() ([]NetworkIOResult, error) {
	f, err := os.Open(procNetDevPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []NetworkIOResult
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		if lineNo <= 2 {
			continue
		}
		line := sc.Text()
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		iface := strings.TrimSpace(line[:idx])
		if !isPhysicalNetworkInterface(iface) {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		results = append(results, NetworkIOResult{
			Interface: iface,
			RxBytes:   parseInt64(fields[0]),
			TxBytes:   parseInt64(fields[8]),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

func isPhysicalNetworkInterface(iface string) bool {
	return strings.HasPrefix(iface, "ens") ||
		strings.HasPrefix(iface, "eth") ||
		strings.HasPrefix(iface, "enp") ||
		strings.HasPrefix(iface, "eno")
}

// collectCPUTimes は /proc/stat から CPU 時間の内訳（%）を取得する
func collectCPUTimes() (CPUTimesResult, error) {
	s, err := readCPUStat()
	if err != nil {
		return CPUTimesResult{}, err
	}
	// s = [user, nice, system, idle, iowait, irq, softirq, steal]
	total := s[0] + s[1] + s[2] + s[3] + s[4] + s[5] + s[6] + s[7]
	if total == 0 {
		return CPUTimesResult{}, nil
	}
	pct := func(v int64) float64 {
		return roundF(float64(v)/float64(total)*100, 1)
	}
	return CPUTimesResult{
		UserPct:    pct(s[0]),
		NicePct:    pct(s[1]),
		SystemPct:  pct(s[2]),
		IdlePct:    pct(s[3]),
		IowaitPct:  pct(s[4]),
		IrqPct:     pct(s[5]),
		SoftirqPct: pct(s[6]),
		StealPct:   pct(s[7]),
	}, nil
}

func collectHost() (HostResult, error) {
	mem, err := readKeyValueKB(procMeminfoPath)
	if err != nil {
		return HostResult{}, err
	}
	cpuModel, cpuCores, err := readCPUInfo()
	if err != nil {
		return HostResult{}, err
	}
	osInfo, err := readOSRelease()
	if err != nil {
		osInfo = map[string]string{}
	}
	hostname, _ := os.Hostname()
	// uname のハング防止に RunWithTimeout 経由で実行する（C1: exec-no-timeout-blocks-loop）。
	kernelVersion, _ := collector.RunWithTimeout(5*time.Second, "uname", "-r")

	return HostResult{
		Hostname:      hostname,
		OSName:        osInfo["NAME"],
		OSVersion:     osInfo["VERSION_ID"],
		OSPrettyName:  osInfo["PRETTY_NAME"],
		KernelVersion: strings.TrimSpace(string(kernelVersion)),
		CPUModel:      cpuModel,
		CPUCores:      cpuCores,
		RAMTotalKB:    mem["MemTotal"],
	}, nil
}

func readKeyValueKB(path string) (map[string]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := make(map[string]int64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		key := strings.TrimSuffix(parts[0], ":")
		values[key] = parseInt64(parts[1])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func readKeyValue(path string) (map[string]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := make(map[string]int64)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 2 {
			continue
		}
		values[parts[0]] = parseInt64(parts[1])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func readCPUInfo() (string, int, error) {
	f, err := os.Open(procCPUInfoPath)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	model := ""
	cores := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "processor") {
			cores++
			continue
		}
		if model == "" && strings.HasPrefix(line, "model name") {
			if idx := strings.Index(line, ":"); idx >= 0 {
				model = strings.TrimSpace(line[idx+1:])
			}
		}
	}
	if err := sc.Err(); err != nil {
		return "", 0, err
	}
	return model, cores, nil
}

func readOSRelease() (map[string]string, error) {
	f, err := os.Open(osReleasePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	values := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		values[key] = strings.Trim(val, `"`)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return values, nil
}

func parseInt64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}

func isVirtualBlockDevice(device string) bool {
	return strings.HasPrefix(device, "loop") ||
		strings.HasPrefix(device, "ram") ||
		strings.HasPrefix(device, "zram")
}

func roundF(f float64, decimals int) float64 {
	pow := 1.0
	for i := 0; i < decimals; i++ {
		pow *= 10
	}
	return float64(int64(f*pow+0.5)) / pow
}
