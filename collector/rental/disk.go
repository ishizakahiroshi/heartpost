package rental

import (
	"strings"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type DiskCollector struct{}

type DiskEntry struct {
	Filesystem string `json:"filesystem"`
	Size       string `json:"size"`
	Used       string `json:"used"`
	Avail      string `json:"avail"`
	UsePercent string `json:"use_percent"`
	Mounted    string `json:"mounted"`
}

func (d *DiskCollector) Name() string { return "disk" }

// Collect は `df -hT` を実行して各マウントポイントの使用状況を返す。
// -T で fstype 列を含め、tmpfs/devfs/procfs 等の仮想 FS を VPS の system collector と
// 同一基準で除外する（C5: disk-filter-inconsistent-dev）。FreeBSD の df は -T 列を
// 「Filesystem Type Size Used Avail Capacity Mounted on」の順で出力する。
func (d *DiskCollector) Collect(cfg collector.Config) (interface{}, error) {
	out, err := runCommand("df", "-hT")
	if err != nil {
		return nil, err
	}

	var entries []DiskEntry
	lines := strings.Split(strings.TrimSpace(out), "\n")
	// 先頭ヘッダ行をスキップ
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		// -T 付きは 7 列（Filesystem Type Size Used Avail Capacity Mounted）。
		if len(fields) < 7 {
			continue
		}
		fstype := fields[1]
		if collector.IsExcludedDiskFSType(fstype) {
			continue
		}
		entries = append(entries, DiskEntry{
			Filesystem: fields[0],
			Size:       fields[2],
			Used:       fields[3],
			Avail:      fields[4],
			UsePercent: fields[5],
			Mounted:    fields[6],
		})
	}

	return entries, nil
}
