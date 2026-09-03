package rental

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type MemoryCollector struct{}

type MemoryData struct {
	PhysMemBytes int64 `json:"phys_mem_bytes"`
}

func (m *MemoryCollector) Name() string { return "memory" }

// Collect は `sysctl -n hw.physmem` で物理メモリ容量（バイト）を取得する。
// FreeBSD では詳細（free/cached/used）は /proc なしでは取得不可のため physmem のみ返す。
func (m *MemoryCollector) Collect(cfg collector.Config) (interface{}, error) {
	out, err := runCommand("sysctl", "-n", "hw.physmem")
	if err != nil {
		return nil, err
	}

	raw := strings.TrimSpace(out)
	val, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("unexpected hw.physmem output: %q", out)
	}

	return &MemoryData{PhysMemBytes: val}, nil
}
