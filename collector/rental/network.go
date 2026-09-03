package rental

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/ishizakahiroshi/heartpost/collector"
)

type NetworkCollector struct{}

type NetworkData struct {
	TxBytes int64 `json:"tx_bytes"` // 累積送信バイト数
	RxBytes int64 `json:"rx_bytes"` // 累積受信バイト数
}

func (n *NetworkCollector) Name() string { return "network" }

// Collect は sysctl dev.vtnet.0.txq0.obytes / rxq0.ibytes で累積バイト数を取得する。
// 差分計算は Monitor 側で行う（前回値との比較）。
// vtnet0 が存在しない場合は null を返す（取得不可として扱う）。
func (n *NetworkCollector) Collect(cfg collector.Config) (interface{}, error) {
	tx, err := readSysctlInt64("dev.vtnet.0.txq0.obytes")
	if err != nil {
		// vtnet0 が存在しない環境では null を返す
		return nil, nil
	}

	rx, err := readSysctlInt64("dev.vtnet.0.rxq0.ibytes")
	if err != nil {
		return nil, nil
	}

	return &NetworkData{TxBytes: tx, RxBytes: rx}, nil
}

// readSysctlInt64 は `sysctl <key>` を実行して整数値を返す。
// 出力形式: "dev.vtnet.0.txq0.obytes: 46174585053186"
func readSysctlInt64(key string) (int64, error) {
	out, err := runCommand("sysctl", key)
	if err != nil {
		return 0, err
	}

	line := strings.TrimSpace(out)
	idx := strings.LastIndex(line, ":")
	if idx < 0 {
		return 0, fmt.Errorf("unexpected sysctl output for %s: %q", key, out)
	}

	valStr := strings.TrimSpace(line[idx+1:])
	v, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse sysctl %s value %q: %w", key, valStr, err)
	}

	return v, nil
}
