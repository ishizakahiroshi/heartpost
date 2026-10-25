// Package audit_log_tail は monitor が出力する audit_log.jsonl.YYYY-MM-DD を
// 定期的に差分 tail し、collector_id="audit_log" として Monitor へ Push する collector。
//
//   - 系統: "audit"（main.go intervals map / 既定 60 秒、agent.toml の [intervals].audit_log_sec で上書き）
//   - log dir: cfg.Paths.AuditLog（ディレクトリ指定。固定ファイルではない）。
//     Nextcloud の audit.log は nextcloud collector が paths.nc_audit_log で別に読む（共有しない）
//   - state: <DataDir>/json/audit_log_tail_state.json（再起動跨ぎで重複/欠損ゼロ）
//   - 日付切り替え: 旧ファイルの残りを読み切ってから新ファイルを offset 0 から読む（A2）
//
// 戻り値の JSON 構造（Monitor 側 insertAuditLogIfPresent と整合）:
//
//	{
//	  "new_events": N,
//	  "events":     [<audit.Event>, ...],
//	  "current_file": "audit_log.jsonl.YYYY-MM-DD",
//	  "offset":      <int64>
//	}
package audit_log_tail

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ishizakahiroshi/heartpost/audit"
	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

const (
	stateFileName = "audit_log_tail_state.json"
	logFilePrefix = "audit_log.jsonl."
	collectorName = "audit_log"
	// maxEventsPerCollect は 1 Collect で送る events の上限。Monitor 長期不達後の
	// 巨大バックログを一括メモリ展開・単一 POST するのを防ぎ、次回 interval で残りを
	// 順次消化する（C5: audit-log-tail-unbounded-payload）。上限到達時は改行境界で
	// 打ち切り、consumed をそこまでにして offset を進める。
	maxEventsPerCollect = 5000
)

type Collector struct{}

func (c *Collector) Name() string     { return collectorName }
func (c *Collector) Interval() string { return "audit" }

// CollectResult はレポート payload。Monitor 側は events だけを SQLite に INSERT する。
type CollectResult struct {
	NewEvents   int           `json:"new_events"`
	Events      []audit.Event `json:"events"`
	CurrentFile string        `json:"current_file,omitempty"`
	Offset      int64         `json:"offset"`
}

type tailState struct {
	CurrentFile string `json:"current_file"`
	Offset      int64  `json:"offset"`
}

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	if strings.TrimSpace(cfg.Paths.DataDir) == "" {
		return nil, fmt.Errorf("paths.data_dir is required for audit_log_tail collector")
	}
	logDir := strings.TrimSpace(cfg.Paths.AuditLog)
	if logDir == "" {
		return nil, fmt.Errorf("paths.audit_log is required for audit_log_tail collector")
	}
	// audit_log がファイル指定（旧仕様）になっている場合はディレクトリへ正規化。
	if info, err := os.Stat(logDir); err == nil && !info.IsDir() {
		logDir = filepath.Dir(logDir)
	}

	statePath := filepath.Join(cfg.Paths.DataDir, "json", stateFileName)
	state, _ := loadState(statePath)

	files, err := listLogFiles(logDir)
	if err != nil {
		return nil, fmt.Errorf("list log files: %w", err)
	}
	if len(files) == 0 {
		// Monitor がまだ書き始めていないだけのことがある。warn 相当だが non-fatal。
		return &CollectResult{NewEvents: 0, Events: []audit.Event{}}, nil
	}
	latest := files[len(files)-1]

	var events []audit.Event
	var newOffset int64
	currentFile := filepath.Base(latest)

	if state != nil && state.CurrentFile != "" && state.CurrentFile != filepath.Base(latest) {
		// 日付切り替え: 旧ファイルの残りを読み切ってから新ファイルを 0 から読む。
		// maxEvents は旧→新を通算した残り budget で制御する。旧ファイルだけで上限に
		// 達した場合は currentFile を旧ファイルのままにして offset を進め、新ファイルは
		// 次回以降に読む（欠損防止）。
		oldPath := filepath.Join(logDir, state.CurrentFile)
		if _, err := os.Stat(oldPath); err == nil {
			oldEvents, oldOff, err := readFromOffset(oldPath, state.Offset, maxEventsPerCollect)
			if err != nil {
				return nil, fmt.Errorf("read old log: %w", err)
			}
			events = append(events, oldEvents...)
			if len(oldEvents) >= maxEventsPerCollect {
				// 旧ファイルがまだ残っている可能性があるため、state は旧ファイル基準で前進。
				currentFile = state.CurrentFile
				newOffset = oldOff
				if err := saveState(statePath, &tailState{CurrentFile: currentFile, Offset: newOffset}); err != nil {
					return nil, fmt.Errorf("save state: %w", err)
				}
				return &CollectResult{
					NewEvents:   len(events),
					Events:      events,
					CurrentFile: currentFile,
					Offset:      newOffset,
				}, nil
			}
		}
		remain := maxEventsPerCollect - len(events)
		newEvents, off, err := readFromOffset(latest, 0, remain)
		if err != nil {
			return nil, fmt.Errorf("read latest log: %w", err)
		}
		events = append(events, newEvents...)
		newOffset = off
	} else {
		// 同じファイルを継続: state.offset から末尾まで読む。
		var startOffset int64
		if state != nil && state.CurrentFile == filepath.Base(latest) {
			startOffset = state.Offset
		}
		// ファイルがトランケートされて size < offset の場合は 0 から読み直す。
		if info, err := os.Stat(latest); err == nil && info.Size() < startOffset {
			startOffset = 0
		}
		newEvents, off, err := readFromOffset(latest, startOffset, maxEventsPerCollect)
		if err != nil {
			return nil, fmt.Errorf("read latest log: %w", err)
		}
		events = append(events, newEvents...)
		newOffset = off
	}

	// 成功時のみ state を保存する。失敗時は state 据え置きで次回再試行（plan A2 / C3-2 5）。
	if err := saveState(statePath, &tailState{
		CurrentFile: currentFile,
		Offset:      newOffset,
	}); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}

	return &CollectResult{
		NewEvents:   len(events),
		Events:      events,
		CurrentFile: currentFile,
		Offset:      newOffset,
	}, nil
}

func listLogFiles(dir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(dir, logFilePrefix+"*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	return matches, nil
}

// readFromOffset は path を offset から読み、最大 maxEvents 件の audit.Event を返す。
// consumed（次回 offset）は改行境界で完全に読み取った行のバイト数ぶんだけ進める。
// maxEvents に達した時点で打ち切り、その行までの consumed を返すので、残りは次回 interval で
// 順次消化される（C5: audit-log-tail-unbounded-payload）。maxEvents<=0 は無制限。
func readFromOffset(path string, offset int64, maxEvents int) ([]audit.Event, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, offset, nil
		}
		return nil, offset, err
	}
	defer f.Close()

	if offset > 0 {
		if _, err := f.Seek(offset, 0); err != nil {
			return nil, offset, err
		}
	}

	// bufio.Scanner は先読みするため f.Seek(0,1) では実際に処理した行末より先の
	// オフセットになり、再起動跨ぎで重複/欠損が起きる。bufio.Reader で 1 行ずつ読み、
	// 改行で終端した「完全な行」のバイト数だけ offset を進める。末尾の不完全行
	// （まだ改行が来ていない書き込み途中の行）は consumed に含めず、次回完全に読み直す。
	reader := bufio.NewReaderSize(f, 1024*1024)
	consumed := offset
	var events []audit.Event
	for {
		line, rerr := reader.ReadString('\n')
		if rerr == nil {
			consumed += int64(len(line)) // 改行を含む完全な行
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				var ev audit.Event
				if json.Unmarshal([]byte(trimmed), &ev) == nil {
					events = append(events, ev)
				}
			}
			// 上限到達: ここまでの consumed（直近の改行境界）で打ち切り、残りは次回。
			if maxEvents > 0 && len(events) >= maxEvents {
				return events, consumed, nil
			}
			continue
		}
		if errors.Is(rerr, io.EOF) {
			// 末尾の不完全行は offset を進めない（次回完全な行として読み直す）。
			break
		}
		return events, offset, rerr
	}
	return events, consumed, nil
}

func loadState(path string) (*tailState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var st tailState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

func saveState(path string, st *tailState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
