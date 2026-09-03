package collector

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

// JSONLLogCollector[T] は「ログを tail → 行を T にパース → 既存 jsonl との重複を除外 →
// 新規だけ jsonl へ追記 → サイズ超過でローテート」という、ログを読む collector が
// どれも必要とするパターンを 1 箇所に集約するテンプレート。
// 各 collector は ParseLine（1 行 → (T, ok)）と SeenKey（T → 重複判定キー）だけ渡し、
// regex とフィールドの対応づけに専念できる。
type JSONLLogCollector[T any] struct {
	// JSONLPath は追記先 jsonl（例: <DataDir>/logs/ssh.jsonl）。
	JSONLPath string
	// MaxBytes はローテート閾値（超過で path+".1" へリネーム）。0 なら 10MB。
	MaxBytes int64
	// ParseLine は元ログの 1 行を T に変換する。対象外行は ok=false を返す。
	ParseLine func(line string) (T, bool)
	// SeenKey は重複判定用キーを返す。
	SeenKey func(T) string
}

// LoadSeen は JSONLPath を読んで既存レコードの SeenKey 集合を返す。
func (c *JSONLLogCollector[T]) LoadSeen() map[string]struct{} {
	seen := make(map[string]struct{})
	f, err := os.Open(c.JSONLPath)
	if err != nil {
		return seen
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, ScannerBufferBytes), ScannerBufferBytes)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			seen[c.SeenKey(v)] = struct{}{}
		}
	}
	return seen
}

// ParseTail は logPath の末尾 maxLines 行を読み、ParseLine でパースし、seen と重複しない
// 新規レコードだけを返す。seen には返したレコードのキーも追加する（同一バッチ内重複も除外）。
func (c *JSONLLogCollector[T]) ParseTail(logPath string, maxLines int, seen map[string]struct{}) ([]T, error) {
	f, err := os.Open(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lines, err := TailLinesReader(f, maxLines)
	if err != nil {
		return nil, err
	}

	var out []T
	for _, line := range lines {
		v, ok := c.ParseLine(line)
		if !ok {
			continue
		}
		key := c.SeenKey(v)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, v)
	}
	return out, nil
}

// AppendJSONL は records を JSONLPath へ 1 行 1 レコードで追記する。
func (c *JSONLLogCollector[T]) AppendJSONL(records []T) error {
	if len(records) == 0 {
		return nil
	}
	f, err := os.OpenFile(c.JSONLPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, r := range records {
		b, err := json.Marshal(r)
		if err != nil {
			continue
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// Rotate は JSONLPath が MaxBytes を超えていればローテートする。
func (c *JSONLLogCollector[T]) Rotate() error {
	max := c.MaxBytes
	if max <= 0 {
		max = 10 * 1024 * 1024
	}
	return RotateIfNeeded(c.JSONLPath, max)
}

// Run は LoadSeen → ParseTail → AppendJSONL → Rotate を順に実行し、新規レコードを返す。
// jsonl ログ collector の共通フローをこの 1 メソッドに集約する。
func (c *JSONLLogCollector[T]) Run(logPath string, maxLines int) ([]T, error) {
	seen := c.LoadSeen()
	records, err := c.ParseTail(logPath, maxLines, seen)
	if err != nil {
		return nil, err
	}
	if len(records) > 0 {
		if err := c.AppendJSONL(records); err != nil {
			return nil, err
		}
		if err := c.Rotate(); err != nil {
			return nil, err
		}
	}
	return records, nil
}

// ScannerBufferBytes は jsonl ログ collector が bufio.Scanner に与える
// 最大トークンサイズの共通定数。collector ごとに違う値を持つと
// バラついていたものを 1 箇所に統一する（C3: jsonl-collector-pattern-duplication）。

const ScannerBufferBytes = 1024 * 1024

// shutdownCh は agent のグレースフルシャットダウンを collector 内部の待機処理へ伝える
// 共有チャネル。collector の Collect は ctx を受け取らないため、素の time.Sleep を
// select で中断可能にする用途で使う（C1: blocking-sleep-ignores-shutdown）。
// main が起動時に SetShutdownCh(ctx.Done()) を呼ぶ。未設定時は閉じないチャネルを返す。

func RotateIfNeeded(path string, maxBytes int64) error {
	info, err := os.Stat(path)
	if err != nil || info.Size() <= maxBytes {
		return nil
	}
	return os.Rename(path, path+".1")
}

// TailLinesReader は io.Reader から末尾 n 行をリングバッファで返す。
// 全 collector で共用する。*os.File は io.Reader を満たすのでそのまま渡せる。
func TailLinesReader(r io.Reader, n int) ([]string, error) {
	// n<=0 だと ring[i%n] でゼロ除算 panic になるためガードする。
	if n <= 0 {
		return nil, nil
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, ScannerBufferBytes), ScannerBufferBytes)
	ring := make([]string, n)
	i, count := 0, 0
	for sc.Scan() {
		ring[i%n] = sc.Text()
		i++
		count++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if count <= n {
		return ring[:count], nil
	}
	result := make([]string, n)
	start := i % n
	for j := 0; j < n; j++ {
		result[j] = ring[(start+j)%n]
	}
	return result, nil
}
