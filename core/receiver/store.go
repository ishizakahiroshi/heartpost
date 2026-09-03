package receiver

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// 保存レイアウト（データディレクトリ配下）
//
//	reports/report_<agent_id>_<YYYYMMDD>.jsonl  受信したレポートの追記ログ
//	state.json                                  agent ごとの最新状態と通知済みフラグ
//
// 外部 DB を要求しないのは、この道具の利用者が「root 権限もパッケージ導入も要らない」
// 前提で数台〜十数台を見たいだけだから。SQLite すら使わない。
const (
	reportsDirName = "reports"
	stateFileName  = "state.json"
	// reportFileDateFormat は JSONL のファイル名に入る日付。保持期間の判定にも使う。
	reportFileDateFormat = "20060102"
)

// NotifyState は「その agent についてどちらの遷移を通知済みか」を表す。
// 永続化されるので、monitor を再起動しても通知済みの欠報が再通知されない。
type NotifyState string

const (
	// NotifyNone はまだ一度も遷移を通知していない状態。
	NotifyNone NotifyState = ""
	// NotifyDown は欠報を通知済み。復帰するまで再通知しない。
	NotifyDown NotifyState = "down"
	// NotifyUp は復帰を通知済み。次に欠報するまで再通知しない。
	NotifyUp NotifyState = "up"
)

// agentIDPattern は agent_id に許す文字種。
//
// テナント形式のような意味づけは強制しない。ここで絞るのは「ファイル名として安全か」
// の 1 点だけ。`.` を許さないので `..` も `./` も通らない。
var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,63}$`)

// ValidAgentID は agent_id がパスとして安全な形かを返す。
func ValidAgentID(id string) bool {
	return agentIDPattern.MatchString(id)
}

// Record は JSONL へ 1 行として書かれる受信レコード。
type Record struct {
	ReceivedAt string                     `json:"received_at"`
	AgentID    string                     `json:"agent_id"`
	AgentLabel string                     `json:"agent_label"`
	AgentType  string                     `json:"agent_type"`
	ReportedAt string                     `json:"reported_at"`
	Collectors map[string]json.RawMessage `json:"collectors"`
}

// AgentState は一覧画面と死活判定が使う agent ごとの最新状態。
//
// 画面のたびに JSONL を読み直さずに済むよう、表示に要る値だけをここへ写す。
type AgentState struct {
	AgentID    string `json:"agent_id"`
	AgentLabel string `json:"agent_label"`
	AgentType  string `json:"agent_type"`

	LastSeen   time.Time `json:"last_seen"`
	ReportedAt string    `json:"reported_at"`

	Hostname string `json:"hostname"`
	// RootDiskPercent は `/` の使用率（"40%" のような df の生表記）。取れなければ空。
	RootDiskPercent string `json:"root_disk_percent"`

	Load1  float64 `json:"load1"`
	Load5  float64 `json:"load5"`
	Load15 float64 `json:"load15"`
	// HasLoad は load を 1 度でも受け取ったか。0.00 と「未取得」を区別する。
	HasLoad bool `json:"has_load"`

	// Down は直近の判定で欠報だったか。表示用。
	Down bool `json:"down"`
	// DownSince は欠報と判定した時刻。生存中はゼロ値。
	DownSince time.Time `json:"down_since,omitempty"`
	// Notified はどちらの遷移まで通知したか。再通知を防ぐために永続化する。
	Notified NotifyState `json:"notified"`
}

// Label は画面と通知に出す表示名を返す。label → hostname → agent_id の順に落とす。
func (s AgentState) Label() string {
	if v := strings.TrimSpace(s.AgentLabel); v != "" {
		return v
	}
	if v := strings.TrimSpace(s.Hostname); v != "" {
		return v
	}
	return s.AgentID
}

// Store は受信レコードの保存と agent ごとの状態を持つ。
// 単一プロセス内での並行アクセスを前提に mutex で守る。
type Store struct {
	mu            sync.Mutex
	dir           string
	retentionDays int
	states        map[string]*AgentState
}

// NewStore は dir 配下に保存する Store を作る。既存の state.json があれば読み込む。
// retentionDays が 0 以下なら JSONL の自動削除を行わない。
func NewStore(dir string, retentionDays int) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("receiver: data dir is empty")
	}
	s := &Store{
		dir:           filepath.Clean(dir),
		retentionDays: retentionDays,
		states:        map[string]*AgentState{},
	}
	if err := os.MkdirAll(filepath.Join(s.dir, reportsDirName), 0o700); err != nil {
		return nil, fmt.Errorf("receiver: mkdir: %w", err)
	}
	if err := s.loadState(); err != nil {
		return nil, err
	}
	return s, nil
}

// Dir は保存先のルートを返す。
func (s *Store) Dir() string { return s.dir }

func (s *Store) reportsDir() string { return filepath.Join(s.dir, reportsDirName) }

func (s *Store) statePath() string { return filepath.Join(s.dir, stateFileName) }

// safeJoin は base 配下に収まるパスだけを返す。
//
// agent_id は ValidAgentID で既に絞ってあるが、パス連結の直前でもう一度
// Clean + base 接頭辞チェックをする。入口の検証が 1 つ抜けただけで
// base の外へ書けてしまう作りにしない。
func safeJoin(base, name string) (string, error) {
	baseClean := filepath.Clean(base)
	joined := filepath.Clean(filepath.Join(baseClean, name))
	if joined != baseClean && !strings.HasPrefix(joined, baseClean+string(filepath.Separator)) {
		return "", fmt.Errorf("receiver: path escapes base directory: %q", name)
	}
	return joined, nil
}

// reportPath は agent と日付から JSONL のパスを返す。
func (s *Store) reportPath(agentID string, day time.Time) (string, error) {
	if !ValidAgentID(agentID) {
		return "", fmt.Errorf("receiver: invalid agent_id: %q", agentID)
	}
	name := fmt.Sprintf("report_%s_%s.jsonl", agentID, day.UTC().Format(reportFileDateFormat))
	return safeJoin(s.reportsDir(), name)
}

// Append は 1 件のレポートを JSONL へ追記し、agent の状態を更新する。
// 追記に成功したら保持期間を過ぎた JSONL を掃除する。
func (s *Store) Append(rec Record, now time.Time) error {
	if !ValidAgentID(rec.AgentID) {
		return fmt.Errorf("receiver: invalid agent_id: %q", rec.AgentID)
	}
	path, err := s.reportPath(rec.AgentID, now)
	if err != nil {
		return err
	}

	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("receiver: marshal record: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	// 0600: レポートには収集したホストの情報が入るので、monitor プロセス以外へ見せない。
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("receiver: open report file: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("receiver: write report: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("receiver: close report file: %w", err)
	}

	st := s.states[rec.AgentID]
	if st == nil {
		st = &AgentState{AgentID: rec.AgentID}
		s.states[rec.AgentID] = st
	}
	st.AgentLabel = rec.AgentLabel
	st.AgentType = rec.AgentType
	st.LastSeen = now
	st.ReportedAt = rec.ReportedAt
	applySummary(st, rec.Collectors)

	if err := s.saveStateLocked(); err != nil {
		return err
	}
	s.cleanupLocked(now)
	return nil
}

// States は agent の状態のスナップショットを返す（呼び出し側が書き換えても影響しない）。
func (s *Store) States() []AgentState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]AgentState, 0, len(s.states))
	for _, st := range s.states {
		out = append(out, *st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AgentID < out[j].AgentID })
	return out
}

// SetLiveness は死活判定の結果を書き戻して永続化する。
func (s *Store) SetLiveness(agentID string, down bool, downSince time.Time, notified NotifyState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[agentID]
	if st == nil {
		return fmt.Errorf("receiver: unknown agent_id: %q", agentID)
	}
	st.Down = down
	st.DownSince = downSince
	st.Notified = notified
	return s.saveStateLocked()
}

// EnsureAgent は「設定に載っているがまだ 1 通も受け取っていない agent」を
// 一覧へ出すために空の状態を作る。既にあれば何もしない。
func (s *Store) EnsureAgent(agentID, label string) error {
	if !ValidAgentID(agentID) {
		return fmt.Errorf("receiver: invalid agent_id: %q", agentID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.states[agentID]; ok {
		return nil
	}
	s.states[agentID] = &AgentState{AgentID: agentID, AgentLabel: label}
	return s.saveStateLocked()
}

func (s *Store) loadState() error {
	b, err := os.ReadFile(s.statePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("receiver: read state: %w", err)
	}
	var loaded map[string]*AgentState
	if err := json.Unmarshal(b, &loaded); err != nil {
		return fmt.Errorf("receiver: parse state: %w", err)
	}
	for id, st := range loaded {
		if st == nil || !ValidAgentID(id) {
			continue
		}
		st.AgentID = id
		s.states[id] = st
	}
	return nil
}

// saveStateLocked は state.json を temp + rename で置き換える。
// 途中で落ちても壊れた state.json を残さないため。呼び出し側が mu を持っていること。
func (s *Store) saveStateLocked() error {
	b, err := json.MarshalIndent(s.states, "", "  ")
	if err != nil {
		return fmt.Errorf("receiver: marshal state: %w", err)
	}
	tmp := s.statePath() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return fmt.Errorf("receiver: write state: %w", err)
	}
	if err := os.Rename(tmp, s.statePath()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("receiver: replace state: %w", err)
	}
	return nil
}

// Cleanup は保持期間を過ぎた JSONL を削除する。
func (s *Store) Cleanup(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanupLocked(now)
}

func (s *Store) cleanupLocked(now time.Time) {
	if s.retentionDays <= 0 {
		return
	}
	cutoff := now.UTC().AddDate(0, 0, -s.retentionDays)
	entries, err := os.ReadDir(s.reportsDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		day, ok := reportFileDay(e.Name())
		if !ok {
			continue
		}
		if day.Before(cutoff) {
			p, err := safeJoin(s.reportsDir(), e.Name())
			if err != nil {
				continue
			}
			_ = os.Remove(p)
		}
	}
}

// reportFileDay は "report_<agent>_<YYYYMMDD>.jsonl" から日付を取り出す。
func reportFileDay(name string) (time.Time, bool) {
	if !strings.HasPrefix(name, "report_") || !strings.HasSuffix(name, ".jsonl") {
		return time.Time{}, false
	}
	trimmed := strings.TrimSuffix(name, ".jsonl")
	idx := strings.LastIndex(trimmed, "_")
	if idx < 0 {
		return time.Time{}, false
	}
	day, err := time.Parse(reportFileDateFormat, trimmed[idx+1:])
	if err != nil {
		return time.Time{}, false
	}
	return day, true
}

// applySummary は collectors から画面に出す値だけを取り出す。
//
// collector が増えても受信側を直さなくて済むよう、取れなかったものは黙って空のままにする。
// レポート本体は JSONL に丸ごと残るので、ここで拾わなかった値が失われるわけではない。
func applySummary(st *AgentState, collectors map[string]json.RawMessage) {
	if collectors == nil {
		return
	}
	if raw, ok := collectors["host"]; ok {
		var host struct {
			Hostname string `json:"hostname"`
		}
		if err := json.Unmarshal(raw, &host); err == nil && host.Hostname != "" {
			st.Hostname = host.Hostname
		}
	}
	if raw, ok := collectors["disk"]; ok {
		var disks []struct {
			UsePercent string `json:"use_percent"`
			Mounted    string `json:"mounted"`
		}
		if err := json.Unmarshal(raw, &disks); err == nil {
			for _, d := range disks {
				if d.Mounted == "/" {
					st.RootDiskPercent = d.UsePercent
					break
				}
			}
		}
	}
	if raw, ok := collectors["loadavg"]; ok {
		var la struct {
			Load1  *float64 `json:"load1"`
			Load5  *float64 `json:"load5"`
			Load15 *float64 `json:"load15"`
		}
		if err := json.Unmarshal(raw, &la); err == nil && la.Load1 != nil {
			st.Load1 = *la.Load1
			if la.Load5 != nil {
				st.Load5 = *la.Load5
			}
			if la.Load15 != nil {
				st.Load15 = *la.Load15
			}
			st.HasLoad = true
		}
	}
}
