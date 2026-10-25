// nextcloud パッケージは Nextcloud の nextcloud.log / audit.log の増えた分を読み、
// logs/nextcloud.jsonl に追記して Monitor へ送る。
// Nextcloud モジュール有効時（collectors.jobs.nextcloud = true）のみ動作する。
//
// 読むファイル: paths.nextcloud_log（cfg.Paths.NextcloudLog）と paths.nc_audit_log
// （cfg.Paths.NcAuditLog）。paths.audit_log（cfg.Paths.AuditLog）は audit_log_tail 用の
// monitor の監査ログのフォルダなので、ここでは読まない。
//
// 読み方（読んだ位置方式。audit_log_tail と同じ考え方）:
//   - 元のファイルごとに、読んだバイト位置・inode・先頭 512 バイトの指紋（SHA-256）を
//     <DataDir>/json/nextcloud_tail_state.json に持ち、増えた分だけ読む。位置は改行まで読めた行の分
//     だけ進める（書き込み途中の行は次回）。
//   - 状態が無い初回は、末尾まで位置を進めるだけで過去分は送らない（配った直後の一斉送信と
//     通知の一斉発報を防ぐ）。位置が欠けている・負の項目も、そのファイルだけ初回扱いにする。
//   - 切り替え（2026-10-16 実機の /etc/logrotate.d/nextcloud-log: nextcloud.log は copytruncate、
//     audit.log は create（.1 へ名前を変えて新しいファイルを作る）。どちらも delaycompress で直近の
//     .1 は圧縮されない）: 今のサイズ < 記録した位置、inode の変化、先頭の指紋の違いのどれかで
//     切り替えとみなす。先頭の指紋は、copytruncate の後で新しいファイルが記録した位置より大きく
//     育った場合や、inode が使い回された場合にも見分けるため。.1 の先頭が記録した指紋と同じで
//     大きさが記録した位置以上なら、.1 の続きを先に読み、続けて元のファイルを 0 から読む。
//     .1 が無い・合わないときは 0 から読む。
//   - 1 回に返すイベントは、CollectResult を JSON にした大きさで maxResultJSONBytes まで、件数で
//     maxResultEvents まで（2 つのファイルの合計）にする。超える分は位置を止めて次回に回す
//     （Monitor の /api/agent/report は本文を 1MB で打ち切り、1 collector あたり最後の 1000 件だけ残す）。
//     2 つのファイルを読む順番は回ごとに入れ替える。
//   - nextcloud.jsonl へ追記する前に、追記前の大きさを状態に印として保存する。位置の保存に
//     失敗したら、次の回にその大きさまで切り詰めてから読み直す（同じイベントを重ねて足さない）。
//
// 以前は末尾 nc_log_lines 行を読み、手元の nextcloud.jsonl との重複を除いていた。nextcloud.jsonl が
// 10MB で .1 に名前を変えた次の回に重複の照合が空になり、末尾の全行を送り直していた
// （2026-10-16、タイムリーの nextcloud.jsonl と .1 に同じイベントが 14,914 件）。
//
// nextcloud.log の各行フォーマット（JSONL）:
//
//	{"reqId":"...","level":1,"time":"...","remoteAddr":"1.2.3.4","user":"alice","message":"Login successful: \"alice\"","url":"/nextcloud/index.php","method":"GET","userAgent":"..."}
//
// audit.log の各行フォーマット（JSONL）:
//
//	{"reqId":"...","level":1,"time":"...","remoteAddr":"1.2.3.4","user":"alice","message":"Login failed: \"alice\"","url":"...","method":"POST","userAgent":"..."}
package nextcloud

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	sharedcollector "github.com/ishizakahiroshi/heartpost/collector"
	collector "github.com/ishizakahiroshi/heartpost/collector/optional"
)

const stateFileName = "nextcloud_tail_state.json"

// maxResultJSONBytes は 1 回の CollectResult を JSON にしたときの上限。
// Monitor の /api/agent/report は本文を 1MB で打ち切る（core/monitor/agent_report.go の
// MaxBytesReader）。同じ POST に載る log の組（nginx / nc_extract）と封筒の分を残すため半分にする。
// テストで差し替えられるよう var にしている。
var maxResultJSONBytes = 512 * 1024

// maxResultEvents は 1 回の CollectResult のイベント数の上限（2 つのファイルの合計）。
// Monitor は 1 回の報告で 1 collector あたり最後の 1000 件しか残さない
// （core/monitor/agent_events.go の agentEventMaxPerCollector）。超えた分は前から捨てられる。
var maxResultEvents = 1000

// saveStateFn は状態ファイルの保存（テストで失敗を差し込むため var）。
var saveStateFn = saveState

// fileInode は path の inode を返す（取れない環境では 0。0 のときは inode を比べない）。
// テストで切り替え（rename）を再現するため var にしている。
var fileInode = func(path string, info os.FileInfo) uint64 { return statInode(info) }

type Collector struct{}

func (c *Collector) Name() string     { return "nextcloud" }
func (c *Collector) Interval() string { return "log" }

// NCEvent は nextcloud.jsonl の1レコード（planの JSONL スキーマに準拠）
type NCEvent struct {
	TS        string       `json:"ts"`
	Source    string       `json:"source"` // "app" | "audit"
	Level     string       `json:"level"`  // "debug" | "info" | "warning" | "error"
	User      string       `json:"user"`
	IP        string       `json:"ip"`
	Msg       string       `json:"msg"`
	App       string       `json:"app"`
	ReqID     string       `json:"req_id,omitempty"`
	URL       string       `json:"url,omitempty"`
	Method    string       `json:"method,omitempty"`
	UserAgent string       `json:"ua,omitempty"`
	Exception *ncException `json:"exception,omitempty"`
}

// ncRawRecord は nextcloud.log / audit.log の1行のフィールド（使用するものだけ）
type ncRawRecord struct {
	ReqID      string       `json:"reqId"`
	Time       string       `json:"time"`
	Level      int          `json:"level"`
	RemoteAddr string       `json:"remoteAddr"`
	User       string       `json:"user"`
	Message    string       `json:"message"`
	App        string       `json:"app"`
	URL        string       `json:"url"`
	Method     string       `json:"method"`
	UserAgent  string       `json:"userAgent"`
	Exception  *ncException `json:"exception"`
}

type ncException struct {
	Message string `json:"message"`
}

type CollectResult struct {
	NewEvents int       `json:"new_events"`
	JsonlPath string    `json:"jsonl_path"`
	Events    []NCEvent `json:"events,omitempty"`
	// Truncated は上限で打ち切り、残りを次の回に回したとき true。
	Truncated bool `json:"truncated,omitempty"`
	// SkippedOversize は 1 件だけで上限を超えるため送らずに読み飛ばしたイベントの数。
	SkippedOversize int `json:"skipped_oversize,omitempty"`
}

// CollectNotes は agent のログへ INFO で 1 行ずつ出す補足を返す（main.go の collectAndReport が読む）。
func (r *CollectResult) CollectNotes() []string {
	if r == nil {
		return nil
	}
	var notes []string
	if r.Truncated {
		notes = append(notes, fmt.Sprintf("result capped (events=%d, limits %d bytes / %d events); the rest is sent next time", r.NewEvents, maxResultJSONBytes, maxResultEvents))
	}
	if r.SkippedOversize > 0 {
		notes = append(notes, fmt.Sprintf("skipped %d event(s) larger than %d bytes", r.SkippedOversize, maxResultJSONBytes))
	}
	return notes
}

var levelNames = map[int]string{
	0: "debug",
	1: "info",
	2: "warning",
	3: "error",
	4: "fatal",
}

// headFingerprintBytes はファイルの先頭の指紋に使う長さ。Nextcloud のログは 1 行目の先頭に
// reqId と時刻が入るので、ファイルごとに違う値になる。
const headFingerprintBytes = 512

// tailState は元のファイルごとの読んだ位置。キーは "app"（nextcloud.log）/ "audit"（audit.log）。
type tailState struct {
	Files map[string]*fileState `json:"files"`
	// Round は Collect の回数。2 つのファイルを読む順番を回ごとに入れ替えるのに使う（F8）。
	Round uint64 `json:"round"`
	// Appending は nextcloud.jsonl へ追記を始める前の印（追記前の大きさと先頭の指紋）。
	// 追記の後に位置の保存まで終われば消える。残っていたら、前の回の追記を切り詰めてからやり直す（F6）。
	Appending *appendMark `json:"appending,omitempty"`
}

// head はファイルの先頭 Len バイトの SHA-256（Len は headFingerprintBytes まで。若いファイルは短い）。
// Len が 0 のときは分からない（記録したとき空だった）。
type head struct {
	Len int    `json:"head_len,omitempty"`
	Sum string `json:"head_sum,omitempty"`
}

type fileState struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode,omitempty"`
	head
	// Prev は切り替えの後、まだ読み終えていない旧ファイル（<path>.1）の続き。
	Prev *prevState `json:"prev,omitempty"`
}

type prevState struct {
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode,omitempty"`
	head          // 旧ファイルの先頭の指紋（.1 がさらに入れ替わっていないかを見る）
}

type appendMark struct {
	Size int64 `json:"size"`
	head
}

// budget は 1 回の Collect で返せる残り（バイト数と件数）。イベント 1 件 = JSON の長さ + 区切りの 1。
type budget struct {
	remaining int
	events    int // まだ入れられる件数（Monitor は 1 回の報告で 1 collector あたり最後の 1000 件しか残さない）
	max       int // 1 件の上限。これを超えるイベントはどの回でも送れないので読み飛ばす
}

// quota は 1 つの元のファイルに割り当てた目安。元のファイルが 2 つあるので、片方の
// たまった分だけで毎回の上限を使い切って、もう片方が止まり続けないようにする。
type quota struct {
	share  int
	events int
	taken  int
}

func newBudget(jsonlPath string) *budget {
	// 封筒（events 以外の項目と "events":[ ] の括り）の分を先に差し引く。数字は最大桁で見積もる。
	env, _ := json.Marshal(&CollectResult{NewEvents: 1 << 30, JsonlPath: jsonlPath, Truncated: true, SkippedOversize: 1 << 30})
	n := maxResultJSONBytes - len(env) - len(`,"events":[]`)
	if n < 0 {
		n = 0
	}
	return &budget{remaining: n, events: maxResultEvents, max: n}
}

// take は cost バイトのイベントを入れられるなら差し引いて true を返す。
// 元のファイルごとの 1 件目だけは、割り当てを超えても全体の残りまで許す（先へ進めるため）。
func (b *budget) take(cost int, q *quota) bool {
	if cost > b.remaining || b.events <= 0 {
		return false
	}
	if q.taken > 0 && (cost > q.share || q.events <= 0) {
		return false
	}
	b.remaining -= cost
	b.events--
	q.share -= cost
	q.events--
	q.taken++
	return true
}

func (c *Collector) Collect(cfg collector.Config) (interface{}, error) {
	if strings.TrimSpace(cfg.Paths.DataDir) == "" {
		return nil, fmt.Errorf("paths.data_dir is required for nextcloud collector")
	}
	// どちらのログも存在しない場合は nil（Nextcloud 未導入）
	if _, err := os.Stat(cfg.Paths.NextcloudLog); os.IsNotExist(err) {
		if _, err2 := os.Stat(cfg.Paths.NcAuditLog); os.IsNotExist(err2) {
			return nil, nil
		}
	}

	jsonlPath := filepath.Join(cfg.Paths.DataDir, "logs", "nextcloud.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0755); err != nil {
		return nil, fmt.Errorf("mkdir logs: %w", err)
	}
	statePath := filepath.Join(cfg.Paths.DataDir, "json", stateFileName)
	state := loadState(statePath)
	// 前の回が追記の途中（または位置の保存の前）で止まっていたら、その追記を切り詰めてからやり直す。
	if err := recoverAppend(jsonlPath, state); err != nil {
		return nil, fmt.Errorf("recover jsonl: %w", err)
	}
	before, err := json.Marshal(state) // 読む前の位置（追記中の印と一緒に先に保存する）
	if err != nil {
		return nil, fmt.Errorf("marshal state: %w", err)
	}

	res := &CollectResult{JsonlPath: jsonlPath}
	b := newBudget(jsonlPath)
	jst := sharedcollector.Location()

	sources := []struct {
		key, source, path, setting string
		events                     []NCEvent
	}{
		{key: "app", source: "app", path: cfg.Paths.NextcloudLog, setting: "nextcloud_log"},
		{key: "audit", source: "audit", path: cfg.Paths.NcAuditLog, setting: "nc_audit_log"},
	}
	// 読む順番を回ごとに入れ替える。先に読む方は全体の残りまで 1 件目を入れられるので、
	// 片方にたまった分があっても、もう片方の大きめの 1 件が先送りされ続けない（F8）。
	order := []int{0, 1}
	if state.Round%2 == 1 {
		order = []int{1, 0}
	}
	for i, idx := range order {
		s := &sources[idx]
		n := len(order) - i
		q := &quota{share: b.remaining / n, events: b.events / n}
		st, err := readSource(state.Files[s.key], s.path, s.source, jst, q, b, res, &s.events)
		if err != nil {
			return nil, fmt.Errorf("read paths.%s %s: %w", s.setting, s.path, err)
		}
		state.Files[s.key] = st
	}
	// 返す順番は読んだ順に関係なく nextcloud.log → audit.log にそろえる。
	for _, s := range sources {
		res.Events = append(res.Events, s.events...)
	}
	res.NewEvents = len(res.Events)
	state.Round++

	// 手元の nextcloud.jsonl への追記は続ける（Monitor の通知が "local" として読む）。
	// 10MB で .1 へ名前を変えても、読む位置は元のファイル側で持つので送り直しは起きない。
	if len(res.Events) > 0 {
		mark, err := newAppendMark(jsonlPath)
		if err != nil {
			return nil, fmt.Errorf("stat jsonl: %w", err)
		}
		var pending tailState
		if err := json.Unmarshal(before, &pending); err != nil {
			return nil, fmt.Errorf("copy state: %w", err)
		}
		pending.Appending = mark
		// 追記中の印を先に保存する。保存できなければ追記しない（次の回に同じ所から読み直す）。
		if err := saveStateFn(statePath, &pending); err != nil {
			return nil, fmt.Errorf("save state: %w", err)
		}
		tmpl := &sharedcollector.JSONLLogCollector[NCEvent]{JSONLPath: jsonlPath}
		if err := tmpl.AppendJSONL(res.Events); err != nil {
			return nil, fmt.Errorf("append jsonl: %w", err)
		}
		if err := tmpl.Rotate(); err != nil {
			return nil, fmt.Errorf("rotate: %w", err)
		}
	}

	// 追記に成功してから位置を保存する（印は消える）。失敗したら、次の回に印から追記を切り詰めて読み直す。
	if err := saveStateFn(statePath, state); err != nil {
		return nil, fmt.Errorf("save state: %w", err)
	}
	return res, nil
}

// newAppendMark は追記を始める前の nextcloud.jsonl の大きさと先頭の指紋を返す（無ければ大きさ 0）。
func newAppendMark(jsonlPath string) (*appendMark, error) {
	info, err := os.Stat(jsonlPath)
	if errors.Is(err, os.ErrNotExist) {
		return &appendMark{}, nil
	}
	if err != nil {
		return nil, err
	}
	h, err := readHead(jsonlPath, info.Size())
	if err != nil {
		return nil, err
	}
	return &appendMark{Size: info.Size(), head: h}, nil
}

// recoverAppend は状態に追記中の印が残っていたら、nextcloud.jsonl を印の大きさまで切り詰めて印を消す。
// nextcloud.jsonl が印より大きくない・先頭の指紋が違う（10MB で .1 へ名前が変わった後など）ときは切り詰めない。
func recoverAppend(jsonlPath string, st *tailState) error {
	m := st.Appending
	st.Appending = nil
	if m == nil {
		return nil
	}
	info, err := os.Stat(jsonlPath)
	if err != nil {
		return nil // 無い（名前が変わった後など）
	}
	if info.Size() <= m.Size {
		return nil
	}
	same, err := m.head.matches(jsonlPath, info.Size())
	if err != nil {
		return err
	}
	if !same {
		return nil
	}
	return os.Truncate(jsonlPath, m.Size)
}

// readSource は 1 つの元のファイルを、記録した位置から読んで更新後の状態を返す。
// 読んだイベントは out に足す（上限で止めた・読み飛ばした件数は res に記録する）。
func readSource(st *fileState, path, source string, jst *time.Location, q *quota, b *budget, res *CollectResult, out *[]NCEvent) (*fileState, error) {
	info, err := os.Stat(path)
	exists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return st, err
	}
	if exists && info.IsDir() {
		return st, fmt.Errorf("is a directory, want the Nextcloud log file")
	}

	// 状態が無い（初回・パスが変わった・状態ファイルが壊れていた・位置が負か欠けていた）:
	// 末尾まで進めるだけで過去分は送らない。
	// まだ無いファイルは位置 0 で覚え、あとで出てきたら頭から読む（出てくる前の過去分は無いため）。
	if st == nil || st.Path != path {
		ns := &fileState{Path: path}
		if exists {
			off, err := lastLineEnd(path, info.Size())
			if err != nil {
				return st, err
			}
			ns.Offset = off
			ns.Inode = fileInode(path, info)
			if ns.head, err = readHead(path, info.Size()); err != nil {
				return st, err
			}
		}
		return ns, nil
	}

	if exists {
		ino := fileInode(path, info)
		sameHead, err := st.head.matches(path, info.Size())
		if err != nil {
			return st, err
		}
		// 切り替えの手がかり: 大きさの縮み・inode の変化・先頭の指紋の違い。
		// copytruncate は inode が変わらず、次の回までに新しいファイルが記録した位置より大きく
		// 育つと大きさでも見分けられないので、先頭の指紋で見る（F1）。inode の使い回しも同じ（F4）。
		rotated := info.Size() < st.Offset || !sameHead || (st.Inode != 0 && ino != 0 && ino != st.Inode)
		if rotated {
			// .1 がまだ読み終えていない旧ファイルなら、その続きを先に読む。
			// （前の切り替えの .1 を読み終える前にもう一度切り替わった場合、古い方の残りは追わない）
			st.Prev = nil
			prevPath := path + ".1"
			if pinfo, perr := os.Stat(prevPath); perr == nil && !pinfo.IsDir() {
				old, err := prevIsOldFile(st, ino, prevPath, pinfo)
				if err != nil {
					return st, err
				}
				if old {
					st.Prev = &prevState{Path: prevPath, Offset: st.Offset, Inode: fileInode(prevPath, pinfo), head: st.head}
				}
			}
			st.Offset = 0
			st.head = head{}
		}
		st.Inode = ino
		// 先頭の指紋を毎回そろえる（切り替えの直後は新しいファイルの指紋。若いファイルは 512 バイトまで伸ばす）。
		// .1 の続きを読んでいる途中でも取っておくので、その間にもう一度切り替わっても本体を見失わない（F2）。
		if st.head.Len < headFingerprintBytes && info.Size() > int64(st.head.Len) {
			if st.head, err = readHead(path, info.Size()); err != nil {
				return st, err
			}
		}
	}

	if st.Prev != nil {
		pinfo, perr := os.Stat(st.Prev.Path)
		valid := perr == nil && !pinfo.IsDir() && pinfo.Size() >= st.Prev.Offset
		if valid && st.Prev.Inode != 0 {
			if pino := fileInode(st.Prev.Path, pinfo); pino != 0 && pino != st.Prev.Inode {
				valid = false // .1 がさらに別のファイルに入れ替わった
			}
		}
		if valid {
			same, err := st.Prev.head.matches(st.Prev.Path, pinfo.Size())
			if err != nil {
				return st, err
			}
			valid = same // 先頭が違えば .1 は別のファイルに入れ替わった
		}
		if !valid {
			st.Prev = nil
		} else {
			off, more, err := readFrom(st.Prev.Path, st.Prev.Offset, true, source, jst, q, b, res, out)
			if err != nil {
				return st, err
			}
			st.Prev.Offset = off
			if more {
				return st, nil // 上限。元のファイルは次の回に
			}
			st.Prev = nil
		}
	}

	if exists {
		off, _, err := readFrom(path, st.Offset, false, source, jst, q, b, res, out)
		if err != nil {
			return st, err
		}
		st.Offset = off
	}
	return st, nil
}

// prevIsOldFile は、切り替えの後の <path>.1 が、記録した位置まで読んでいた旧ファイル（またはその写し）かを返す。
//   - 記録した先頭の指紋があれば、.1 の先頭がそれと同じで、大きさが記録した位置以上のときだけ旧ファイルとみなす。
//     create（audit.log）では旧ファイルそのもの、copytruncate（nextcloud.log）では写しが .1 になり、どちらも
//     先頭は旧ファイルと同じ。古い .1 が残ったまま本体だけ切り詰められた場合は先頭が違うので読まない（F3）
//   - 指紋が無い（記録したとき空だった）ときは、inode と大きさで見る
func prevIsOldFile(st *fileState, curIno uint64, prevPath string, pinfo os.FileInfo) (bool, error) {
	if pinfo.Size() < st.Offset {
		return false, nil
	}
	if st.head.Len > 0 {
		return st.head.matches(prevPath, pinfo.Size())
	}
	pino := fileInode(prevPath, pinfo)
	if st.Inode != 0 && pino != 0 && pino != st.Inode && curIno != st.Inode {
		return false, nil // .1 は別のファイル（読み終える前に 2 回以上切り替わった等）
	}
	return true, nil
}

// readHead は path の先頭 min(size, headFingerprintBytes) バイトの指紋を返す。
func readHead(path string, size int64) (head, error) {
	n := int64(headFingerprintBytes)
	if size < n {
		n = size
	}
	if n <= 0 {
		return head{}, nil
	}
	sum, err := headSum(path, int(n))
	if err != nil {
		return head{}, err
	}
	return head{Len: int(n), Sum: sum}, nil
}

// matches は path の先頭 h.Len バイトが記録と同じかを返す。指紋が無い（Len 0）ときは同じとみなす。
// ファイルが記録した長さより短ければ違う（切り詰められた）。
func (h head) matches(path string, size int64) (bool, error) {
	if h.Len <= 0 {
		return true, nil
	}
	if size < int64(h.Len) {
		return false, nil
	}
	sum, err := headSum(path, h.Len)
	if err != nil {
		return false, err
	}
	return sum == h.Sum, nil
}

func headSum(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, n)
	if _, err := io.ReadFull(f, buf); err != nil {
		return "", err
	}
	s := sha256.Sum256(buf)
	return hex.EncodeToString(s[:]), nil
}

// readFrom は path を offset から読み、改行まで読めた行だけをイベントにして out に足す。
// 戻り値は次に読む位置と、上限で止めたか（more）。
// final=true（切り替え後の .1 のように、もう書き足されないファイル）のときは、末尾の改行の無い行も読む。
func readFrom(path string, offset int64, final bool, source string, jst *time.Location, q *quota, b *budget, res *CollectResult, out *[]NCEvent) (int64, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return offset, false, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, false, err
	}

	r := bufio.NewReaderSize(f, 1024*1024)
	consumed := offset
	for {
		line, rerr := r.ReadString('\n')
		if rerr != nil && !errors.Is(rerr, io.EOF) {
			return offset, false, rerr
		}
		if rerr != nil && (!final || line == "") {
			return consumed, false, nil // 末尾の書きかけの行は位置を進めない
		}

		if ev, ok := parseLine(line, source, jst); ok {
			bs, merr := json.Marshal(ev)
			cost := len(bs) + 1
			switch {
			case merr != nil:
				// 文字列だけの構造なので起きないが、起きたら読み飛ばす
			case cost > b.max:
				res.SkippedOversize++
			case !b.take(cost, q):
				res.Truncated = true
				return consumed, true, nil // この行は次の回に
			default:
				*out = append(*out, ev)
			}
		}
		consumed += int64(len(line))
		if rerr != nil {
			return consumed, false, nil // final の最後の行（改行なし）
		}
	}
}

// lastLineEnd は path の [0,size) の最後の改行の直後の位置を返す（改行が無ければ 0）。
func lastLineEnd(path string, size int64) (int64, error) {
	if size <= 0 {
		return 0, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	const chunk = 64 * 1024
	buf := make([]byte, chunk)
	end := size
	for end > 0 {
		start := end - chunk
		if start < 0 {
			start = 0
		}
		n, err := f.ReadAt(buf[:end-start], start)
		if err != nil && !errors.Is(err, io.EOF) {
			return 0, err
		}
		if i := bytes.LastIndexByte(buf[:n], '\n'); i >= 0 {
			return start + int64(i) + 1, nil
		}
		end = start
	}
	return 0, nil
}

// loadState は状態ファイルを読む。無い・壊れているときは空の状態（＝初回扱い。過去分は送らない）。
// 元のファイルごとの項目で、位置が欠けている・負・先頭の指紋の長さがおかしいものは、
// そのファイルだけ初回扱い（末尾まで進めるだけ）にする。位置 0 として読むと全部を送り直し、
// 負のまま読むと毎回 seek で失敗してもう片方のファイルも止まるため（F7）。
func loadState(path string) *tailState {
	empty := &tailState{Files: map[string]*fileState{}}
	b, err := os.ReadFile(path)
	if err != nil {
		return empty
	}
	var st tailState
	if err := json.Unmarshal(b, &st); err != nil || st.Files == nil {
		return empty
	}
	var present struct {
		Files map[string]*struct {
			Offset *int64 `json:"offset"`
			Prev   *struct {
				Offset *int64 `json:"offset"`
			} `json:"prev"`
		} `json:"files"`
		Appending *struct {
			Size *int64 `json:"size"`
		} `json:"appending"`
	}
	_ = json.Unmarshal(b, &present)
	for k, fs := range st.Files {
		p := present.Files[k]
		if fs == nil || p == nil || fs.Path == "" || p.Offset == nil || fs.Offset < 0 || !fs.head.valid() {
			delete(st.Files, k)
			continue
		}
		if fs.Prev != nil && (p.Prev == nil || p.Prev.Offset == nil || fs.Prev.Offset < 0 || fs.Prev.Path == "" || !fs.Prev.head.valid()) {
			fs.Prev = nil
		}
	}
	if st.Appending != nil && (present.Appending == nil || present.Appending.Size == nil || st.Appending.Size < 0 || !st.Appending.head.valid()) {
		st.Appending = nil
	}
	return &st
}

func (h head) valid() bool {
	if h.Len == 0 {
		return h.Sum == ""
	}
	return h.Len > 0 && h.Len <= headFingerprintBytes && len(h.Sum) == 64
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

func parseLine(line, source string, jst *time.Location) (NCEvent, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return NCEvent{}, false
	}

	var raw ncRawRecord
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return NCEvent{}, false
	}

	ts := parseTS(raw.Time, jst)
	level := levelNames[raw.Level]
	if level == "" {
		level = "info"
	}
	app := raw.App
	if app == "" {
		app = "core"
	}

	return NCEvent{
		TS:        ts,
		Source:    source,
		Level:     level,
		User:      raw.User,
		IP:        raw.RemoteAddr,
		Msg:       raw.Message,
		App:       app,
		ReqID:     raw.ReqID,
		URL:       raw.URL,
		Method:    raw.Method,
		UserAgent: raw.UserAgent,
		Exception: raw.Exception,
	}, true
}

func parseTS(raw string, jst *time.Location) string {
	// Nextcloud の time フィールドは RFC3339 形式（例: "2026-04-21T00:01:00+00:00"）
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		// フォールバック: 他のフォーマット
		for _, layout := range []string{
			"2006-01-02T15:04:05+00:00",
			"2006-01-02 15:04:05",
		} {
			if t2, err2 := time.ParseInLocation(layout, raw, time.UTC); err2 == nil {
				return t2.In(jst).Format(time.RFC3339)
			}
		}
		return raw
	}
	return t.In(jst).Format(time.RFC3339)
}
