// Package nc_deletion は Nextcloud の削除を「あとから原因を追える形」で残す collector。
//
// 同期クライアントや利用者が短時間に大量のファイルを消したとき、監査ログ（admin_audit の
// audit.log）の数千行を手で集計しないと「誰の名義・どのクライアント・どこから・何件」が分からない。
// この collector はそれを最初から 1 行にまとめて残す。通知はしない（記録だけ）。
//
// 有効にする条件: Paths.NcAuditLog（Nextcloud の audit.log）と Paths.DataDir の両方が設定され、
// audit.log が存在すること。どちらかが無ければ何もせず nil を返す。
//
// 記録するもの（DataDir/logs/nc_deletion.jsonl・0600。状態は DataDir/json/nc_deletion_state.json）:
//
//  1. 監査ログの削除系の行を、同じ名義・接続元・クライアント・種類で、間隔が 5 分以内のものを
//     1 つの塊にまとめた行（kind = delete / trash_purge / version_delete / trash_restore）
//  2. 保守の操作（occ の maintenance・upgrade・app の更新・ごみ箱の掃除など）を 1 行ずつ（kind = ops）
//  3. グループフォルダのごみ箱から消えた項目（kind = gf_trash_removed）。グループフォルダの
//     ごみ箱の完全削除と期限切れの自動削除は監査ログに残らない（Nextcloud 34 / groupfolders で
//     コードを確認）ため、ごみ箱の一覧を前回と比べて補う
//
// 報告として返すのは件数だけ。名義・接続元・ファイル名は返さない（報告が監視先の外へ
// 集約されることがあるため。詳細はサーバー内の記録ファイルにだけ残す）。
//
// グループフォルダのごみ箱の位置は、audit.log と同じフォルダ（Nextcloud の data directory）の
// __groupfolders/<id>/trash とみなす。
package nc_deletion

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
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	hpcollector "github.com/ishizakahiroshi/heartpost/collector"
	optional "github.com/ishizakahiroshi/heartpost/collector/optional"
)

const (
	// clusterGap は同じ塊とみなす削除の間隔。これより空いたら別の塊にする。
	clusterGap = 5 * time.Minute
	// maxReadBytes は 1 回の収集で読む上限（監査ログが急に膨らんでもメモリを使い切らない）。
	maxReadBytes = 64 << 20
	// fingerprintLen はログの切り替わりを見分けるために先頭から読むバイト数。
	fingerprintLen = 512
	// maxFolders は 1 つの塊で数えるフォルダの種類の上限（それ以上は "(その他)" にまとめる）。
	maxFolders = 200
	// topFolders / samplePaths は記録 1 行に載せる数。
	topFolders  = 10
	samplePaths = 5
	// maxRecordBytes を超えたら記録ファイルを .1 へ回す（1 世代だけ残す）。
	maxRecordBytes = 50 << 20
	// trashExpiryHint は「期限切れによる自動削除の可能性」を付ける目安（Nextcloud の auto,14）。
	trashExpiryHint = 14 * 24 * time.Hour
	// recentWindow は報告で返す件数の集計範囲。
	recentWindow = 24 * time.Hour
	// maxTrashNames は 1 行に載せるごみ箱の項目名の数。
	maxTrashNames = 20
)

// opsPrefixes は記録する occ の操作。削除・保守・ごみ箱の掃除に関わるものだけを選ぶ。
var opsPrefixes = []string{
	"maintenance:mode",
	"upgrade",
	"app:update",
	"app:enable",
	"app:disable",
	"app:remove",
	"trashbin:cleanup",
	"trashbin:expire",
	"versions:cleanup",
	"versions:expire",
	"groupfolders:trashbin:cleanup",
	"groupfolders:expire",
	"groupfolders:delete",
	"groupfolders:scan",
	"files:scan",
	"files:cleanup",
	"files:delete",
	"user:delete",
}

var (
	reDelete        = regexp.MustCompile(`^File with id "\d+" deleted: "(.*)"$`)
	reTrashPurge    = regexp.MustCompile(`^File "(.*)" deleted from trash bin\.?$`)
	reTrashRestore  = regexp.MustCompile(`^File "(.*)" restored from trash bin\.?$`)
	reVersionDelete = regexp.MustCompile(`^Version "(.*)" was deleted\.?$`)
	reTrashSuffix   = regexp.MustCompile(`^(.*)\.d(\d{9,11})$`)
)

// Collector は nc_deletion collector。
type Collector struct {
	// Now はテストで時刻を固定するためのもの。nil なら time.Now。
	Now func() time.Time
	mu  sync.Mutex
}

func (c *Collector) Name() string     { return "nc_deletion" }
func (c *Collector) Interval() string { return "log" }

// Summary は報告で返す件数だけの要約。
type Summary struct {
	Clusters24h     int    `json:"clusters_24h"`
	Files24h        int    `json:"files_24h"`
	Largest24h      int    `json:"largest_24h"`
	TrashRemoved24h int    `json:"gf_trash_removed_24h"`
	OpenClusters    int    `json:"open_clusters"`
	Error           string `json:"error,omitempty"`
}

// Record は nc_deletion.jsonl の 1 行。
type Record struct {
	Kind        string        `json:"kind"`
	Start       string        `json:"start"`
	End         string        `json:"end"`
	Count       int           `json:"count"`
	User        string        `json:"user,omitempty"`
	RemoteAddr  string        `json:"remote_addr,omitempty"`
	UserAgent   string        `json:"user_agent,omitempty"`
	Client      string        `json:"client,omitempty"`
	Method      string        `json:"method,omitempty"`
	Folders     []FolderCount `json:"folders,omitempty"`
	Samples     []string      `json:"samples,omitempty"`
	Command     string        `json:"command,omitempty"`
	FolderID    string        `json:"folder_id,omitempty"`
	Restored    int           `json:"restore_logged,omitempty"`
	Unlogged    int           `json:"not_logged,omitempty"`
	OlderThan14 int           `json:"deleted_14d_ago_or_more,omitempty"`
	Names       []string      `json:"names,omitempty"`
	Note        string        `json:"note,omitempty"`
}

// FolderCount は塊の中で、どのフォルダから何件消えたか。
type FolderCount struct {
	Folder string `json:"folder"`
	Count  int    `json:"count"`
}

// state は DataDir/json/nc_deletion_state.json に残す読み取り位置と途中の塊。
type state struct {
	Audit    auditPos            `json:"audit"`
	Open     map[string]*cluster `json:"open"`
	Trash    map[string][]string `json:"gf_trash"`
	TrashSet bool                `json:"gf_trash_initialized"`
	// Restored は直近の「ごみ箱から戻した」記録の名前（ベース名）と時刻。ごみ箱から消えた
	// 項目が戻されたのか消されたのかを見分けるのに使う。
	Restored map[string]string `json:"restored"`
	Recent   []recent          `json:"recent"`
}

type auditPos struct {
	Path        string `json:"path"`
	Offset      int64  `json:"offset"`
	Fingerprint string `json:"fingerprint"`
	FPLen       int    `json:"fingerprint_len"`
}

type recent struct {
	At    string `json:"at"`
	Kind  string `json:"kind"`
	Count int    `json:"count"`
}

type cluster struct {
	Kind       string         `json:"kind"`
	User       string         `json:"user"`
	RemoteAddr string         `json:"remote_addr"`
	UserAgent  string         `json:"user_agent"`
	Method     string         `json:"method"`
	First      time.Time      `json:"first"`
	Last       time.Time      `json:"last"`
	Count      int            `json:"count"`
	Folders    map[string]int `json:"folders"`
	Samples    []string       `json:"samples"`
}

// auditLine は audit.log の 1 行のうち使う項目。
type auditLine struct {
	Time       string `json:"time"`
	User       string `json:"user"`
	RemoteAddr string `json:"remoteAddr"`
	UserAgent  string `json:"userAgent"`
	Method     string `json:"method"`
	Message    string `json:"message"`
}

func (c *Collector) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// Collect は監査ログの差分とグループフォルダのごみ箱を読み、記録を足して件数を返す。
// Nextcloud が無い（audit.log が無い）サーバーでは何もせず nil を返す。
func (c *Collector) Collect(cfg optional.Config) (interface{}, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	auditPath := cfg.Paths.NcAuditLog
	if auditPath == "" {
		return nil, nil
	}
	if _, err := os.Stat(auditPath); err != nil {
		return nil, nil
	}
	dataDir := cfg.Paths.DataDir
	if dataDir == "" {
		return nil, nil
	}
	statePath := filepath.Join(dataDir, "json", "nc_deletion_state.json")
	outPath := filepath.Join(dataDir, "logs", "nc_deletion.jsonl")
	now := c.now()

	st, err := loadState(statePath)
	if err != nil {
		// 壊れた状態ファイルで止まり続けないよう、記録を残して作り直す。
		st = newState()
		_ = appendRecords(outPath, []Record{{Kind: "agent_note", Start: fmtTime(now), End: fmtTime(now), Note: "状態ファイルを読めなかったので作り直した: " + err.Error()}})
	}

	var records []Record
	sum := Summary{}

	lines, pos, readErr := readAudit(auditPath, st.Audit)
	if readErr != nil {
		sum.Error = readErr.Error()
	} else {
		st.Audit = pos
	}
	for _, raw := range lines {
		records = append(records, st.feed(raw)...)
	}
	records = append(records, st.flush(now, false)...)

	gfRoot := filepath.Join(filepath.Dir(auditPath), "__groupfolders")
	trashRecs, trashErr := st.scanTrash(gfRoot, now)
	if trashErr != nil && sum.Error == "" {
		sum.Error = trashErr.Error()
	}
	records = append(records, trashRecs...)

	if len(records) > 0 {
		if err := appendRecords(outPath, records); err != nil {
			// 書けなかった塊は捨てる（次回同じ行を読み直さないので、失敗を件数側に出す）。
			sum.Error = "記録の書き込みに失敗: " + err.Error()
		}
	}
	st.pruneRecent(now)
	st.pruneRestored(now)
	if err := saveState(statePath, st); err != nil && sum.Error == "" {
		sum.Error = "状態の保存に失敗: " + err.Error()
	}

	for _, r := range st.Recent {
		switch r.Kind {
		case "gf_trash_removed":
			sum.TrashRemoved24h += r.Count
		case "delete", "trash_purge", "version_delete":
			sum.Clusters24h++
			sum.Files24h += r.Count
			if r.Count > sum.Largest24h {
				sum.Largest24h = r.Count
			}
		}
	}
	sum.OpenClusters = len(st.Open)
	return sum, nil
}

func newState() *state {
	return &state{Open: map[string]*cluster{}, Trash: map[string][]string{}, Restored: map[string]string{}}
}

func loadState(p string) (*state, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return newState(), nil
	}
	if err != nil {
		return nil, err
	}
	st := newState()
	if err := json.Unmarshal(b, st); err != nil {
		return nil, err
	}
	if st.Open == nil {
		st.Open = map[string]*cluster{}
	}
	if st.Trash == nil {
		st.Trash = map[string][]string{}
	}
	if st.Restored == nil {
		st.Restored = map[string]string{}
	}
	return st, nil
}

func saveState(p string, st *state) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func appendRecords(p string, recs []Record) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	if fi, err := os.Stat(p); err == nil && fi.Size() > maxRecordBytes {
		_ = os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			return err
		}
	}
	_, err = f.Write(buf.Bytes())
	return err
}

// ---- 監査ログの読み取り ----

func fingerprint(p string) (string, int, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	buf := make([]byte, fingerprintLen)
	n, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", 0, err
	}
	sum := sha256.Sum256(buf[:n])
	return hex.EncodeToString(sum[:]), n, nil
}

// fingerprintN は先頭 n バイトだけで指紋を取る（記録時より短かった指紋と比べるため）。
func fingerprintN(p string, n int) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", err
	}
	if got < n {
		return "", nil
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}

// readAudit は前回の位置から audit.log の新しい行を読む。
// 初回は末尾へ進めるだけで読まない（過去分を一度に記録しない）。
// ログが切り替わっていたら、指紋が一致する audit.log.1 の残りを読んでから新しいファイルを頭から読む。
func readAudit(p string, pos auditPos) ([][]byte, auditPos, error) {
	fi, err := os.Stat(p)
	if err != nil {
		return nil, pos, err
	}
	fp, fpLen, err := fingerprint(p)
	if err != nil {
		return nil, pos, err
	}
	if pos.Path != p || pos.Fingerprint == "" {
		return nil, auditPos{Path: p, Offset: fi.Size(), Fingerprint: fp, FPLen: fpLen}, nil
	}

	same := false
	if fi.Size() >= pos.Offset {
		cur, err := fingerprintN(p, pos.FPLen)
		if err == nil && cur == pos.Fingerprint {
			same = true
		}
	}

	var lines [][]byte
	budget := int64(maxReadBytes)
	if !same {
		old := p + ".1"
		if oldFP, err := fingerprintN(old, pos.FPLen); err == nil && oldFP == pos.Fingerprint {
			got, _, err := readLines(old, pos.Offset, budget, true)
			if err == nil {
				lines = append(lines, got...)
			}
		}
		pos = auditPos{Path: p, Offset: 0}
	}
	got, next, err := readLines(p, pos.Offset, budget, false)
	if err != nil {
		return lines, pos, err
	}
	lines = append(lines, got...)
	// 指紋は記録時より伸びていれば取り直す（512 バイトに満たないうちに読んだ場合）。
	if pos.Fingerprint == "" || pos.FPLen < fingerprintLen {
		pos.Fingerprint, pos.FPLen = fp, fpLen
	}
	pos.Path = p
	pos.Offset = next
	return lines, pos, nil
}

// readLines は offset から改行で終わる行だけを読み、読み終えた位置を返す。
// toEnd が true（切り替わり前のファイル）のときは、改行の無い最後の行も読む。
func readLines(p string, offset, budget int64, toEnd bool) ([][]byte, int64, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, offset, err
	}
	defer f.Close()
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, err
	}
	r := bufio.NewReaderSize(f, 1<<20)
	var out [][]byte
	pos := offset
	for pos-offset < budget {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && (line[len(line)-1] == '\n' || (toEnd && errors.Is(err, io.EOF))) {
			pos += int64(len(line))
			out = append(out, bytes.TrimRight(line, "\r\n"))
		}
		if err != nil {
			break
		}
	}
	return out, pos, nil
}

// ---- 塊にまとめる ----

func (st *state) feed(raw []byte) []Record {
	if !bytes.Contains(raw, []byte(`deleted`)) && !bytes.Contains(raw, []byte(`restored from trash bin`)) && !bytes.Contains(raw, []byte(`Console command executed`)) {
		return nil
	}
	var l auditLine
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil
	}
	t, err := time.Parse(time.RFC3339, l.Time)
	if err != nil {
		return nil
	}
	msg := l.Message

	if strings.HasPrefix(msg, "Console command executed: ") {
		cmd := strings.TrimPrefix(msg, "Console command executed: ")
		if !isOpsCommand(cmd) {
			return nil
		}
		return []Record{{Kind: "ops", Start: fmtTime(t), End: fmtTime(t), Count: 1, User: l.User, Command: cmd}}
	}

	kind, p := "", ""
	if m := reDelete.FindStringSubmatch(msg); m != nil {
		kind, p = "delete", m[1]
	} else if m := reTrashPurge.FindStringSubmatch(msg); m != nil {
		kind, p = "trash_purge", m[1]
	} else if m := reVersionDelete.FindStringSubmatch(msg); m != nil {
		kind, p = "version_delete", m[1]
	} else if m := reTrashRestore.FindStringSubmatch(msg); m != nil {
		kind, p = "trash_restore", m[1]
		st.Restored[path.Base(p)] = fmtTime(t)
	} else {
		return nil
	}

	var out []Record
	key := strings.Join([]string{kind, l.User, l.RemoteAddr, l.UserAgent}, "\x00")
	cl := st.Open[key]
	if cl != nil && t.Sub(cl.Last) > clusterGap {
		out = append(out, cl.record())
		st.addRecent(cl.Last, cl.Kind, cl.Count)
		delete(st.Open, key)
		cl = nil
	}
	if cl == nil {
		cl = &cluster{Kind: kind, User: l.User, RemoteAddr: l.RemoteAddr, UserAgent: l.UserAgent, Method: l.Method, First: t, Last: t, Folders: map[string]int{}}
		st.Open[key] = cl
	}
	if t.Before(cl.First) {
		cl.First = t
	}
	if t.After(cl.Last) {
		cl.Last = t
	}
	cl.Count++
	rel := relPath(l.User, p)
	folder := folderOf(rel)
	if _, ok := cl.Folders[folder]; ok || len(cl.Folders) < maxFolders {
		cl.Folders[folder]++
	} else {
		cl.Folders["(その他)"]++
	}
	if len(cl.Samples) < samplePaths {
		cl.Samples = append(cl.Samples, rel)
	}
	return out
}

// flush は最後の削除から clusterGap を過ぎた塊を記録に回す。all なら全部回す。
func (st *state) flush(now time.Time, all bool) []Record {
	keys := make([]string, 0, len(st.Open))
	for k := range st.Open {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []Record
	for _, k := range keys {
		cl := st.Open[k]
		if all || now.Sub(cl.Last) > clusterGap {
			out = append(out, cl.record())
			st.addRecent(cl.Last, cl.Kind, cl.Count)
			delete(st.Open, k)
		}
	}
	return out
}

func (cl *cluster) record() Record {
	r := Record{
		Kind:       cl.Kind,
		Start:      fmtTime(cl.First),
		End:        fmtTime(cl.Last),
		Count:      cl.Count,
		User:       cl.User,
		RemoteAddr: cl.RemoteAddr,
		UserAgent:  cl.UserAgent,
		Client:     clientKind(cl.UserAgent),
		Method:     cl.Method,
		Samples:    cl.Samples,
	}
	for f, n := range cl.Folders {
		r.Folders = append(r.Folders, FolderCount{Folder: f, Count: n})
	}
	sort.Slice(r.Folders, func(i, j int) bool {
		if r.Folders[i].Count != r.Folders[j].Count {
			return r.Folders[i].Count > r.Folders[j].Count
		}
		return r.Folders[i].Folder < r.Folders[j].Folder
	})
	if len(r.Folders) > topFolders {
		r.Folders = r.Folders[:topFolders]
	}
	return r
}

func (st *state) addRecent(at time.Time, kind string, n int) {
	st.Recent = append(st.Recent, recent{At: fmtTime(at), Kind: kind, Count: n})
}

func (st *state) pruneRecent(now time.Time) {
	kept := st.Recent[:0]
	for _, r := range st.Recent {
		t, err := time.Parse(time.RFC3339, r.At)
		if err == nil && now.Sub(t) <= recentWindow {
			kept = append(kept, r)
		}
	}
	st.Recent = kept
}

func (st *state) pruneRestored(now time.Time) {
	for k, v := range st.Restored {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil || now.Sub(t) > recentWindow {
			delete(st.Restored, k)
		}
	}
}

// ---- グループフォルダのごみ箱 ----

// scanTrash は __groupfolders/<id>/trash の直下の名前を前回と比べ、消えたものを記録する。
// 初回は一覧を覚えるだけ。名前は "<元の名前>.d<削除時刻>"。
func (st *state) scanTrash(root string, now time.Time) ([]Record, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("グループフォルダの一覧を読めない: %w", err)
	}
	current := map[string][]string{}
	var firstErr error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		id := e.Name()
		items, err := os.ReadDir(filepath.Join(root, id, "trash"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("ごみ箱を読めない（folder %s）: %w", id, err)
			}
			// 読めなかったフォルダは前回の一覧をそのまま残す（消えたと誤って記録しない）。
			if prev, ok := st.Trash[id]; ok {
				current[id] = prev
			}
			continue
		}
		names := make([]string, 0, len(items))
		for _, it := range items {
			names = append(names, it.Name())
		}
		sort.Strings(names)
		current[id] = names
	}

	var out []Record
	if st.TrashSet {
		ids := make([]string, 0, len(st.Trash))
		for id := range st.Trash {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			now2 := map[string]bool{}
			for _, n := range current[id] {
				now2[n] = true
			}
			var gone []string
			for _, n := range st.Trash[id] {
				if !now2[n] {
					gone = append(gone, n)
				}
			}
			if len(gone) == 0 {
				continue
			}
			r := Record{Kind: "gf_trash_removed", Start: fmtTime(now), End: fmtTime(now), Count: len(gone), FolderID: id,
				Note: "グループフォルダのごみ箱から消えた項目。戻した記録があるもの以外は、完全削除・期限切れ・記録の残らない復元のどれか"}
			for _, n := range gone {
				base := n
				var deletedAt time.Time
				if m := reTrashSuffix.FindStringSubmatch(n); m != nil {
					base = m[1]
					if sec, err := strconv.ParseInt(m[2], 10, 64); err == nil {
						deletedAt = time.Unix(sec, 0)
					}
				}
				if _, ok := st.Restored[base]; ok {
					r.Restored++
				} else {
					r.Unlogged++
				}
				if !deletedAt.IsZero() && now.Sub(deletedAt) >= trashExpiryHint {
					r.OlderThan14++
				}
				if len(r.Names) < maxTrashNames {
					r.Names = append(r.Names, n)
				}
			}
			out = append(out, r)
			st.addRecent(now, r.Kind, r.Count)
		}
	}
	st.Trash = current
	st.TrashSet = true
	return out, firstErr
}

// ---- 小さな道具 ----

func isOpsCommand(cmd string) bool {
	for _, p := range opsPrefixes {
		if cmd == p || strings.HasPrefix(cmd, p+" ") {
			return true
		}
	}
	return false
}

// relPath は "/<user>/files/A/B/c" を "A/B/c" にする。形が違えばそのまま返す。
func relPath(user, p string) string {
	prefix := "/" + user + "/files/"
	if user != "" && strings.HasPrefix(p, prefix) {
		return strings.TrimPrefix(p, prefix)
	}
	return strings.TrimPrefix(p, "/")
}

// folderOf はファイルの親フォルダを上 2 階層までで返す（直下のファイルは "/"）。
func folderOf(rel string) string {
	dir := path.Dir(rel)
	if dir == "." || dir == "/" || dir == "" {
		return "/"
	}
	parts := strings.Split(dir, "/")
	if len(parts) > 2 {
		parts = parts[:2]
	}
	return strings.Join(parts, "/")
}

// clientKind は User-Agent から、人が読める端末の種類を返す。
func clientKind(ua string) string {
	switch {
	case ua == "" || ua == "--":
		return "不明"
	case strings.Contains(ua, "mirall"):
		return "デスクトップ同期クライアント"
	case strings.Contains(ua, "Nextcloud-android"), strings.Contains(ua, "Nextcloud-iOS"):
		return "スマホアプリ"
	case strings.Contains(ua, "Mozilla/5.0") && (strings.Contains(ua, "Chrome") || strings.Contains(ua, "Firefox") || strings.Contains(ua, "Safari") || strings.Contains(ua, "Edg")):
		return "ブラウザ"
	default:
		return "その他"
	}
}

func fmtTime(t time.Time) string {
	return t.In(hpcollector.Location()).Format(time.RFC3339)
}
