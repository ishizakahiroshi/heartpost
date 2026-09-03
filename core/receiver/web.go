package receiver

import (
	"crypto/subtle"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"time"

	webassets "github.com/ishizakahiroshi/heartpost/web"
)

// BasicAuth は一覧画面の認証。RBAC は持たない。
// User が空なら認証をかけない（LAN 内・SSH ポートフォワード越しに見る場合を想定）。
type BasicAuth struct {
	User     string
	Password string
	Realm    string
}

func (a BasicAuth) enabled() bool { return a.User != "" }

// Dashboard は一覧画面 1 枚を出す。
type Dashboard struct {
	store      *Store
	thresholds Thresholds
	auth       BasicAuth
	loc        *time.Location
	tmpl       *template.Template
	static     http.Handler
	now        func() time.Time
}

// NewDashboard は一覧画面を作る。loc が nil なら実行ホストのローカル時刻で表示する。
func NewDashboard(store *Store, thresholds Thresholds, auth BasicAuth, loc *time.Location) (*Dashboard, error) {
	tmpl, err := template.ParseFS(webassets.FS, "dashboard.html")
	if err != nil {
		return nil, fmt.Errorf("receiver: parse dashboard template: %w", err)
	}
	staticFS, err := fs.Sub(webassets.FS, "static")
	if err != nil {
		return nil, fmt.Errorf("receiver: static fs: %w", err)
	}
	if loc == nil {
		loc = time.Local
	}
	return &Dashboard{
		store:      store,
		thresholds: thresholds,
		auth:       auth,
		loc:        loc,
		tmpl:       tmpl,
		static:     http.StripPrefix("/static/", http.FileServerFS(staticFS)),
	}, nil
}

// SetNow はテスト用に現在時刻を差し替える。
func (d *Dashboard) SetNow(f func() time.Time) { d.now = f }

func (d *Dashboard) currentTime() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// ServeHTTP は "/" に一覧を、"/static/" に埋め込み静的ファイルを出す。
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !d.checkAuth(w, r) {
		return
	}
	if len(r.URL.Path) >= len("/static/") && r.URL.Path[:len("/static/")] == "/static/" {
		d.static.ServeHTTP(w, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	d.index(w, r)
}

func (d *Dashboard) checkAuth(w http.ResponseWriter, r *http.Request) bool {
	if !d.auth.enabled() {
		return true
	}
	user, pass, ok := r.BasicAuth()
	// 定数時間比較。ユーザー名の一致・不一致で応答時間を変えない。
	userOK := subtle.ConstantTimeCompare([]byte(user), []byte(d.auth.User)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(d.auth.Password)) == 1
	if ok && userOK && passOK {
		return true
	}
	realm := d.auth.Realm
	if realm == "" {
		realm = "heartpost monitor"
	}
	w.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q, charset=\"UTF-8\"", realm))
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return false
}

// Row は表の 1 行分。
type Row struct {
	AgentID   string
	AgentType string
	Label     string
	Down      bool
	// Unknown はまだ 1 通も受け取っていない agent。生存とも欠報とも言えないので分ける。
	Unknown  bool
	LastSeen string
	Silence  string
	RootDisk string
	Load     string
}

type pageData struct {
	GeneratedAt string
	Rows        []Row
	DownCount   int
	TotalCount  int
}

func (d *Dashboard) index(w http.ResponseWriter, r *http.Request) {
	now := d.currentTime()
	data := d.buildPage(now)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if err := d.tmpl.ExecuteTemplate(w, "dashboard.html", data); err != nil {
		// ヘッダは既に送っているので、ここでは status を変えられない。
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// buildPage は画面に出す行を組み立てる。欠報を上に、次に無通信時間の長い順に並べる。
func (d *Dashboard) buildPage(now time.Time) pageData {
	states := d.store.States()
	rows := make([]Row, 0, len(states))
	downCount := 0

	type sortKey struct {
		down    bool
		unknown bool
		silence time.Duration
	}
	keys := make([]sortKey, 0, len(states))

	for _, st := range states {
		unknown := st.LastSeen.IsZero()
		silence := time.Duration(0)
		down := false
		lastSeen := "-"
		silenceText := "-"

		if !unknown {
			silence = now.Sub(st.LastSeen)
			down = silence > d.thresholds.For(st.AgentID)
			lastSeen = st.LastSeen.In(d.loc).Format("2006-01-02 15:04:05")
			silenceText = humanDuration(silence)
		}
		if down {
			downCount++
		}

		rows = append(rows, Row{
			AgentID:   st.AgentID,
			AgentType: st.AgentType,
			Label:     st.Label(),
			Down:      down,
			Unknown:   unknown,
			LastSeen:  lastSeen,
			Silence:   silenceText,
			RootDisk:  orDash(st.RootDiskPercent),
			Load:      formatLoad(st),
		})
		keys = append(keys, sortKey{down: down, unknown: unknown, silence: silence})
	}

	idx := make([]int, len(rows))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(a, b int) bool {
		ka, kb := keys[idx[a]], keys[idx[b]]
		if ka.down != kb.down {
			return ka.down
		}
		if ka.unknown != kb.unknown {
			return ka.unknown
		}
		if ka.silence != kb.silence {
			return ka.silence > kb.silence
		}
		return rows[idx[a]].AgentID < rows[idx[b]].AgentID
	})
	sorted := make([]Row, 0, len(rows))
	for _, i := range idx {
		sorted = append(sorted, rows[i])
	}

	return pageData{
		GeneratedAt: now.In(d.loc).Format("2006-01-02 15:04:05"),
		Rows:        sorted,
		DownCount:   downCount,
		TotalCount:  len(sorted),
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatLoad(st AgentState) string {
	if !st.HasLoad {
		return "-"
	}
	return fmt.Sprintf("%.2f / %.2f / %.2f", st.Load1, st.Load5, st.Load15)
}

// humanDuration は経過時間を日本語の短い表記にする。
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d秒", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d分", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) - h*60
		return fmt.Sprintf("%d時間%d分", h, m)
	default:
		days := int(d.Hours()) / 24
		h := int(d.Hours()) - days*24
		return fmt.Sprintf("%d日%d時間", days, h)
	}
}
