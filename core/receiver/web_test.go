package receiver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func seedThreeAgents(t *testing.T, store *Store, base time.Time) {
	t.Helper()
	collectors := func(host, use string, load float64) map[string]json.RawMessage {
		return map[string]json.RawMessage{
			"host":    json.RawMessage(`{"hostname":"` + host + `","os":"FreeBSD sample 14.0"}`),
			"disk":    json.RawMessage(`[{"filesystem":"/dev/da0p2","size":"20G","used":"8.0G","avail":"12G","use_percent":"` + use + `","mounted":"/"}]`),
			"loadavg": json.RawMessage(`{"load1":` + jsonNum(load) + `,"load5":0.20,"load15":0.30}`),
		}
	}
	// web-01 は生存、web-02 も生存、db-01 はしきい値を大きく超えた欠報。
	if err := store.Append(Record{AgentID: "web-01", AgentLabel: "web-01 (front)", AgentType: "rental", Collectors: collectors("web-01.example.net", "40%", 0.12)}, base); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(Record{AgentID: "web-02", AgentLabel: "web-02 (front)", AgentType: "rental", Collectors: collectors("web-02.example.net", "62%", 0.45)}, base.Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(Record{AgentID: "db-01", AgentLabel: "db-01 (batch)", AgentType: "vps", Collectors: collectors("db-01.example.net", "81%", 1.05)}, base.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func TestDashboardRendersRows(t *testing.T) {
	store, err := NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	seedThreeAgents(t, store, base)

	d, err := NewDashboard(store, Thresholds{Default: 15 * time.Minute}, BasicAuth{}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	d.SetNow(func() time.Time { return base.Add(time.Minute) })

	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()

	for _, want := range []string{
		"web-01 (front)", "web-02 (front)", "db-01 (batch)",
		"40%", "62%", "81%",
		"欠報", "生存",
		"2026-03-01 09:00:00",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard html does not contain %q", want)
		}
	}
	// 欠報の行が一番上に来る。
	iDown := strings.Index(body, "db-01 (batch)")
	iUp := strings.Index(body, "web-01 (front)")
	if iDown < 0 || iUp < 0 || iDown > iUp {
		t.Errorf("down row should be listed first (db-01=%d web-01=%d)", iDown, iUp)
	}
	// 外部 CDN を参照しない。
	for _, bad := range []string{"http://", "https://"} {
		if strings.Contains(body, bad) {
			t.Errorf("dashboard html references an external URL (%s)", bad)
		}
	}
}

func TestDashboardBuildPageOrdering(t *testing.T) {
	store, err := NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC)
	seedThreeAgents(t, store, base)
	if err := store.EnsureAgent("web-03", "never reported"); err != nil {
		t.Fatal(err)
	}

	d, err := NewDashboard(store, Thresholds{Default: 15 * time.Minute}, BasicAuth{}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	page := d.buildPage(base.Add(time.Minute))

	if page.TotalCount != 4 || page.DownCount != 1 {
		t.Fatalf("TotalCount=%d DownCount=%d, want 4/1", page.TotalCount, page.DownCount)
	}
	if page.Rows[0].AgentID != "db-01" || !page.Rows[0].Down {
		t.Fatalf("first row = %+v, want db-01 down", page.Rows[0])
	}
	if !page.Rows[1].Unknown || page.Rows[1].AgentID != "web-03" {
		t.Fatalf("second row = %+v, want web-03 unknown", page.Rows[1])
	}
	if page.Rows[1].LastSeen != "-" || page.Rows[1].Silence != "-" {
		t.Errorf("never-reported row should show dashes: %+v", page.Rows[1])
	}
	if page.Rows[2].AgentID != "web-02" {
		t.Errorf("third row = %s, want web-02 (longer silence first)", page.Rows[2].AgentID)
	}
}

func TestDashboardStaticCSS(t *testing.T) {
	store, err := NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDashboard(store, Thresholds{}, BasicAuth{}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/static/style.css", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "css") {
		t.Errorf("Content-Type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "heartpost monitor") {
		t.Errorf("css body looks wrong")
	}
}

func TestDashboardBasicAuth(t *testing.T) {
	store, err := NewStore(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDashboard(store, Thresholds{}, BasicAuth{User: "monitor", Password: "sample-password"}, time.UTC)
	if err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	d.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no credentials: status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("WWW-Authenticate header missing")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("monitor", "wrong")
	rec = httptest.NewRecorder()
	d.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: status = %d, want 401", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("monitor", "sample-password")
	rec = httptest.NewRecorder()
	d.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("correct credentials: status = %d, want 200", rec.Code)
	}
}

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{30 * time.Second, "30秒"},
		{5 * time.Minute, "5分"},
		{90 * time.Minute, "1時間30分"},
		{50 * time.Hour, "2日2時間"},
	}
	for _, c := range cases {
		if got := humanDuration(c.in); got != c.want {
			t.Errorf("humanDuration(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
