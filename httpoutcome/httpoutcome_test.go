package httpoutcome

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type memSink struct {
	mu   sync.Mutex
	recs []Receipt
	err  error
}

func (m *memSink) Record(r Receipt) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.recs = append(m.recs, r)
	return nil
}

type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(status int) rtFunc {
	return func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: status, Body: http.NoBody, Header: http.Header{}, Request: r}, nil
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		op, method string
		status     int
		want       string
	}{
		{OpEnsureCollection, "MKCOL", 201, OutcomeSuccess},
		{OpEnsureCollection, "MKCOL", 405, OutcomeExpected},
		{OpEnsureCollection, "MKCOL", 409, OutcomeOther},
		{OpEnsureCollection, "PUT", 405, OutcomeOther},
		{OpPathExists, "PROPFIND", 207, OutcomeSuccess},
		{OpPathExists, "PROPFIND", 404, OutcomeExpected},
		{OpPathExists, "PROPFIND", 500, OutcomeOther},
		{OpPathExists, "GET", 404, OutcomeOther},
		{OpFetchFile, "GET", 200, OutcomeSuccess},
		{OpFetchFile, "GET", 404, OutcomeIntegrationError},
		{OpFetchFile, "HEAD", 404, OutcomeIntegrationError},
		{OpFetchFile, "PROPFIND", 404, OutcomeOther},
		{OpPreviewFile, "GET", 404, OutcomeIntegrationError},
		{OpPreviewFile, "HEAD", 404, OutcomeOther},
		{OpPreviewFile, "GET", 403, OutcomeOther},
	}
	for _, c := range cases {
		if got := Classify(c.op, c.method, c.status); got != c.want {
			t.Errorf("Classify(%s,%s,%d)=%s want %s", c.op, c.method, c.status, got, c.want)
		}
	}
}

func newReq(t *testing.T, ctx context.Context, method, url string) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func TestRoundTripRecordsAndTags(t *testing.T) {
	sink := &memSink{}
	var seen *http.Request
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		seen = r
		return respond(405)(r)
	})
	tr := NewTransport(base, sink)
	ctx := WithOperation(context.Background(), OpEnsureCollection)
	req := newReq(t, ctx, "MKCOL", "https://dav.example.test/remote.php/a%20b/?token=secret")
	req.Header.Set("Authorization", "Bearer xyz")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if len(sink.recs) != 1 {
		t.Fatalf("records=%d", len(sink.recs))
	}
	r := sink.recs[0]
	if !IsOperationID(r.RequestID) || seen.Header.Get(HeaderOperationID) != r.RequestID {
		t.Fatalf("id mismatch: %q vs %q", r.RequestID, seen.Header.Get(HeaderOperationID))
	}
	if r.PathHash != PathHash("/remote.php/a%20b/") {
		t.Fatalf("path hash covers more than escaped path")
	}
	if r.Status != 405 || r.Outcome != OutcomeExpected || r.Operation != OpEnsureCollection || r.Method != "MKCOL" {
		t.Fatalf("bad receipt %+v", r)
	}
	// The line must round-trip through the strict parser.
	if _, err := ParseReceiptLine(mustJSON(t, r)); err != nil {
		t.Fatal(err)
	}
}

func TestHeaderSpoofOverwritten(t *testing.T) {
	sink := &memSink{}
	var got []string
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		got = r.Header.Values(HeaderOperationID)
		return respond(200)(r)
	})
	tr := NewTransport(base, sink)
	req := newReq(t, WithOperation(context.Background(), OpPathExists), "PROPFIND", "https://dav.example.test/x")
	req.Header.Add(HeaderOperationID, "00000000000000000000000000000000")
	req.Header.Add(HeaderOperationID, "second")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != sink.recs[0].RequestID || got[0] == "00000000000000000000000000000000" {
		t.Fatalf("header values %v, receipt %v", got, sink.recs[0].RequestID)
	}
}

func TestNoMutationOfCallerRequest(t *testing.T) {
	sink := &memSink{}
	tr := NewTransport(respond(200), sink)
	req := newReq(t, WithOperation(context.Background(), OpFetchFile), "GET", "https://dav.example.test/x")
	req.Header.Set(HeaderOperationID, "caller-value")
	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get(HeaderOperationID) != "caller-value" {
		t.Fatalf("caller request mutated: %q", req.Header.Get(HeaderOperationID))
	}
}

func TestUnknownOperationNoRecordNoHeader(t *testing.T) {
	sink := &memSink{}
	var hdr string
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		hdr = r.Header.Get(HeaderOperationID)
		return respond(200)(r)
	})
	tr := NewTransport(base, sink)
	for _, ctx := range []context.Context{
		context.Background(),
		WithOperation(context.Background(), "delete_everything"),
		WithOperation(context.Background(), ""),
	} {
		hdr = ""
		if _, err := tr.RoundTrip(newReq(t, ctx, "GET", "https://dav.example.test/x")); err != nil {
			t.Fatal(err)
		}
		if hdr != "" || len(sink.recs) != 0 {
			t.Fatalf("unexpected tagging/record: hdr=%q recs=%d", hdr, len(sink.recs))
		}
	}
}

func TestUnknownOperationStripsNothingButDoesNotAdd(t *testing.T) {
	// Without an allowed operation the request passes through untouched.
	var hdr string
	base := rtFunc(func(r *http.Request) (*http.Response, error) {
		hdr = r.Header.Get(HeaderOperationID)
		return respond(200)(r)
	})
	tr := NewTransport(base, &memSink{})
	req := newReq(t, context.Background(), "GET", "https://dav.example.test/x")
	req.Header.Set(HeaderOperationID, "caller")
	_, _ = tr.RoundTrip(req)
	if hdr != "caller" {
		t.Fatalf("pass-through changed header: %q", hdr)
	}
}

func TestTransportErrorRecordsNothing(t *testing.T) {
	sink := &memSink{}
	boom := errors.New("boom")
	tr := NewTransport(rtFunc(func(*http.Request) (*http.Response, error) { return nil, boom }), sink)
	req := newReq(t, WithOperation(context.Background(), OpFetchFile), "GET", "https://dav.example.test/x")
	if _, err := tr.RoundTrip(req); !errors.Is(err, boom) {
		t.Fatalf("err=%v", err)
	}
	if len(sink.recs) != 0 {
		t.Fatal("recorded on transport error")
	}
}

func TestSinkFailureNeverFailsRequest(t *testing.T) {
	sink := &memSink{err: errors.New("disk full")}
	tr := NewTransport(respond(200), sink)
	var reported error
	tr.OnError = func(err error) { reported = err }
	req := newReq(t, WithOperation(context.Background(), OpFetchFile), "GET", "https://dav.example.test/x")
	resp, err := tr.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("request failed: %v", err)
	}
	if reported == nil {
		t.Fatal("OnError not called")
	}
}

func TestNilBaseUsesDefaultTransport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values(HeaderOperationID)) != 1 {
			t.Errorf("server saw %v", r.Header.Values(HeaderOperationID))
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	sink := &memSink{}
	c := &http.Client{Transport: NewTransport(nil, sink)}
	req := newReq(t, WithOperation(context.Background(), OpPathExists), "PROPFIND", srv.URL+"/a")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(sink.recs) != 1 || sink.recs[0].Outcome != OutcomeExpected {
		t.Fatalf("%+v", sink.recs)
	}
}

func TestOperationIDsAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		id, err := NewOperationID()
		if err != nil || !IsOperationID(id) || seen[id] {
			t.Fatalf("bad or duplicate id %q %v", id, err)
		}
		seen[id] = true
	}
}

func TestParseReceiptLineRejects(t *testing.T) {
	good := `{"ts":"2026-01-02T03:04:05Z","request_id":"` + strings.Repeat("a", 32) + `","method":"GET","path_hash":"` + strings.Repeat("b", 64) + `","status":404,"operation":"fetch_file","outcome":"integration_error"}`
	if _, err := ParseReceiptLine([]byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"extra key":   strings.Replace(good, `"outcome"`, `"x":1,"outcome"`, 1),
		"missing key": strings.Replace(good, `"method":"GET",`, "", 1),
		"upper id":    strings.Replace(good, strings.Repeat("a", 32), strings.Repeat("A", 32), 1),
		"short hash":  strings.Replace(good, strings.Repeat("b", 64), strings.Repeat("b", 63), 1),
		"status 99":   strings.Replace(good, `404`, `99`, 1),
		"status 600":  strings.Replace(good, `404`, `600`, 1),
		"bad op":      strings.Replace(good, `fetch_file`, `other_op`, 1),
		"bad outcome": strings.Replace(good, `integration_error`, `fine`, 1),
		"bad ts":      strings.Replace(good, `2026-01-02T03:04:05Z`, `yesterday`, 1),
		"not json":    `nope`,
		"str status":  strings.Replace(good, `404`, `"404"`, 1),
	}
	for name, line := range bad {
		if _, err := ParseReceiptLine([]byte(line)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestFileSinkConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "receipts.jsonl")
	sink, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	const n = 200
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _ := NewOperationID()
			if err := sink.Record(Receipt{TS: "2026-01-02T03:04:05Z", RequestID: id, Method: "GET", PathHash: PathHash("/x"), Status: 200, Operation: OpFetchFile, Outcome: OutcomeSuccess}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		if _, err := ParseReceiptLine(sc.Bytes()); err != nil {
			t.Fatalf("line %d: %v", count, err)
		}
		count++
	}
	if count != n {
		t.Fatalf("lines=%d want %d", count, n)
	}
}

func TestFileSinkRefusesSymlinkFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	if _, err := NewFileSink(link); err == nil {
		t.Fatal("symlink file accepted")
	}
}

func TestFileSinkRefusesSymlinkParent(t *testing.T) {
	real := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "linkdir")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Skipf("symlink not available: %v", err)
	}
	if _, err := NewFileSink(filepath.Join(linkDir, "r.jsonl")); err == nil {
		t.Fatal("symlink parent accepted")
	}
}

func TestFileSinkRefusesNonRegular(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "afile")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSink(sub); err == nil {
		t.Fatal("directory accepted as sink file")
	}
}

func TestFileSinkMissingParent(t *testing.T) {
	if _, err := NewFileSink(filepath.Join(t.TempDir(), "nope", "r.jsonl")); err == nil {
		t.Fatal("missing parent accepted")
	}
}
