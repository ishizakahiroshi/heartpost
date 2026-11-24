// Package httpoutcome records trusted receipts of outbound HTTP calls that a
// producer makes on purpose (for example a WebDAV existence check). A receipt
// says which operation the call was and how its status should be read, so a
// consumer can tell an expected 405/404 from a real failure without guessing
// from the status code alone.
//
// The producer tags a request with WithOperation, wraps its transport with
// NewTransport and gives it a Sink. The transport adds a fresh random
// X-HTTP-Operation-ID header, which a reverse proxy can log, and appends one
// JSONL receipt after the response. When the caller cancels the request (its
// context is done) before a response arrives, the receipt carries status 499
// (StatusClientClosedRequest), the code a reverse proxy such as nginx logs for
// a client that went away. Other transport errors record nothing. Receipts
// never hold credentials, the raw path, the query or any body.
package httpoutcome

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// HeaderOperationID is the request header carrying the operation id.
const HeaderOperationID = "X-HTTP-Operation-ID"

// Allowed operation names.
const (
	OpEnsureCollection = "ensure_collection"
	OpPathExists       = "path_exists"
	OpFetchFile        = "fetch_file"
	OpPreviewFile      = "preview_file"
	// OpUploadFile is a single PUT of a whole file. With If-None-Match: * a 412
	// means the name is taken, which is part of reserving a free name.
	OpUploadFile = "upload_file"
	// OpUploadSession is the MKCOL that opens a chunked-upload session.
	OpUploadSession = "upload_session"
	// OpUploadChunk is one PUT of a chunk into an upload session.
	OpUploadChunk = "upload_chunk"
	// OpUploadAssemble is the MOVE that assembles an upload session into the
	// destination. With If-None-Match: * a 412 means the name is taken.
	OpUploadAssemble = "upload_assemble"
	// OpDeleteFile is a DELETE of a file; 404 means it is already gone.
	OpDeleteFile = "delete_file"
	// OpDeleteUploadSession is the DELETE that drops an upload session.
	OpDeleteUploadSession = "delete_upload_session"
	// OpFileID is a PROPFIND that reads the id of a file that should exist.
	OpFileID = "file_id"
	// OpListChildren is a PROPFIND that lists a folder that may not exist yet.
	OpListChildren = "list_children"
)

// StatusClientClosedRequest is recorded when the caller cancelled the request
// before a response arrived (nginx logs the same code for a client that left).
const StatusClientClosedRequest = 499

// operationMethods lists the methods each operation really uses. A receipt for
// another method is still written, but its non-2xx statuses classify as other.
var operationMethods = map[string][]string{
	OpEnsureCollection:    {"MKCOL"},
	OpPathExists:          {"PROPFIND"},
	OpFetchFile:           {"GET", "HEAD"},
	OpPreviewFile:         {"GET"},
	OpUploadFile:          {"PUT"},
	OpUploadSession:       {"MKCOL"},
	OpUploadChunk:         {"PUT"},
	OpUploadAssemble:      {"MOVE"},
	OpDeleteFile:          {"DELETE"},
	OpDeleteUploadSession: {"DELETE"},
	OpFileID:              {"PROPFIND"},
	OpListChildren:        {"PROPFIND"},
}

func operationUses(op, method string) bool {
	for _, m := range operationMethods[op] {
		if m == method {
			return true
		}
	}
	return false
}

// Outcome values.
const (
	OutcomeSuccess          = "success"
	OutcomeExpected         = "expected"
	OutcomeIntegrationError = "integration_error"
	OutcomeOther            = "other"
)

type ctxKey struct{}

func allowedOperation(op string) bool {
	_, ok := operationMethods[op]
	return ok
}

func allowedOutcome(o string) bool {
	switch o {
	case OutcomeSuccess, OutcomeExpected, OutcomeIntegrationError, OutcomeOther:
		return true
	}
	return false
}

// WithOperation marks requests made with the returned context as the given
// operation. Names outside the allowed set are ignored (ctx is returned as is).
func WithOperation(ctx context.Context, operation string) context.Context {
	if !allowedOperation(operation) {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, operation)
}

func operationFrom(ctx context.Context) (string, bool) {
	op, ok := ctx.Value(ctxKey{}).(string)
	if !ok || !allowedOperation(op) {
		return "", false
	}
	return op, true
}

// Receipt is one JSONL line.
type Receipt struct {
	TS        string `json:"ts"`
	RequestID string `json:"request_id"`
	Method    string `json:"method"`
	PathHash  string `json:"path_hash"`
	Status    int    `json:"status"`
	Operation string `json:"operation"`
	Outcome   string `json:"outcome"`
}

// Classify maps an operation, method and status to an outcome.
//
// A 499 (the caller cancelled before a response arrived) is expected for every
// operation used with its own method: the producer itself gave up, typically
// because its own client went away. Everything not listed is other.
func Classify(operation, method string, status int) string {
	if status >= 200 && status < 300 {
		return OutcomeSuccess
	}
	if !operationUses(operation, method) {
		return OutcomeOther
	}
	if status == StatusClientClosedRequest {
		return OutcomeExpected
	}
	switch operation {
	case OpEnsureCollection, OpUploadSession:
		if status == 405 { // the collection already exists
			return OutcomeExpected
		}
	case OpPathExists, OpListChildren:
		if status == 404 { // asking whether it exists is the point
			return OutcomeExpected
		}
	case OpFetchFile:
		if status == 404 || status == 423 { // missing or locked file
			return OutcomeIntegrationError
		}
	case OpPreviewFile, OpFileID:
		if status == 404 {
			return OutcomeIntegrationError
		}
	case OpUploadFile, OpUploadAssemble:
		switch status {
		case 412: // create-only and the name is taken
			return OutcomeExpected
		case 404, 409, 423: // parent missing, conflict or locked
			return OutcomeIntegrationError
		}
	case OpUploadChunk:
		if status == 404 || status == 423 {
			return OutcomeIntegrationError
		}
	case OpDeleteFile, OpDeleteUploadSession:
		if status == 404 { // already gone
			return OutcomeExpected
		}
	}
	return OutcomeOther
}

// PathHash returns the lowercase hex sha256 of an escaped URL path.
func PathHash(escapedPath string) string {
	sum := sha256.Sum256([]byte(escapedPath))
	return hex.EncodeToString(sum[:])
}

// NewOperationID returns a fresh 128-bit random id as lowercase hex32.
func NewOperationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

var (
	reHex32 = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reHex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// IsOperationID reports whether s is lowercase hex32.
func IsOperationID(s string) bool { return reHex32.MatchString(s) }

var receiptKeys = []string{"ts", "request_id", "method", "path_hash", "status", "operation", "outcome"}

// ParseReceiptLine strictly validates one JSONL line: exactly the receipt key
// set, well-formed values, and operation/outcome from the allowed sets.
func ParseReceiptLine(line []byte) (Receipt, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(line, &raw); err != nil {
		return Receipt{}, fmt.Errorf("not a json object: %w", err)
	}
	if len(raw) != len(receiptKeys) {
		return Receipt{}, fmt.Errorf("unexpected key set")
	}
	for _, k := range receiptKeys {
		if _, ok := raw[k]; !ok {
			return Receipt{}, fmt.Errorf("missing key %q", k)
		}
	}
	var r Receipt
	if err := json.Unmarshal(line, &r); err != nil {
		return Receipt{}, fmt.Errorf("bad value type: %w", err)
	}
	if err := ValidateReceipt(r); err != nil {
		return Receipt{}, err
	}
	return r, nil
}

// ValidateReceipt checks every field of a receipt against the allowed formats
// and sets (ts RFC3339, lowercase hex32 id, hex64 path hash, status 100-599,
// allowed operation and outcome).
func ValidateReceipt(r Receipt) error {
	if _, err := time.Parse(time.RFC3339, r.TS); err != nil {
		return fmt.Errorf("bad ts")
	}
	if !reHex32.MatchString(r.RequestID) {
		return fmt.Errorf("bad request_id")
	}
	if r.Method == "" || strings.TrimSpace(r.Method) != r.Method || len(r.Method) > 32 {
		return fmt.Errorf("bad method")
	}
	if !reHex64.MatchString(r.PathHash) {
		return fmt.Errorf("bad path_hash")
	}
	if r.Status < 100 || r.Status > 599 {
		return fmt.Errorf("bad status")
	}
	if !allowedOperation(r.Operation) {
		return fmt.Errorf("bad operation")
	}
	if !allowedOutcome(r.Outcome) {
		return fmt.Errorf("bad outcome")
	}
	return nil
}

// Sink receives receipts. Implementations must be safe for concurrent use.
type Sink interface {
	Record(Receipt) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(Receipt) error

// Record calls f.
func (f SinkFunc) Record(r Receipt) error { return f(r) }

// Transport is an http.RoundTripper that tags and records operations.
type Transport struct {
	base http.RoundTripper
	sink Sink
	// OnError is called when the sink fails. It never affects the request.
	OnError func(error)
}

// NewTransport wraps base (nil means http.DefaultTransport).
func NewTransport(base http.RoundTripper, sink Sink) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Transport{base: base, sink: sink}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	op, ok := operationFrom(req.Context())
	if !ok {
		return t.base.RoundTrip(req)
	}
	id, err := NewOperationID()
	if err != nil {
		// No trustworthy id: send the request untagged rather than fail it.
		t.report(err)
		return t.base.RoundTrip(req)
	}
	out := req.Clone(req.Context())
	out.Header.Del(HeaderOperationID)
	out.Header.Set(HeaderOperationID, id)

	resp, err := t.base.RoundTrip(out)
	if err != nil {
		// Only a request the caller cancelled is recorded (as 499). Any other
		// transport error leaves no receipt.
		if req.Context().Err() != nil {
			t.record(req, id, op, StatusClientClosedRequest)
		}
		return resp, err
	}
	t.record(req, id, op, resp.StatusCode)
	return resp, nil
}

func (t *Transport) record(req *http.Request, id, op string, status int) {
	if t.sink == nil {
		return
	}
	rec := Receipt{
		TS:        time.Now().UTC().Format(time.RFC3339),
		RequestID: id,
		Method:    req.Method,
		PathHash:  PathHash(req.URL.EscapedPath()),
		Status:    status,
		Operation: op,
		Outcome:   Classify(op, req.Method, status),
	}
	if werr := t.sink.Record(rec); werr != nil {
		t.report(werr)
	}
}

func (t *Transport) report(err error) {
	if t.OnError != nil {
		t.OnError(err)
	}
}
