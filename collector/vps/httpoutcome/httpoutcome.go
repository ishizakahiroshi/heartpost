// Package httpoutcome (collector) ships the trusted receipts written by
// github.com/ishizakahiroshi/heartpost/httpoutcome. It reads the configured
// JSONL files, drops every line that fails strict validation and reports the
// rest as the "http_outcome" result of the signed report. It never writes to the
// receipt files.
package httpoutcome

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/ishizakahiroshi/heartpost/collector"
	"github.com/ishizakahiroshi/heartpost/collector/vps"
	hp "github.com/ishizakahiroshi/heartpost/httpoutcome"
)

// DefaultMaxLines caps how many lines are read per file per run when
// Rules.HTTPOutcomeLogLines is unset.
const DefaultMaxLines = 5000

// Collector implements vps.Collector.
type Collector struct {
	// Logf receives skip reasons. nil uses the standard logger.
	Logf func(format string, args ...any)
	// LookupUser resolves user names for HTTPOutcomeTrustedOwners. nil uses os/user.
	LookupUser func(name string) (*user.User, error)
}

// Name is the key used in [collectors.jobs] and in the report payload.
func (c *Collector) Name() string { return "http_outcome" }

// SkippedFile explains why a configured file was not read. Reasons contain no
// file contents.
type SkippedFile struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// CollectResult is the http_outcome payload.
type CollectResult struct {
	NewEvents int           `json:"new_events"`
	Dropped   int           `json:"dropped_invalid"`
	JsonlPath string        `json:"jsonl_path"`
	Skipped   []SkippedFile `json:"skipped,omitempty"`
	Events    []hp.Receipt  `json:"events,omitempty"`
}

func (c *Collector) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Collect reads each configured file (tail, capped), validates, de-duplicates by
// request_id and, like the nginx collector, remembers what it has already
// shipped in <DataDir>/logs/http_outcome.jsonl so a receipt is sent once.
func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	if len(cfg.Paths.HTTPOutcomeLogs) == 0 {
		return nil, nil
	}
	if cfg.Paths.DataDir == "" {
		return nil, fmt.Errorf("http_outcome: paths.data_dir is required")
	}
	jsonlPath := filepath.Join(cfg.Paths.DataDir, "logs", "http_outcome.jsonl")
	if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir logs: %w", err)
	}
	maxLines := cfg.Rules.HTTPOutcomeLogLines
	if maxLines <= 0 {
		maxLines = DefaultMaxLines
	}

	res := &CollectResult{JsonlPath: jsonlPath}
	dropped := 0
	tmpl := &collector.JSONLLogCollector[hp.Receipt]{
		JSONLPath: jsonlPath,
		ParseLine: func(line string) (hp.Receipt, bool) {
			r, err := hp.ParseReceiptLine([]byte(line))
			if err != nil {
				dropped++
				return hp.Receipt{}, false
			}
			return r, true
		},
		SeenKey: func(r hp.Receipt) string { return r.RequestID },
	}

	var owners []uint32
	ownersErr := false
	for _, name := range cfg.Paths.HTTPOutcomeTrustedOwners {
		uid, err := c.resolveOwner(name)
		if err != nil {
			c.logf("http_outcome: trusted owner %q cannot be resolved: %v", name, err)
			ownersErr = true
			continue
		}
		owners = append(owners, uid)
	}

	for _, p := range cfg.Paths.HTTPOutcomeLogs {
		if ownersErr {
			// An owner list that cannot be resolved is a configuration error;
			// reading files under a narrower rule than configured would hide it.
			res.Skipped = append(res.Skipped, SkippedFile{Path: p, Reason: "unknown trusted owner in configuration"})
			continue
		}
		var err error
		if len(owners) == 0 {
			err = hp.VerifyTrustedPath(p)
		} else {
			err = hp.VerifyTrustedPathWithOwners(p, owners)
		}
		if err != nil {
			reason := "untrusted or unreadable file"
			if os.IsNotExist(err) {
				reason = "file does not exist"
			} else if errors.Is(err, hp.ErrPathNotAbsolute) || errors.Is(err, hp.ErrPathNotClean) {
				reason = "path must be absolute and clean"
			}
			c.logf("http_outcome: skip %s: %s (%v)", p, reason, err)
			res.Skipped = append(res.Skipped, SkippedFile{Path: p, Reason: reason})
			continue
		}
		events, err := tmpl.Run(p, maxLines)
		if err != nil {
			c.logf("http_outcome: skip %s: read failed: %v", p, err)
			res.Skipped = append(res.Skipped, SkippedFile{Path: p, Reason: "read failed"})
			continue
		}
		res.Events = append(res.Events, events...)
	}
	res.NewEvents = len(res.Events)
	res.Dropped = dropped
	return res, nil
}

// resolveOwner turns a user name or a numeric uid into a uid.
func (c *Collector) resolveOwner(name string) (uint32, error) {
	if n, err := strconv.ParseUint(name, 10, 32); err == nil {
		return uint32(n), nil
	}
	lookup := c.LookupUser
	if lookup == nil {
		lookup = user.Lookup
	}
	u, err := lookup(name)
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("non-numeric uid")
	}
	return uint32(n), nil
}
