// Package inventory collects read-only configuration facts for later analysis.
// It does not decide whether a host is vulnerable or change the host.
package inventory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

const SchemaVersion = 1
const maxOutput = 8 << 20

// Observation never includes command stderr or environment values. Unknown
// provenance and package installation times are omitted, not guessed.
type Observation struct {
	Status     string `json:"status"`
	Source     string `json:"source"`
	ObservedAt string `json:"observed_at"`
	ErrorCode  string `json:"error_code,omitempty"`
	Value      any    `json:"value,omitempty"`
}
type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}
type Result struct {
	SchemaVersion    int         `json:"schema_version"`
	CollectorVersion string      `json:"collector_version"`
	ObservedAt       string      `json:"observed_at"`
	OS               Observation `json:"os"`
	Kernel           Observation `json:"kernel"`
	Packages         Observation `json:"packages"`
	Runtimes         Observation `json:"runtimes"`
	Containers       Observation `json:"containers"`
}

// Collector's zero value uses bounded local reads and commands. The command
// runner is private so configuration cannot introduce arbitrary shell commands.
type Collector struct {
	readFile func(string) ([]byte, error)
	run      func(string, ...string) ([]byte, error)
	now      func() time.Time
	goos     string
	readDir  func(string) ([]os.DirEntry, error)
	readlink func(string) (string, error)
	stat     func(string) (os.FileInfo, error)
	lookPath func(string) (string, error)
}

func (*Collector) Name() string { return "inventory" }

func (c *Collector) Collect(cfg vps.Config) (interface{}, error) {
	return c.CollectContext(context.Background(), cfg)
}

func (c *Collector) CollectContext(parent context.Context, _ vps.Config) (interface{}, error) {
	if err := parent.Err(); err != nil {
		return nil, err
	}
	read := c.readFile
	if read == nil {
		read = os.ReadFile
	}
	run := c.run
	if run == nil {
		// One budget covers all probes, including hosts with many runtimes.
		ctx, cancel := context.WithTimeout(parent, 25*time.Second)
		defer cancel()
		run = func(name string, args ...string) ([]byte, error) { return runCommandContext(ctx, name, args...) }
	}
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	at := now().UTC().Format(time.RFC3339Nano)
	goos := c.goos
	if goos == "" {
		goos = runtime.GOOS
	}
	r := &Result{SchemaVersion: SchemaVersion, CollectorVersion: "1", ObservedAt: at}
	r.OS = Observation{Source: "/etc/os-release", ObservedAt: at}
	r.Kernel = Observation{Source: "uname -r", ObservedAt: at}
	r.Packages = Observation{Source: "dpkg-query", ObservedAt: at}
	r.Runtimes = Observation{Source: "known binaries and /proc/*/exe", ObservedAt: at}
	r.Containers = Observation{Source: "docker formatted inspect", ObservedAt: at}
	if goos != "linux" {
		for _, o := range []*Observation{&r.OS, &r.Kernel, &r.Packages, &r.Runtimes, &r.Containers} {
			o.Status = "unsupported"
			o.ErrorCode = "unsupported_os"
		}
		return r, nil
	}
	data, err := read("/etc/os-release")
	if err != nil {
		fail(&r.OS, err)
	} else if value, ok := parseOS(data); ok {
		r.OS.Status = "ok"
		r.OS.Value = value
	} else {
		invalid(&r.OS)
	}
	data, err = run("uname", "-r")
	if err != nil {
		fail(&r.Kernel, err)
	} else if value := strings.TrimSpace(string(data)); value != "" && !strings.ContainsAny(value, "\r\n\x00") && len(value) < 256 {
		r.Kernel.Status = "ok"
		r.Kernel.Value = value
	} else {
		invalid(&r.Kernel)
	}
	data, err = run("dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n")
	if err != nil {
		fail(&r.Packages, err)
	} else if value, ok := parsePackages(data); ok {
		r.Packages.Status = "ok"
		r.Packages.Value = value
	} else {
		invalid(&r.Packages)
	}
	// These capabilities are independent: denied Docker access must not discard
	// the package snapshot, and a process probe failure must not mean no PHP.
	installed, _ := r.Packages.Value.([]Package)
	c.collectRuntimes(&r.Runtimes, run, installed)
	collectContainers(&r.Containers, run)
	// Measure nested, indented JSON as used by the agent, rather than compact
	// inventory JSON: indentation can add hundreds of kilobytes. Reserve at
	// least 256 KiB for the remaining collectors in the 1 MiB envelope.
	encodedSize := func() int {
		encoded, _ := json.MarshalIndent(map[string]any{"collectors": map[string]any{"inventory": r}}, "", "  ")
		return len(encoded) + 1024 // report identity and framing allowance
	}
	if encodedSize() > 768<<10 {
		r.Packages.Status = "error"
		r.Packages.ErrorCode = "report_size_limit"
		r.Packages.Value = nil
		if encodedSize() > 768<<10 {
			for _, o := range []*Observation{&r.Runtimes, &r.Containers} {
				o.Status = "error"
				o.ErrorCode = "report_size_limit"
				o.Value = nil
			}
		}
	}
	return r, nil
}
func invalid(o *Observation) { o.Status = "error"; o.ErrorCode = "invalid_output" }
func fail(o *Observation, err error) {
	o.Status, o.ErrorCode = "error", "command_failed"
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		o.ErrorCode = "timeout"
	case errors.Is(err, fs.ErrPermission):
		o.Status, o.ErrorCode = "permission_denied", "permission_denied"
	case errors.Is(err, exec.ErrNotFound), errors.Is(err, fs.ErrNotExist):
		o.Status, o.ErrorCode = "unavailable", "source_not_found"
	case errors.Is(err, errOutputLimit):
		o.ErrorCode = "output_limit"
	}
}

var errOutputLimit = errors.New("inventory output limit")

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxOutput {
		return 0, errOutputLimit
	}
	return b.Buffer.Write(p)
}
func runCommand(name string, args ...string) ([]byte, error) {
	return runCommandContext(context.Background(), name, args...)
}
func runCommandContext(parent context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var out boundedBuffer
	cmd.Stdout = &out
	// Some known version commands (nginx -v) use stderr. Keep bounded output
	// private and expose only parsed allowlisted fields or a safe error code.
	cmd.Stderr = &out
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		// Callers keep failed output private. Docker uses only known connection
		// failure phrases to produce a safe status, never raw stderr.
		return out.Bytes(), err
	}
	return out.Bytes(), nil
}
func parseOS(data []byte) (map[string]string, bool) {
	if len(data) > 64<<10 || bytes.IndexByte(data, 0) >= 0 {
		return nil, false
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch key {
		case "ID", "VERSION_ID", "ID_LIKE":
			value = strings.Trim(value, "\"'")
			if value == "" || strings.ContainsAny(value, "\\$`\r\x00") {
				return nil, false
			}
			out[key] = value
		}
	}
	return out, out["ID"] != ""
}
func parsePackages(data []byte) ([]Package, bool) {
	if len(data) > maxOutput || bytes.IndexByte(data, 0) >= 0 {
		return nil, false
	}
	// A final newline proves that the last record was not cut halfway through.
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return nil, false
	}
	out := []Package{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, false
		}
		if fields[3] != "installed" {
			switch fields[3] {
			case "not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending":
				continue
			}
			return nil, false
		}
		for i, value := range fields[:3] {
			if value == "" || len(value) > 512 {
				return nil, false
			}
			for _, ch := range value {
				valid := ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || strings.ContainsRune(".+-", ch)
				if i == 1 {
					valid = valid || ch >= 'A' && ch <= 'Z' || strings.ContainsRune(":~_", ch)
				}
				if !valid {
					return nil, false
				}
			}
		}
		key := fields[0] + ":" + fields[2]
		if seen[key] {
			return nil, false
		}
		seen[key] = true
		out = append(out, Package{Name: fields[0], Version: fields[1], Architecture: fields[2]})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Architecture < out[j].Architecture
		}
		return out[i].Name < out[j].Name
	})
	return out, true
}
