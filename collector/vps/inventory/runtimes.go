package inventory

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Bound local /proc work separately from the 25-second command budget. A
// 4096-entry scan covers small VPS fleets without reading the whole directory
// on a high-process host. Keep at most 128 PID examples per executable; even
// the existing 128-executable limit must not create an unbounded PID report.
const maxRuntimeProcEntries = 4096
const maxRuntimeProcesses = 128

func readRuntimeProcEntries(dir string) ([]os.DirEntry, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	// One lookahead entry distinguishes an exact-boundary directory from a
	// truncated one, without os.ReadDir's allocation of every directory entry.
	entries, err := f.ReadDir(maxRuntimeProcEntries + 1)
	if errors.Is(err, io.EOF) {
		err = nil
	}
	return entries, err
}

// Runtime describes a binary, not its configuration, arguments or environment.
// A running binary can serve multiple pools/vhosts: these are not inferred.
type Runtime struct {
	Kind      string `json:"kind"`
	Binary    string `json:"binary"`
	Evidence  string `json:"evidence"`
	Version   string `json:"version,omitempty"`
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	Processes []int  `json:"processes,omitempty"`
	Deleted   bool   `json:"deleted,omitempty"`
}

var runtimeNames = regexp.MustCompile(`^(php(?:[0-9]+\.[0-9]+)?|php-fpm(?:[0-9]+\.[0-9]+)?|nginx|apache2|httpd|mariadbd|mysqld|redis-server)$`)
var phpPackageName = regexp.MustCompile(`^php([0-9]+\.[0-9]+)-(cli|fpm)$`)
var versionNumber = regexp.MustCompile(`\b[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:[-+~._][a-zA-Z0-9.+~_-]+)?`)

func runtimeKind(name string) string {
	if !runtimeNames.MatchString(name) {
		return ""
	}
	switch {
	case strings.HasPrefix(name, "php-fpm"):
		return "php-fpm"
	case strings.HasPrefix(name, "php"):
		return "php-cli"
	case name == "apache2" || name == "httpd":
		return "apache"
	case name == "mariadbd":
		return "mariadb"
	case name == "mysqld":
		return "mysql"
	case name == "redis-server":
		return "redis"
	default:
		return name
	}
}

func probeVersion(run func(string, ...string) ([]byte, error), binary, kind string) (string, string, string) {
	arg := "--version"
	if kind == "apache" || kind == "nginx" {
		arg = "-v"
	}
	data, err := run(binary, arg)
	if err != nil {
		var o Observation
		fail(&o, err)
		return "", o.Status, o.ErrorCode
	}
	// Require an expected banner, never mistake a warning's line number for a version.
	text := strings.TrimSpace(string(data))
	if kind == "mariadb" || kind == "mysql" {
		banner := regexp.MustCompile(`^(?:/[a-zA-Z0-9._/-]+/)?(?:mariadbd|mysqld)\s+Ver\s+`)
		if prefix := banner.FindString(text); prefix != "" {
			if v := versionNumber.FindString(strings.TrimPrefix(text, prefix)); v != "" {
				return v, "ok", ""
			}
		}
		return "", "error", "invalid_output"
	}
	prefixes := map[string][]string{"php-cli": {"PHP "}, "php-fpm": {"PHP "}, "nginx": {"nginx version: nginx/"}, "apache": {"Server version: Apache/"}, "mariadb": {"mariadbd ", "mysqld ", binary + " "}, "mysql": {"mysqld ", binary + " "}, "redis": {"Redis server "}}
	for _, prefix := range prefixes[kind] {
		if strings.HasPrefix(text, prefix) {
			if kind == "redis" {
				if _, rest, ok := strings.Cut(text, "v="); ok {
					text = rest
				}
			}
			if v := versionNumber.FindString(strings.TrimPrefix(text, prefix)); v != "" {
				return v, "ok", ""
			}
		}
	}
	return "", "error", "invalid_output"
}

func runtimeCandidates(installed ...[]Package) ([]string, bool) {
	names := []string{"php", "php-fpm", "nginx", "apache2", "httpd", "mariadbd", "mysqld", "redis-server"}
	versioned := map[string]bool{}
	for _, packages := range installed {
		for _, pkg := range packages {
			match := phpPackageName.FindStringSubmatch(pkg.Name)
			if match == nil {
				continue
			}
			name := "php" + match[1]
			if match[2] == "fpm" {
				name = "php-fpm" + match[1]
			}
			versioned[name] = true
		}
	}
	extra := make([]string, 0, len(versioned))
	for name := range versioned {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	limited := len(extra) > 32
	if limited {
		extra = extra[:32]
	}
	return append(names, extra...), limited
}

func (c *Collector) collectRuntimes(o *Observation, run func(string, ...string) ([]byte, error), installed ...[]Package) {
	readDir := c.readDir
	if readDir == nil {
		readDir = readRuntimeProcEntries
	}
	readlink := c.readlink
	if readlink == nil {
		readlink = os.Readlink
	}
	stat := c.stat
	if stat == nil {
		stat = os.Stat
	}
	items := []Runtime{}
	lookPath := c.lookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	type trustedProbe struct {
		file          os.FileInfo
		kind, version string
	}
	trusted := []trustedProbe{}
	// PATH discoveries are deliberately separate from running-process evidence.
	names, limited := runtimeCandidates(installed...)
	if limited {
		o.Status, o.ErrorCode = "partial", "runtime_discovery_limit"
	}
	for _, name := range names {
		kind := runtimeKind(name)
		// Execute only the explicit PATH probe. Process names must never grant
		// permission to execute a lower-privilege process's /proc executable.
		binary, resolveErr := lookPath(name)
		if resolveErr != nil {
			var unavailable Observation
			fail(&unavailable, resolveErr)
			items = append(items, Runtime{Kind: kind, Binary: name, Evidence: "path_probe", Status: unavailable.Status, ErrorCode: unavailable.ErrorCode})
			continue
		}
		before, beforeErr := stat(binary)
		v, status, code := probeVersion(run, binary, kind)
		after, afterErr := stat(binary)
		if status == "ok" && beforeErr == nil && afterErr == nil && os.SameFile(before, after) {
			trusted = append(trusted, trustedProbe{file: after, kind: kind, version: v})
		}
		items = append(items, Runtime{Kind: kind, Binary: name, Evidence: "path_probe", Version: v, Status: status, ErrorCode: code})
	}
	entries, err := readDir("/proc")
	if err != nil {
		fail(o, err)
		o.Value = items
		return
	}
	if len(entries) > maxRuntimeProcEntries {
		entries = entries[:maxRuntimeProcEntries]
		o.Status, o.ErrorCode = "partial", "process_scan_limit"
	}
	type processBinary struct {
		file    os.FileInfo
		runtime *Runtime
	}
	byBinary := map[string][]processBinary{}
	instances := 0
	denied := false
	identityUnknown := false
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		exe, err := readlink(path.Join("/proc", entry.Name(), "exe"))
		if err != nil {
			// Vanished processes are normal; permission failures leave coverage incomplete.
			if os.IsPermission(err) {
				denied = true
			}
			continue
		}
		deleted := strings.HasSuffix(exe, " (deleted)")
		clean := strings.TrimSuffix(exe, " (deleted)")
		kind := runtimeKind(path.Base(clean))
		if kind == "" {
			continue
		}
		key := clean
		if deleted {
			key += " (deleted)"
		}
		procExe := path.Join("/proc", entry.Name(), "exe")
		info, err := stat(procExe)
		if err != nil {
			// Never assume two processes run the same inode from their path alone.
			identityUnknown = true
			continue
		}
		matched := false
		for _, previous := range byBinary[key] {
			if os.SameFile(previous.file, info) {
				if len(previous.runtime.Processes) < maxRuntimeProcesses {
					previous.runtime.Processes = append(previous.runtime.Processes, pid)
				} else {
					o.Status = "partial"
					if o.ErrorCode == "" {
						o.ErrorCode = "runtime_process_limit"
					}
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if instances >= 128 {
			o.Status = "partial"
			o.ErrorCode = "process_limit"
			break
		}
		r := &Runtime{Kind: kind, Binary: clean, Evidence: "proc_exe", Processes: []int{pid}, Deleted: deleted}
		// Reuse only an already-observed PATH version for the same inode/kind.
		// Unknown and deleted process executables remain visible but unexecuted.
		r.Status, r.ErrorCode = "error", "unverified_process_executable"
		if !deleted {
			for _, probe := range trusted {
				if probe.kind == kind && os.SameFile(probe.file, info) {
					r.Version, r.Status, r.ErrorCode = probe.version, "ok", ""
					break
				}
			}
		}
		byBinary[key] = append(byBinary[key], processBinary{file: info, runtime: r})
		instances++
	}
	keys := make([]string, 0, len(byBinary))
	for key := range byBinary {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, binary := range byBinary[key] {
			r := binary.runtime
			sort.Ints(r.Processes)
			items = append(items, *r)
		}
	}
	if o.Status == "" {
		o.Status = "ok"
	}
	if denied {
		o.Status = "partial"
		o.ErrorCode = "process_visibility_limited"
	}
	if identityUnknown {
		o.Status = "partial"
		if o.ErrorCode == "" {
			o.ErrorCode = "process_identity_unavailable"
		}
	}
	// Per-runtime failures remain explicit even when discovery itself succeeded.
	for _, r := range items {
		// A missing PATH executable is a valid absence, but a denied, timed-out
		// or malformed probe is unknown and must not erase a previously seen
		// installed runtime from the monitor's successful snapshot.
		failedPathProbe := r.Evidence == "path_probe" && r.Status != "ok" && r.Status != "unavailable"
		if (r.Evidence == "proc_exe" && r.Status != "ok") || failedPathProbe {
			o.Status = "partial"
			if o.ErrorCode == "" {
				o.ErrorCode = "runtime_probe_failed"
			}
		}
	}
	o.Value = items
}
