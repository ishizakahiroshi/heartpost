package inventory

import (
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunningAndPATHVersionsStaySeparate(t *testing.T) {
	dir := t.TempDir()
	for _, pid := range []string{"11", "12", "13"} {
		if err := os.WriteFile(filepath.Join(dir, pid), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := &Collector{readDir: func(string) ([]os.DirEntry, error) { return os.ReadDir(dir) }, readlink: func(path string) (string, error) {
		if strings.Contains(path, "13") {
			return "", fs.ErrPermission
		}
		return "/usr/sbin/php-fpm8.4 (deleted)", nil
	}, stat: func(string) (os.FileInfo, error) { return os.Stat(filepath.Join(dir, "11")) }}
	var o Observation
	c.collectRuntimes(&o, func(name string, args ...string) ([]byte, error) {
		if name == "php" {
			return []byte("PHP 8.3.1 (cli)\nsynthetic-secret"), nil
		}
		if strings.HasPrefix(name, "/proc/") {
			return []byte("PHP 8.4.2 (fpm-fcgi)\n"), nil
		}
		return nil, exec.ErrNotFound
	})
	if o.Status != "partial" || o.ErrorCode != "process_visibility_limited" {
		t.Fatalf("visibility: %+v", o)
	}
	items := o.Value.([]Runtime)
	last := items[len(items)-1]
	if items[0].Version != "8.3.1" || last.Version != "8.4.2" || !last.Deleted || last.Kind != "php-fpm" || len(last.Processes) != 2 {
		t.Fatalf("binary evidence lost: %+v", items)
	}
	data, _ := json.Marshal(o)
	if strings.Contains(string(data), "synthetic-secret") {
		t.Fatal("raw version output leaked")
	}
}

func TestRunningProcessesWithSamePathAndDifferentExecutables(t *testing.T) {
	dir := t.TempDir()
	for _, pid := range []string{"11", "12"} {
		if err := os.WriteFile(filepath.Join(dir, pid), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	c := &Collector{
		readDir:  func(string) ([]os.DirEntry, error) { return os.ReadDir(dir) },
		readlink: func(string) (string, error) { return "/usr/sbin/php-fpm8.4 (deleted)", nil },
		stat:     func(p string) (os.FileInfo, error) { return os.Stat(filepath.Join(dir, strings.Split(p, "/")[2])) },
	}
	var o Observation
	c.collectRuntimes(&o, func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "/proc/11/exe":
			return []byte("PHP 8.4.1 (fpm-fcgi)"), nil
		case "/proc/12/exe":
			return []byte("PHP 8.4.2 (fpm-fcgi)"), nil
		default:
			return nil, exec.ErrNotFound
		}
	})
	items := o.Value.([]Runtime)
	if o.Status != "ok" || len(items) != 10 || items[8].Version != "8.4.1" || items[9].Version != "8.4.2" {
		t.Fatalf("distinct executables collapsed: %+v", items)
	}
}

func TestRuntimeBannerValidation(t *testing.T) {
	for _, tc := range []struct{ kind, banner, version string }{
		{"nginx", "nginx version: nginx/1.26.3", "1.26.3"},
		{"mariadb", "/usr/sbin/mariadbd  Ver 10.11.11-MariaDB for debian-linux-gnu", "10.11.11-MariaDB"},
		{"mysql", "mysqld  Ver 8.4.2 for Linux", "8.4.2"},
		{"redis", "Redis server v=7.4.1 sha=fixture malloc=jemalloc", "7.4.1"},
		{"apache", "Server version: Apache/2.4.63 (Unix)", "2.4.63"},
		{"php-cli", "warning at line 8.4", ""},
	} {
		v, status, _ := probeVersion(func(string, ...string) ([]byte, error) { return []byte(tc.banner), nil }, "/proc/11/exe", tc.kind)
		if v != tc.version || (status == "ok") != (tc.version != "") {
			t.Fatalf("kind=%s version=%s status=%s", tc.kind, v, status)
		}
	}
}

func TestFailedPathProbeIsNotAnInstalledRuntimeRemoval(t *testing.T) {
	dir := t.TempDir()
	c := &Collector{readDir: func(string) ([]os.DirEntry, error) { return os.ReadDir(dir) }}
	var o Observation
	c.collectRuntimes(&o, func(name string, _ ...string) ([]byte, error) {
		if name == "php" {
			return []byte("invalid banner"), nil
		}
		return nil, exec.ErrNotFound
	})
	if o.Status != "partial" || o.ErrorCode != "runtime_probe_failed" {
		t.Fatalf("failed path probe became an absence: %+v", o)
	}
}

func TestDockerFormattedAllowlistAndDigest(t *testing.T) {
	id := strings.Repeat("a", 64)
	image := "sha256:" + strings.Repeat("b", 64)
	digest := "example.com/sample@sha256:" + strings.Repeat("c", 64)
	var o Observation
	collectContainers(&o, func(name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatal(name)
		}
		switch args[0] {
		case "ps":
			return []byte(id + "\n"), nil
		case "inspect":
			if !strings.Contains(strings.Join(args, " "), "{{.Id}}\t{{.Image}}\t{{.State.Status}}") {
				t.Fatal("unbounded container inspect")
			}
			return []byte(id + "\t" + image + "\trunning\n"), nil
		case "image":
			return []byte(image + "\t[\"" + digest + "\"]\n"), nil
		}
		t.Fatal(args)
		return nil, nil
	})
	if o.Status != "ok" {
		t.Fatalf("status: %+v", o)
	}
	items := o.Value.([]Container)
	if len(items) != 1 || items[0].DigestStatus != "ok" || items[0].Digests[0] != digest {
		t.Fatalf("containers: %+v", items)
	}
}

func TestDockerFailureAndMissingDigestAreNotAbsence(t *testing.T) {
	var o Observation
	collectContainers(&o, func(string, ...string) ([]byte, error) { return nil, fs.ErrPermission })
	if o.Status != "permission_denied" || o.Value != nil {
		t.Fatal("denial became empty containers")
	}
	collectContainers(&o, func(string, ...string) ([]byte, error) { return []byte("not-a-container-id synthetic-secret"), nil })
	if o.Status != "error" {
		t.Fatal("bad output accepted")
	}
	id := strings.Repeat("a", 64)
	image := "sha256:" + strings.Repeat("b", 64)
	o = Observation{}
	collectContainers(&o, func(_ string, args ...string) ([]byte, error) {
		switch args[0] {
		case "ps":
			return []byte(id), nil
		case "inspect":
			return []byte(id + "\t" + image + "\trunning"), nil
		default:
			return nil, exec.ErrNotFound
		}
	})
	if o.Status != "partial" || o.Value.([]Container)[0].DigestStatus != "unavailable" {
		t.Fatal("missing image evidence became success")
	}
}
