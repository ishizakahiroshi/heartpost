package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

func TestInstalledVersionedPHPDiscoveredWithoutProcessAccess(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/11", nil, 0600); err != nil {
		t.Fatal(err)
	}
	c := &Collector{lookPath: func(name string) (string, error) { return name, nil }, goos: "linux", readFile: func(string) ([]byte, error) { return []byte("ID=ubuntu\nVERSION_ID=24.04\n"), nil }, readDir: func(string) ([]os.DirEntry, error) { return os.ReadDir(dir) }, readlink: func(string) (string, error) { return "", os.ErrPermission }, run: func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "uname":
			return []byte("6.1-fixture"), nil
		case "dpkg-query":
			return []byte("php8.3-cli\t8.3.6-1\tamd64\tinstalled\nphp8.3-fpm\t8.3.6-1\tamd64\tinstalled\n"), nil
		case "php8.3":
			return []byte("PHP 8.3.6 (cli)"), nil
		case "php-fpm8.3":
			return []byte("PHP 8.3.6 (fpm-fcgi)"), nil
		default:
			return nil, exec.ErrNotFound
		}
	}}
	value, err := c.Collect(vps.Config{})
	if err != nil {
		t.Fatal(err)
	}
	o := value.(*Result).Runtimes
	if o.Status != "partial" || o.ErrorCode != "process_visibility_limited" {
		t.Fatalf("process coverage lost: %+v", o)
	}
	found := map[string]bool{}
	for _, r := range o.Value.([]Runtime) {
		if r.Binary == "php8.3" || r.Binary == "php-fpm8.3" {
			if r.Evidence != "path_probe" || r.Status != "ok" || r.Version != "8.3.6" || len(r.Processes) != 0 {
				t.Fatalf("installed runtime misrepresented: %+v", r)
			}
			found[r.Binary] = true
		}
	}
	if len(found) != 2 {
		t.Fatalf("versioned binaries not discovered: %+v", found)
	}
}

func TestDockerConnectionFailureClassifiedWithoutRawOutput(t *testing.T) {
	for _, tc := range []struct{ text, status, code string }{
		{"permission denied while trying to connect to the Docker daemon socket at unix:///run/docker.sock: synthetic-secret", "permission_denied", "permission_denied"},
		{"Cannot connect to the Docker daemon at unix:///run/docker.sock. Is the docker daemon running? synthetic-secret", "unavailable", "docker_daemon_unavailable"},
		{"unrelated synthetic-secret failure", "error", "command_failed"},
		{"an unrelated file reported permission denied synthetic-secret", "error", "command_failed"},
	} {
		var o Observation
		collectContainers(&o, func(string, ...string) ([]byte, error) { return []byte(tc.text), errors.New("exit status 1") })
		if o.Status != tc.status || o.ErrorCode != tc.code || o.Value != nil {
			t.Fatalf("status=%s code=%s", o.Status, o.ErrorCode)
		}
		data, err := json.Marshal(o)
		if err != nil || strings.Contains(string(data), "synthetic-secret") || strings.Contains(string(data), "docker.sock") {
			t.Fatal("raw daemon output escaped")
		}
	}
}

func TestVersionedRuntimeCandidatesAreBoundedAndAllowlisted(t *testing.T) {
	packages := []Package{{Name: "php8.3-fpm"}, {Name: "php8.3-fpm"}, {Name: "php8.3-cgi"}, {Name: "php8.3-fpm-extra"}, {Name: "php8.3-fpm;echo"}}
	names, limited := runtimeCandidates(packages)
	if limited || len(names) != 9 || names[8] != "php-fpm8.3" {
		t.Fatalf("candidate allowlist: %v %v", names, limited)
	}
	for i := 0; i < 40; i++ {
		packages = append(packages, Package{Name: fmt.Sprintf("php9.%d-fpm", i)})
	}
	names, limited = runtimeCandidates(packages)
	if !limited || len(names) != 40 {
		t.Fatalf("candidate budget: %d %v", len(names), limited)
	}
}

func TestFailedDockerStderrRemainsPrivateThroughCommandRunner(t *testing.T) {
	const helper = "HEARTPOST_SYNTHETIC_DOCKER_FAILURE"
	if os.Getenv(helper) == "1" {
		fmt.Fprintln(os.Stderr, "permission denied while trying to connect to the Docker daemon socket: synthetic-secret")
		os.Exit(1)
	}
	t.Setenv(helper, "1")
	var o Observation
	collectContainers(&o, func(string, ...string) ([]byte, error) {
		return runCommand(os.Args[0], "-test.run=^TestFailedDockerStderrRemainsPrivateThroughCommandRunner$")
	})
	if o.Status != "permission_denied" || o.ErrorCode != "permission_denied" || o.Value != nil {
		t.Fatalf("failed command classification: %+v", o)
	}
	data, _ := json.Marshal(o)
	if strings.Contains(string(data), "synthetic-secret") {
		t.Fatal("failed stderr escaped into observation")
	}
}
