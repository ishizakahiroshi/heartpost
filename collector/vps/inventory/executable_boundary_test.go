package inventory

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProcessExecutableIsNeverExecuted(t *testing.T) {
	for _, tc := range []struct {
		name, exe   string
		same, known bool
		want        string
	}{
		{"trusted-same-inode", "/synthetic/nginx", true, true, "1.26.3"},
		{"different-inode", "/synthetic/low-privilege/nginx", false, true, ""},
		{"deleted", "/synthetic/nginx (deleted)", true, true, ""},
		{"unknown-path", "/synthetic/nginx", false, false, ""},
		{"different-kind", "/synthetic/php", true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			a := filepath.Join(dir, "a")
			b := filepath.Join(dir, "b")
			for _, p := range []string{a, b} {
				if err := os.WriteFile(p, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			ai, _ := os.Stat(a)
			bi, _ := os.Stat(b)
			c := &Collector{
				lookPath: func(name string) (string, error) {
					if tc.known && name == "nginx" {
						return "/synthetic/path-nginx", nil
					}
					return "", exec.ErrNotFound
				},
				readDir:  func(string) ([]os.DirEntry, error) { return syntheticPIDs(1), nil },
				readlink: func(string) (string, error) { return tc.exe, nil },
				stat: func(p string) (os.FileInfo, error) {
					if strings.HasPrefix(p, "/proc/") && !tc.same {
						return bi, nil
					}
					return ai, nil
				},
			}
			var o Observation
			c.collectRuntimes(&o, func(name string, args ...string) ([]byte, error) {
				if strings.HasPrefix(name, "/proc/") {
					t.Fatalf("unsafe proc execution: %s %v", name, args)
				}
				if name != "/synthetic/path-nginx" {
					return nil, exec.ErrNotFound
				}
				return []byte("nginx version: nginx/1.26.3"), nil
			})
			items := o.Value.([]Runtime)
			r := items[len(items)-1]
			if r.Evidence != "proc_exe" || len(r.Processes) != 1 || r.Version != tc.want {
				t.Fatalf("process evidence lost: %+v", r)
			}
			if tc.want == "" && (o.Status != "partial" || r.Status != "error" || r.ErrorCode != "unverified_process_executable") {
				t.Fatalf("unknown executable claimed complete: %+v %+v", o, r)
			}
			if tc.want != "" && (o.Status != "ok" || r.Status != "ok") {
				t.Fatalf("trusted reuse failed: %+v", o)
			}
		})
	}
}

func TestDeniedPATHResolutionRemainsPartial(t *testing.T) {
	c := &Collector{
		lookPath: func(string) (string, error) { return "", os.ErrPermission },
		readDir:  func(string) ([]os.DirEntry, error) { return nil, nil },
	}
	var o Observation
	c.collectRuntimes(&o, func(string, ...string) ([]byte, error) { t.Fatal("executed denied PATH"); return nil, nil })
	if o.Status != "partial" {
		t.Fatalf("denied resolution became absence: %+v", o)
	}
	for _, r := range o.Value.([]Runtime) {
		if r.Status != "permission_denied" || r.ErrorCode != "permission_denied" {
			t.Fatalf("permission cause lost: %+v", r)
		}
	}
}
