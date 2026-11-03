package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

func TestInventoryHonorsCanceledRun(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &Collector{goos: "linux", readFile: func(string) ([]byte, error) { t.Fatal("read after cancellation"); return nil, nil }}
	if _, err := c.CollectContext(ctx, vps.Config{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled run was accepted: %v", err)
	}
}

func TestSnapshotPreservesPackageVersionsAndSeparatesFailures(t *testing.T) {
	c := &Collector{goos: "linux", now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		readFile: func(path string) ([]byte, error) {
			if path != "/etc/os-release" {
				t.Fatal(path)
			}
			return []byte("ID=debian\nVERSION_ID=13\nSECRET=synthetic-secret\n"), nil
		},
		run: func(name string, args ...string) ([]byte, error) {
			switch name {
			case "uname":
				return []byte("6.1-fixture\n"), nil
			case "dpkg-query":
				if !reflect.DeepEqual(args, []string{"-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"}) {
					t.Fatalf("unexpected query: %q", args)
				}
				return []byte("zlib1g\t1:1.3.dfsg-2+deb13u1\tamd64\tinstalled\nold\t1\tamd64\tconfig-files\nalpha\t2.0~rc1-1\tall\tinstalled\n"), nil
			}
			return nil, exec.ErrNotFound
		}}
	v, err := c.Collect(vps.Config{})
	if err != nil {
		t.Fatal(err)
	}
	r := v.(*Result)
	if r.OS.Status != "ok" || r.Kernel.Status != "ok" || r.Packages.Status != "ok" {
		t.Fatalf("snapshot: %+v", r)
	}
	packages := r.Packages.Value.([]Package)
	if len(packages) != 2 || packages[0].Name != "alpha" || packages[1].Version != "1:1.3.dfsg-2+deb13u1" {
		t.Fatalf("packages: %+v", packages)
	}
	if r.Packages.ObservedAt != r.ObservedAt || r.SchemaVersion != 1 {
		t.Fatal("metadata lost")
	}
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "synthetic-secret") {
		t.Fatal("non-allowlisted OS field leaked")
	}
}
func TestSourceFailuresRemainExplicitAndDoNotLeakErrors(t *testing.T) {
	for _, tc := range []struct {
		err          error
		status, code string
	}{
		{context.DeadlineExceeded, "error", "timeout"},
		{fs.ErrPermission, "permission_denied", "permission_denied"},
		{exec.ErrNotFound, "unavailable", "source_not_found"},
		{errors.New("synthetic-secret stderr"), "error", "command_failed"},
	} {
		c := &Collector{goos: "linux", readFile: func(string) ([]byte, error) { return nil, tc.err }, run: func(string, ...string) ([]byte, error) { return nil, tc.err }}
		v, _ := c.Collect(vps.Config{})
		r := v.(*Result)
		for _, o := range []Observation{r.OS, r.Kernel, r.Packages} {
			if o.Status != tc.status || o.ErrorCode != tc.code || o.Value != nil {
				t.Fatalf("got %+v", o)
			}
		}
		data, _ := json.Marshal(r)
		if strings.Contains(string(data), "synthetic-secret") {
			t.Fatal("error leaked")
		}
	}
}
func TestMalformedPackagesNeverBecomeCompleteInventory(t *testing.T) {
	for _, data := range []string{"alpha\t1\tamd64\tinstalled", "alpha\t1\tamd64\tinstalled\nsecret", "alpha\t1\tamd64\tunknown\n", "alpha\t\tamd64\tinstalled\n", "alpha\t1\tamd64\tinstalled\nalpha\t1\tamd64\tinstalled\n", strings.Repeat("x", maxOutput+1)} {
		if _, ok := parsePackages([]byte(data)); ok {
			t.Fatal("accepted invalid/truncated inventory")
		}
	}
	if got, ok := parsePackages(nil); !ok || got == nil || len(got) != 0 {
		t.Fatal("valid empty result must be an array")
	}
}
func TestUnsupportedDoesNotExecute(t *testing.T) {
	c := &Collector{goos: "freebsd", readFile: func(string) ([]byte, error) { t.Fatal("read on unsupported OS"); return nil, nil }, run: func(string, ...string) ([]byte, error) { t.Fatal("execute on unsupported OS"); return nil, nil }}
	v, _ := c.Collect(vps.Config{})
	r := v.(*Result)
	if r.OS.Status != "unsupported" || r.Packages.Status != "unsupported" {
		t.Fatal("unsupported became success")
	}
}
