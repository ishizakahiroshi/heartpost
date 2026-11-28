package inventory

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
	"github.com/ishizakahiroshi/heartpost/report"
)

func TestLargeInventoryCannotOverflowExistingReportEnvelope(t *testing.T) {
	var packages strings.Builder
	for i := 0; i < 12000; i++ {
		fmt.Fprintf(&packages, "sample%05d\t1.0-%s\tamd64\tinstalled\n", i, strings.Repeat("x", 50))
	}
	dir := t.TempDir()
	c := &Collector{lookPath: func(name string) (string, error) { return name, nil }, goos: "linux", readFile: func(string) ([]byte, error) { return []byte("ID=debian\n"), nil }, readDir: func(string) ([]os.DirEntry, error) { return os.ReadDir(dir) }, run: func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "uname":
			return []byte("6.1-fixture"), nil
		case "dpkg-query":
			return []byte(packages.String()), nil
		default:
			return nil, exec.ErrNotFound
		}
	}}
	value, err := c.Collect(vps.Config{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := value.(*Result)
	if snapshot.Packages.Status != "error" || snapshot.Packages.ErrorCode != "report_size_limit" || snapshot.Packages.Value != nil || snapshot.Packages.OmittedItems != 12000 {
		t.Fatal("large snapshot became a partial successful package list")
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil || len(encoded) > 768<<10 {
		t.Fatal("snapshot exceeded report budget")
	}
}

func TestInventoryFitsIndentedReportEnvelope(t *testing.T) {
	var packages strings.Builder
	for i := 0; i < 6500; i++ {
		fmt.Fprintf(&packages, "sample%05d\t1.0-%s\tamd64\tinstalled\n", i, strings.Repeat("x", 50))
	}
	dir := t.TempDir()
	c := &Collector{lookPath: func(name string) (string, error) { return name, nil }, goos: "linux", readFile: func(string) ([]byte, error) { return []byte("ID=debian\n"), nil }, readDir: func(string) ([]os.DirEntry, error) { return os.ReadDir(dir) }, run: func(name string, _ ...string) ([]byte, error) {
		switch name {
		case "uname":
			return []byte("6.1-fixture"), nil
		case "dpkg-query":
			return []byte(packages.String()), nil
		default:
			return nil, exec.ErrNotFound
		}
	}}
	value, err := c.Collect(vps.Config{})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(value)
	body, err := json.MarshalIndent(report.Build("alpha-vps-fixture", "fixture", "vps", time.Now(), time.UTC, map[string]json.RawMessage{"inventory": raw}), "", "  ")
	if err != nil || len(body) > 768<<10 {
		t.Fatalf("indented inventory exhausted envelope budget: bytes=%d err=%v", len(body), err)
	}
}

func TestSizeLimitKeepsIndependentObservations(t *testing.T) {
	containers := make([]Container, 128)
	for i := range containers {
		containers[i] = Container{ID: fmt.Sprintf("%064x", i), ImageID: "sha256:" + strings.Repeat("a", 64), State: "running", DigestStatus: "ok"}
		if i == 0 {
			containers[i].DigestStatus = "unavailable"
			continue
		}
		for j := 0; j < 72; j++ {
			containers[i].Digests = append(containers[i].Digests, fmt.Sprintf("example.invalid/image-%03d@sha256:%064x", j, j))
		}
	}
	r := Result{
		Packages:   Observation{Status: "permission_denied", ErrorCode: "permission_denied"},
		Runtimes:   Observation{Status: "ok", Value: []Runtime{}},
		Containers: Observation{Status: "partial", ErrorCode: "image_digest_unavailable", Value: containers},
	}
	limitSnapshotSize(&r)
	if r.Packages.ErrorCode != "permission_denied" || r.Runtimes.Status != "ok" ||
		r.Containers.CollectionStatus != "partial" || r.Containers.CollectionErrorCode != "image_digest_unavailable" ||
		r.Containers.ErrorCode != "report_size_limit" || r.Containers.OmittedItems != len(containers) {
		t.Fatal("overflow must preserve independent evidence")
	}
}
