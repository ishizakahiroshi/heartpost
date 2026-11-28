package inventory

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/ishizakahiroshi/heartpost/collector/vps"
)

func TestPackageSourceOptIn(t *testing.T) {
	const binary = "sample-cli\t2:1.4~rc1-3+b2\tamd64\tinstalled"
	const source = "sample-suite\t2:1.4~rc1-3"
	for _, tc := range []struct {
		name                                      string
		enable                                    bool
		row, status, sourcePackage, sourceVersion string
	}{
		{"default binary only", false, binary, "ok", "", ""},
		{"different binary and source revision", true, binary + "\t" + source, "ok", "sample-suite", "2:1.4~rc1-3"},
		{"dpkg reports identical identities", true, binary + "\tsample-cli\t2:1.4~rc1-3+b2", "ok", "sample-cli", "2:1.4~rc1-3+b2"},
		{"missing source", true, binary + "\t\t", "partial", "", ""},
		{"invalid source version", true, binary + "\tsample-suite\tinvalid value", "partial", "sample-suite", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			queries := 0
			c := &Collector{
				IncludePackageSources: tc.enable,
				goos:                  "linux",
				readFile:              func(string) ([]byte, error) { return []byte("ID=ubuntu\n"), nil },
				readDir:               func(string) ([]os.DirEntry, error) { return nil, nil },
				lookPath:              func(string) (string, error) { return "", exec.ErrNotFound },
				run: func(name string, args ...string) ([]byte, error) {
					switch name {
					case "uname":
						return []byte("fixture\n"), nil
					case "dpkg-query":
						queries++
						const base = "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}"
						want := base
						if tc.enable {
							want += "\t${source:Package}\t${source:Version}"
						}
						if len(args) != 2 || args[0] != "-W" || args[1] != want+"\n" {
							t.Fatalf("unexpected dpkg-query args %q", args)
						}
						return []byte(tc.row + "\n"), nil
					default:
						return nil, exec.ErrNotFound
					}
				},
			}
			value, err := c.Collect(vps.Config{})
			if err != nil {
				t.Fatal(err)
			}
			o := value.(*Result).Packages
			items := o.Value.([]Package)
			if queries != 1 || len(items) != 1 || o.Status != tc.status || (o.ErrorCode == "package_source_unavailable") != (tc.status == "partial") {
				t.Fatalf("queries=%d observation=%+v", queries, o)
			}
			got := items[0]
			if got.Name != "sample-cli" || got.Version != "2:1.4~rc1-3+b2" || got.Architecture != "amd64" || got.SourcePackage != tc.sourcePackage || got.SourceVersion != tc.sourceVersion {
				t.Fatalf("unexpected package: %+v", got)
			}
			wire, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var old struct{ Name, Version, Architecture string }
			if err := json.Unmarshal(wire, &old); err != nil || old.Name != got.Name || old.Version != got.Version || old.Architecture != got.Architecture {
				t.Fatalf("legacy decoder: %+v, err=%v", old, err)
			}
			if strings.Contains(string(wire), `"source_package"`) != (tc.sourcePackage != "") || strings.Contains(string(wire), `"source_version"`) != (tc.sourceVersion != "") {
				t.Fatalf("wire fields: %s", wire)
			}
		})
	}
}
