//go:build !windows

package httpoutcome

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSinkCreatesMode0600(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "r.jsonl")
	s, err := NewFileSink(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
}

func TestFileSinkRefusesWritableFile(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "r.jsonl")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o620, 0o602, 0o666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := NewFileSink(path); err == nil {
			t.Fatalf("mode %o accepted", mode)
		}
	}
}

func TestFileSinkRefusesWritableParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSink(filepath.Join(dir, "r.jsonl")); err == nil {
		t.Fatal("group-writable parent accepted")
	}
}

// realTempDir returns t.TempDir() with symlinks resolved: on macOS the system
// temp dir sits under /var, a symlink to /private/var, which the production
// check correctly refuses.
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func ownerFixture(t *testing.T, mode os.FileMode) string {
	t.Helper()
	dir := realTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "r.jsonl")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func otherUID() uint32 { return uint32(os.Getuid()) + 12345 }

func TestOwnersAllowListIsExplicit(t *testing.T) {
	p := ownerFixture(t, 0o600)
	me := uint32(os.Getuid())
	if err := VerifyTrustedPathWithOwners(p, nil); err != nil {
		t.Fatalf("current user rejected: %v", err)
	}
	if err := VerifyTrustedPathWithOwners(p, []uint32{otherUID()}); err != nil {
		t.Fatalf("current user rejected when other listed: %v", err)
	}
	// Simulate a file owned by someone else: the current user is the owner, so
	// verify the decision function directly with a uid that is neither.
	if uidAllowed(otherUID(), nil, false) || uidAllowed(otherUID(), []uint32{me}, false) {
		t.Fatal("unlisted uid accepted")
	}
	if !uidAllowed(otherUID(), []uint32{otherUID()}, false) {
		t.Fatal("listed uid rejected")
	}
	if me != 0 && uidAllowed(0, nil, false) {
		t.Fatal("root trusted implicitly for files")
	}
	if !uidAllowed(0, nil, true) {
		t.Fatal("root should be allowed as an ancestor")
	}
}

func TestOwnersCheckOnOtherOwnersFile(t *testing.T) {
	// A file owned by another account: only runs when we are root and can chown.
	if os.Getuid() != 0 {
		t.Skip("needs root to chown")
	}
	p := ownerFixture(t, 0o600)
	if err := os.Chown(p, 4242, -1); err != nil {
		t.Skip(err)
	}
	if VerifyTrustedPathWithOwners(p, nil) == nil {
		t.Fatal("foreign owner accepted without list")
	}
	if err := VerifyTrustedPathWithOwners(p, []uint32{4242}); err != nil {
		t.Fatalf("listed owner rejected: %v", err)
	}
	if err := os.Chmod(p, 0o660); err != nil {
		t.Fatal(err)
	}
	if VerifyTrustedPathWithOwners(p, []uint32{4242}) == nil {
		t.Fatal("group-writable accepted despite owner listed")
	}
}

func TestOwnersGroupWritableFileRejected(t *testing.T) {
	p := ownerFixture(t, 0o620)
	if VerifyTrustedPathWithOwners(p, []uint32{uint32(os.Getuid())}) == nil {
		t.Fatal("group-writable accepted")
	}
}

func TestOwnersWritableParentRejected(t *testing.T) {
	p := ownerFixture(t, 0o600)
	if err := os.Chmod(filepath.Dir(p), 0o770); err != nil {
		t.Fatal(err)
	}
	if VerifyTrustedPathWithOwners(p, []uint32{uint32(os.Getuid())}) == nil {
		t.Fatal("writable parent accepted")
	}
}

func TestOwnersSymlinkAnywhereRejected(t *testing.T) {
	p := ownerFixture(t, 0o600)
	link := filepath.Join(realTempDir(t), "dirlink")
	if err := os.Symlink(filepath.Dir(p), link); err != nil {
		t.Fatal(err)
	}
	if VerifyTrustedPathWithOwners(filepath.Join(link, "r.jsonl"), nil) == nil {
		t.Fatal("symlinked parent accepted")
	}
	// A symlinked grandparent.
	gp := filepath.Join(realTempDir(t), "gplink")
	base := realTempDir(t)
	if err := os.Mkdir(filepath.Join(base, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "sub", "r.jsonl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, gp); err != nil {
		t.Fatal(err)
	}
	if VerifyTrustedPathWithOwners(filepath.Join(gp, "sub", "r.jsonl"), nil) == nil {
		t.Fatal("symlinked grandparent accepted")
	}
	flink := filepath.Join(filepath.Dir(p), "flink.jsonl")
	if err := os.Symlink(p, flink); err != nil {
		t.Fatal(err)
	}
	if VerifyTrustedPathWithOwners(flink, nil) == nil {
		t.Fatal("symlinked file accepted")
	}
}

func TestOwnersRelativePathRejected(t *testing.T) {
	if VerifyTrustedPathWithOwners("r.jsonl", nil) == nil {
		t.Fatal("relative accepted")
	}
}
