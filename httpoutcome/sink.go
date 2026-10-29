package httpoutcome

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FileSink appends receipts to a JSONL file. It is safe for concurrent use.
type FileSink struct {
	mu sync.Mutex
	f  *os.File
}

// NewFileSink opens (creating with mode 0600) path for append. The parent
// directory and the file must not be symlinks, must be owned by the current
// user and must not be group/world-writable (the owner and mode checks are
// skipped on Windows; the symlink check is not).
func NewFileSink(path string) (*FileSink, error) {
	if err := CheckAbsoluteClean(path); err != nil {
		return nil, err
	}
	if err := VerifyTrustedPath(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	// Re-verify what we actually opened (guards against a swap after the check).
	if err := verifyOpened(path, f); err != nil {
		f.Close()
		return nil, err
	}
	return &FileSink{f: f}, nil
}

// Record appends one receipt as a single write.
func (s *FileSink) Record(r Receipt) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("sink closed")
	}
	_, err = s.f.Write(b)
	return err
}

// Close closes the file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

// VerifyTrustedPath checks the parent directory and the file at path with the
// same rules NewFileSink applies. It returns an error wrapping os.ErrNotExist
// when only the file is missing. Collectors use it before reading a receipt file.
func VerifyTrustedPath(path string) error {
	if err := CheckAbsoluteClean(path); err != nil {
		return err
	}
	if err := verifyDir(filepath.Dir(path)); err != nil {
		return err
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return checkFileInfo(path, fi, false)
}

// CheckAbsoluteClean requires an absolute path that equals its cleaned form and
// has no ".." element. Receipt files are never resolved against the working directory.
func CheckAbsoluteClean(path string) error {
	if path == "" || !filepath.IsAbs(path) {
		return ErrPathNotAbsolute
	}
	if filepath.Clean(path) != path {
		return ErrPathNotClean
	}
	for _, el := range strings.Split(filepath.ToSlash(path), "/") {
		if el == ".." {
			return ErrPathNotClean
		}
	}
	return nil
}

// Path errors returned by CheckAbsoluteClean, NewFileSink and VerifyTrustedPath.
var (
	ErrPathNotAbsolute = errors.New("path must be absolute")
	ErrPathNotClean    = errors.New("path must be clean (no .., //, or trailing separator)")
)

func verifyDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("directory %s: %w", dir, err)
	}
	return checkFileInfo(dir, fi, true)
}

func verifyOpened(path string, f *os.File) error {
	lfi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	ofi, err := f.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(lfi, ofi) {
		return fmt.Errorf("%s changed while opening", path)
	}
	return checkFileInfo(path, lfi, false)
}

func checkFileInfo(path string, fi os.FileInfo, wantDir bool) error {
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink", path)
	}
	if wantDir && !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if !wantDir && !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return checkOwnerAndMode(path, fi)
}
