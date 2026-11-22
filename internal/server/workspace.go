package server

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Limits of the workspace listing.
const (
	// maxListDepth is how many directory levels below the workspace root
	// the listing descends into.
	maxListDepth = 4
	// maxListFiles caps the number of files the listing returns.
	maxListFiles = 500
	// maxPathLen caps the length of a workspace-relative path.
	maxPathLen = 512
)

// skipDirs are directories the listing never enters (dot directories are
// skipped as well).
var skipDirs = map[string]bool{"node_modules": true, "vendor": true}

// errPathStatus pairs a path error with the HTTP status to answer with.
type errPathStatus struct {
	code int
	err  error
}

func (e *errPathStatus) Error() string { return e.err.Error() }
func (e *errPathStatus) Unwrap() error { return e.err }

// badPath returns a 400 error for an unacceptable workspace path.
func badPath(p, why string) error {
	return &errPathStatus{http.StatusBadRequest, fmt.Errorf("invalid path %q: %s", p, why)}
}

// windowsReserved are device names that Windows resolves in every
// directory, with any extension.
var windowsReserved = map[string]bool{
	"con": true, "prn": true, "aux": true, "nul": true, "conin$": true, "conout$": true,
	"com0": true, "com1": true, "com2": true, "com3": true, "com4": true, "com5": true, "com6": true, "com7": true, "com8": true, "com9": true,
	"lpt0": true, "lpt1": true, "lpt2": true, "lpt3": true, "lpt4": true, "lpt5": true, "lpt6": true, "lpt7": true, "lpt8": true, "lpt9": true,
	"com¹": true, "com²": true, "com³": true, "lpt¹": true, "lpt²": true, "lpt³": true,
}

// cleanPath checks a workspace-relative scenario path from a client: forward
// slashes only, relative, no "." or ".." segments, no dot files or
// directories, no drive letters, colons or backslashes, no Windows device
// names or trailing dots and spaces, no percent signs, and a .yaml or .yml
// extension. It
// returns the path unchanged when it is acceptable, so that the same file
// is never reachable under two spellings.
func cleanPath(p string) (string, error) {
	switch {
	case p == "":
		return "", badPath(p, "the path is empty")
	case len(p) > maxPathLen:
		return "", badPath(p[:32]+"...", fmt.Sprintf("longer than %d bytes", maxPathLen))
	case strings.ContainsAny(p, "\\:"):
		return "", badPath(p, `use a relative path with forward slashes (no \ or :)`)
	case strings.HasPrefix(p, "/"):
		return "", badPath(p, "absolute paths are not allowed; use a path relative to the workspace")
	}
	for i := 0; i < len(p); i++ {
		if c := p[i]; c < ' ' || c == 0x7f || strings.IndexByte(`*?"<>|%`, c) >= 0 {
			// % is refused so that no path looks like an encoded one.
			return "", badPath(p, `control characters and * ? " < > | % are not allowed`)
		}
	}
	segs := strings.Split(p, "/")
	for _, seg := range segs {
		switch {
		case seg == "":
			return "", badPath(p, "empty path segment")
		case seg == "." || seg == "..":
			return "", badPath(p, `"." and ".." are not allowed`)
		case strings.HasPrefix(seg, "."):
			return "", badPath(p, "dot files and directories are not accessible")
		case strings.HasSuffix(seg, ".") || strings.HasSuffix(seg, " ") || strings.HasPrefix(seg, " "):
			return "", badPath(p, "path segments must not start with a space or end with a dot or space")
		}
		base, _, _ := strings.Cut(seg, ".")
		if windowsReserved[strings.ToLower(strings.TrimRight(base, " "))] {
			return "", badPath(p, "Windows device names are not allowed")
		}
	}
	if !isScenarioFile(segs[len(segs)-1]) {
		return "", badPath(p, "only .yaml and .yml files are accessible")
	}
	if path.Clean(p) != p || !fs.ValidPath(p) {
		return "", badPath(p, "the path is not in canonical form")
	}
	return p, nil
}

// isScenarioFile reports whether name has a .yaml or .yml extension.
func isScenarioFile(name string) bool {
	ext := strings.ToLower(path.Ext(name))
	return (ext == ".yaml" || ext == ".yml") && len(name) > len(ext)
}

// statusOf returns the HTTP status for a workspace error.
func statusOf(err error) int {
	var ps *errPathStatus
	switch {
	case errors.As(err, &ps):
		return ps.code
	case errors.Is(err, fs.ErrNotExist):
		return http.StatusNotFound
	case errors.Is(err, fs.ErrExist):
		return http.StatusConflict
	case errors.Is(err, fs.ErrPermission):
		return http.StatusForbidden
	default:
		return http.StatusBadRequest
	}
}

// confined wraps an error of the os.Root, which refuses names that escape
// the workspace (through ".." or a symbolic link), in a message that does
// not reveal the resolved location.
func confined(p string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return &errPathStatus{http.StatusNotFound, fmt.Errorf("%s does not exist in the workspace", p)}
	}
	if errors.Is(err, fs.ErrExist) {
		return &errPathStatus{http.StatusConflict, fmt.Errorf("%s already exists in the workspace", p)}
	}
	var pe *fs.PathError
	if errors.As(err, &pe) && strings.Contains(pe.Err.Error(), "escapes") {
		return &errPathStatus{http.StatusForbidden, fmt.Errorf("%s leads outside the workspace", p)}
	}
	return &errPathStatus{http.StatusForbidden, fmt.Errorf("%s cannot be accessed: %v", p, unwrapPathError(err))}
}

// unwrapPathError drops the path from an fs.PathError, which would show the
// absolute location on disk.
func unwrapPathError(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// spellingBatch is how many directory entries lists reads at once.
const spellingBatch = 256

// checkPath checks a client path with cleanPath and then checkSpelling.
func (s *Server) checkPath(p string) (string, error) {
	p, err := cleanPath(p)
	if err != nil {
		return "", err
	}
	return p, s.checkSpelling(p)
}

// checkSpelling makes sure that every existing component of the clean path
// p has exactly the name its parent directory lists for it. Case-insensitive
// file systems (Windows, macOS) resolve SUB/OK.YAML to sub/ok.yaml, and NTFS
// resolves 8.3 short names such as GITHUB~1 to .github: without this check
// one file would be reachable under several spellings, and dot directories,
// which cleanPath refuses by name, through their short names. Components
// that do not exist yet are created as spelled, so they need no check.
func (s *Server) checkSpelling(p string) error {
	dir := "."
	for _, seg := range strings.Split(p, "/") {
		name := path.Join(dir, seg)
		if _, err := s.root.Lstat(name); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return confined(p, err)
		}
		listed, err := s.lists(dir, seg)
		if err != nil {
			return confined(p, err)
		}
		if !listed {
			return badPath(p, "use the names exactly as they are on disk (no short names, no other letter case)")
		}
		dir = name
	}
	return nil
}

// lists reports whether the workspace directory dir has an entry named
// exactly name.
func (s *Server) lists(dir, name string) (bool, error) {
	f, err := s.root.Open(dir)
	if err != nil {
		return false, err
	}
	defer f.Close()
	for {
		entries, err := f.ReadDir(spellingBatch)
		for _, e := range entries {
			if e.Name() == name {
				return true, nil
			}
		}
		switch {
		case errors.Is(err, io.EOF), err == nil && len(entries) == 0:
			return false, nil
		case err != nil:
			return false, err
		}
	}
}

// readFile reads a workspace scenario file after checking its path, its
// type and its size.
func (s *Server) readFile(p string) ([]byte, error) {
	p, err := s.checkPath(p)
	if err != nil {
		return nil, err
	}
	return s.readListed(p)
}

// readListed reads a scenario file whose clean path comes from a listing of
// the workspace, so that its spelling needs no check.
func (s *Server) readListed(p string) ([]byte, error) {
	f, err := s.root.Open(p)
	if err != nil {
		return nil, confined(p, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, confined(p, err)
	}
	if !fi.Mode().IsRegular() {
		return nil, &errPathStatus{http.StatusBadRequest, fmt.Errorf("%s is not a regular file", p)}
	}
	if fi.Size() > MaxFileBytes {
		return nil, &errPathStatus{http.StatusRequestEntityTooLarge, fmt.Errorf("%s is larger than %d KiB", p, MaxFileBytes>>10)}
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, confined(p, err)
	}
	if len(data) > MaxFileBytes {
		return nil, &errPathStatus{http.StatusRequestEntityTooLarge, fmt.Errorf("%s is larger than %d KiB", p, MaxFileBytes>>10)}
	}
	return data, nil
}

// writeFile writes data to a workspace scenario file, creating missing
// directories. The data goes to a temporary file in the same directory
// first, which then replaces the target, so that a reader never sees half a
// file. With exclusive set an existing file is not replaced.
func (s *Server) writeFile(p string, data []byte, exclusive bool) error {
	p, err := s.checkPath(p)
	if err != nil {
		return err
	}
	if len(data) > MaxFileBytes {
		return &errPathStatus{http.StatusRequestEntityTooLarge, fmt.Errorf("the content is larger than %d KiB", MaxFileBytes>>10)}
	}
	if dir := path.Dir(p); dir != "." {
		if err := s.root.MkdirAll(dir, 0o755); err != nil {
			if errors.Is(err, fs.ErrExist) {
				// A component is a file, or a link the root does not follow.
				return &errPathStatus{http.StatusForbidden, fmt.Errorf("cannot create the directory of %s inside the workspace", p)}
			}
			return confined(p, err)
		}
	}
	if fi, err := s.root.Lstat(p); err == nil {
		if exclusive {
			return &errPathStatus{http.StatusConflict, fmt.Errorf("%s already exists in the workspace", p)}
		}
		if !fi.Mode().IsRegular() {
			return &errPathStatus{http.StatusBadRequest, fmt.Errorf("%s is not a regular file", p)}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return confined(p, err)
	}
	if exclusive {
		f, err := s.root.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return confined(p, err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			_ = s.root.Remove(p)
			return confined(p, err)
		}
		return confined(p, f.Close())
	}
	tmp := path.Join(path.Dir(p), ".photofinish-"+randomHex(6)+".tmp")
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return confined(p, err)
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = s.root.Remove(tmp)
		return confined(p, err)
	}
	if err := s.root.Rename(tmp, p); err != nil {
		_ = s.root.Remove(tmp)
		return confined(p, err)
	}
	return nil
}

// removeFile deletes a workspace scenario file.
func (s *Server) removeFile(p string) error {
	p, err := s.checkPath(p)
	if err != nil {
		return err
	}
	fi, err := s.root.Lstat(p)
	if err != nil {
		return confined(p, err)
	}
	if !fi.Mode().IsRegular() && fi.Mode()&fs.ModeSymlink == 0 {
		return &errPathStatus{http.StatusBadRequest, fmt.Errorf("%s is not a regular file", p)}
	}
	return confined(p, s.root.Remove(p))
}

// listedFile is one scenario file found by listFiles.
type listedFile struct {
	path string
	data []byte
	err  error // the file could not be read
}

// listFiles walks the workspace for *.yaml and *.yml files, at most
// maxListDepth directories deep and maxListFiles files, skipping dot
// directories, node_modules and vendor. Symbolic links are followed only
// when they stay inside the workspace. truncated reports that the file cap
// was reached.
func (s *Server) listFiles() (files []listedFile, truncated bool, err error) {
	fsys := s.root.FS()
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == "." {
				return err
			}
			return nil // unreadable directory: skip it
		}
		name := d.Name()
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if strings.HasPrefix(name, ".") || skipDirs[name] || strings.Count(p, "/")+1 > maxListDepth {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasPrefix(name, ".") || !isScenarioFile(name) {
			return nil
		}
		if _, err := cleanPath(p); err != nil {
			return nil // not reachable through the API anyway
		}
		if len(files) == maxListFiles {
			truncated = true
			return fs.SkipAll
		}
		if d.Type()&fs.ModeSymlink != 0 {
			// The os.Root refuses links that leave the workspace.
			fi, err := s.root.Stat(p)
			if err != nil || !fi.Mode().IsRegular() {
				return nil
			}
		} else if !d.Type().IsRegular() {
			return nil
		}
		data, rerr := s.readListed(p)
		files = append(files, listedFile{path: p, data: data, err: rerr})
		return nil
	})
	return files, truncated, err
}

// hashContent returns the hex SHA-256 of a file's content, the baseHash
// that PUT compares to avoid lost updates.
func hashContent(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// randomHex returns n random bytes as hex.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported platforms
	}
	return hex.EncodeToString(b)
}

// readAbs reads the scenario file at an absolute path inside the workspace
// through readFile, so that the path checks, the os.Root and the size cap
// apply. Paths outside the workspace are refused.
func (s *Server) readAbs(name string) ([]byte, error) {
	rel, err := filepath.Rel(s.workspace, name)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, &errPathStatus{http.StatusForbidden, errors.New("the file is not in the workspace")}
	}
	return s.readFile(filepath.ToSlash(rel))
}
