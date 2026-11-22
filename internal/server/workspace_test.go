package server

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// minimal is a valid scenario.
const minimal = `version: 1
name: minimal
description: A small valid scenario.
target: https://127.0.0.1:8443/vuln/api
tls: { insecure: true }
scope:
  allow_hosts: [127.0.0.1:8443]
race:
  engine: h2
  copies: 5
  request: { request: POST /carts }
check:
  invariant: size(race) == 5
trials: 3
`

func TestCleanPath(t *testing.T) {
	good := []string{"a.yaml", "a.yml", "A.YAML", "dir/a.yaml", "a/b/c/d/e/f.yaml", "my scenario.yaml", "x-1_2.yaml", "ünïcode.yaml"}
	for _, p := range good {
		if _, err := cleanPath(p); err != nil {
			t.Errorf("cleanPath(%q): %v", p, err)
		}
	}
	bad := []string{
		"", "../a.yaml", "..\\a.yaml", "a/../../b.yaml", "a/../b.yaml", "./a.yaml", "a/./b.yaml",
		"/etc/a.yaml", "/a.yaml", "C:/a.yaml", "C:\\a.yaml", "c:a.yaml", "\\\\server\\share\\a.yaml", "//server/share/a.yaml",
		"a//b.yaml", "a/", "a.txt", "a.yaml.txt", ".yaml", "a", "a.json",
		".hidden.yaml", ".git/config.yaml", "a/.git/b.yaml",
		"a.yaml:stream", "a.yaml::$DATA", "NUL.yaml", "con.yaml", "Com1.yml", "lpt9.yaml", "aux/a.yaml", "nul .yaml",
		"a.yaml.", "a.yaml ", " a.yaml", "dir./a.yaml",
		"%2e%2e.yaml", "%2e%2e/a.yaml", "a%2fb.yaml",
		"a\x00.yaml", "a\n.yaml", "a*.yaml", "a?.yaml", "a<b.yaml", "a|b.yaml", `a".yaml`,
		strings.Repeat("a/", 300) + "x.yaml",
	}
	for _, p := range bad {
		if _, err := cleanPath(p); err == nil {
			t.Errorf("cleanPath(%q) accepted", p)
		} else if statusOf(err) != http.StatusBadRequest {
			t.Errorf("cleanPath(%q): status %d", p, statusOf(err))
		}
	}
}

// outsideFile creates a scenario file outside the workspace and returns its
// directory.
func outsideFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.yaml"), []byte("outside: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestTraversalAttempts(t *testing.T) {
	e := newEnv(t)
	outside := outsideFile(t)
	rel, _ := filepath.Rel(e.workspace, filepath.Join(outside, "secret.yaml"))
	rel = filepath.ToSlash(rel)
	abs := filepath.ToSlash(filepath.Join(outside, "secret.yaml"))
	paths := []string{
		rel,
		"../secret.yaml",
		strings.ReplaceAll(rel, "/", "\\"),
		abs,
		"/" + strings.TrimPrefix(abs, "/"),
		"C:/Windows/win.yaml",
		"C:\\Windows\\win.yaml",
		"..%2fsecret.yaml",
		"%2e%2e/secret.yaml",
		"examples/../../secret.yaml",
		"file:///" + abs,
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			q := "?path=" + url.QueryEscape(p)
			for _, req := range []request{
				{path: "/api/scenarios/file" + q},
				{method: "PUT", path: "/api/scenarios/file" + q, body: `{"content":"pwned: true\n"}`},
				{method: "DELETE", path: "/api/scenarios/file" + q},
				{method: "POST", path: "/api/scenarios/validate", body: map[string]string{"content": "", "path": p}},
				{method: "POST", path: "/api/runs", body: map[string]string{"path": p}},
			} {
				r := e.do(req)
				if r.code != http.StatusBadRequest && r.code != http.StatusNotFound && r.code != http.StatusForbidden {
					t.Errorf("%s: status %d: %s", req.method, r.code, r.body)
				}
				if strings.Contains(string(r.body), "outside: true") {
					t.Errorf("%s leaked the outside file", req.method)
				}
			}
		})
	}
	// The outside file is untouched and nothing was written outside.
	data, err := os.ReadFile(filepath.Join(outside, "secret.yaml"))
	if err != nil || string(data) != "outside: true\n" {
		t.Fatalf("outside file changed: %q %v", data, err)
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 {
		t.Errorf("files appeared outside the workspace: %v", entries)
	}
	if runs, _ := e.store.List(0, ""); len(runs) != 0 {
		t.Errorf("runs started: %v", runs)
	}
}

// linkDir makes link a directory link to target: a symbolic link, or a
// junction on Windows without the symlink privilege. It skips the test when
// neither works.
func linkDir(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err == nil {
		return
	}
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err == nil {
			return
		} else {
			t.Logf("mklink /J: %v %s", err, out)
		}
	}
	t.Skip("cannot create directory links here")
}

func TestSymlinkOutOfWorkspace(t *testing.T) {
	e := newEnv(t)
	outside := outsideFile(t)
	linkDir(t, outside, filepath.Join(e.workspace, "out"))
	for _, req := range []request{
		{path: "/api/scenarios/file?path=out/secret.yaml"},
		{method: "PUT", path: "/api/scenarios/file?path=out/new.yaml", body: `{"content":"x: 1\n"}`},
		{method: "PUT", path: "/api/scenarios/file?path=out/secret.yaml", body: `{"content":"x: 1\n"}`},
		{method: "PUT", path: "/api/scenarios/file?path=out/sub/new.yaml", body: `{"content":"x: 1\n"}`},
		{method: "DELETE", path: "/api/scenarios/file?path=out/secret.yaml"},
		{method: "POST", path: "/api/runs", body: map[string]string{"path": "out/secret.yaml"}},
	} {
		r := e.do(req)
		if r.code != http.StatusForbidden && r.code != http.StatusNotFound && r.code != http.StatusBadRequest {
			t.Errorf("%s %s: status %d %s", req.method, req.path, r.code, r.body)
		}
		if strings.Contains(string(r.body), "outside: true") || strings.Contains(string(r.body), filepath.ToSlash(outside)) {
			t.Errorf("%s %s leaked: %s", req.method, req.path, r.body)
		}
	}
	entries, _ := os.ReadDir(outside)
	if len(entries) != 1 {
		t.Errorf("files appeared outside the workspace: %v", entries)
	}
	if data, _ := os.ReadFile(filepath.Join(outside, "secret.yaml")); string(data) != "outside: true\n" {
		t.Errorf("outside file changed: %q", data)
	}
	// The listing does not follow the link either.
	r := e.get("/api/scenarios")
	want(t, r, http.StatusOK)
	if strings.Contains(string(r.body), "secret") {
		t.Errorf("listing shows the outside file: %s", r.body)
	}
}

func TestFileSymlinkOutOfWorkspace(t *testing.T) {
	e := newEnv(t)
	outside := outsideFile(t)
	if err := os.Symlink(filepath.Join(outside, "secret.yaml"), filepath.Join(e.workspace, "link.yaml")); err != nil {
		t.Skipf("cannot create file symlinks here: %v", err)
	}
	r := e.get("/api/scenarios/file?path=link.yaml")
	if r.code != http.StatusForbidden {
		t.Errorf("read through the link: %d %s", r.code, r.body)
	}
	r = e.do(request{method: "PUT", path: "/api/scenarios/file?path=link.yaml", body: `{"content":"x: 1\n"}`})
	if r.code < 400 {
		t.Errorf("write through the link: %d", r.code)
	}
	if data, _ := os.ReadFile(filepath.Join(outside, "secret.yaml")); string(data) != "outside: true\n" {
		t.Errorf("outside file changed: %q", data)
	}
	if strings.Contains(string(e.get("/api/scenarios").body), "link.yaml") {
		t.Error("listing shows the escaping link")
	}
}

func TestSymlinkInsideWorkspace(t *testing.T) {
	e := newEnv(t)
	e.write("real/minimal.yaml", minimal)
	if err := os.Symlink("real/minimal.yaml", filepath.Join(e.workspace, "alias.yaml")); err != nil {
		t.Skipf("cannot create file symlinks here: %v", err)
	}
	r := e.get("/api/scenarios/file?path=alias.yaml")
	want(t, r, http.StatusOK)
	var f fileResponse
	r.json(t, &f)
	if f.Content != minimal {
		t.Errorf("content %q", f.Content)
	}
}

func TestFileLifecycle(t *testing.T) {
	e := newEnv(t)
	put := func(p string, body any) response {
		return e.do(request{method: "PUT", path: "/api/scenarios/file?path=" + url.QueryEscape(p), body: body})
	}
	r := put("nested/dir/minimal.yaml", map[string]string{"content": minimal})
	want(t, r, http.StatusOK)
	var saved fileResponse
	r.json(t, &saved)
	if saved.Path != "nested/dir/minimal.yaml" || saved.Hash != hashContent([]byte(minimal)) {
		t.Errorf("put: %+v", saved)
	}
	data, err := os.ReadFile(filepath.Join(e.workspace, "nested", "dir", "minimal.yaml"))
	if err != nil || string(data) != minimal {
		t.Fatalf("on disk: %q %v", data, err)
	}

	r = e.get("/api/scenarios/file?path=nested/dir/minimal.yaml")
	want(t, r, http.StatusOK)
	var got fileResponse
	r.json(t, &got)
	if got.Content != minimal || got.Hash != saved.Hash {
		t.Errorf("get: %+v", got)
	}

	// Lost-update protection.
	edited := strings.Replace(minimal, "copies: 5", "copies: 6", 1)
	r = put("nested/dir/minimal.yaml", map[string]string{"content": edited, "baseHash": saved.Hash})
	want(t, r, http.StatusOK)
	r = put("nested/dir/minimal.yaml", map[string]string{"content": minimal, "baseHash": saved.Hash})
	want(t, r, http.StatusConflict)
	var conflict errorBody
	r.json(t, &conflict)
	if conflict.Hash != hashContent([]byte(edited)) || conflict.Error == "" {
		t.Errorf("conflict %+v", conflict)
	}
	r = put("gone.yaml", map[string]string{"content": minimal, "baseHash": saved.Hash})
	want(t, r, http.StatusConflict)
	// Without baseHash the write overwrites.
	want(t, put("nested/dir/minimal.yaml", map[string]string{"content": minimal}), http.StatusOK)

	want(t, put("missing-content.yaml", map[string]string{}), http.StatusBadRequest)
	want(t, put("empty.yaml", map[string]string{"content": ""}), http.StatusOK)

	r = e.do(request{method: "DELETE", path: "/api/scenarios/file?path=nested/dir/minimal.yaml"})
	want(t, r, http.StatusNoContent)
	want(t, e.get("/api/scenarios/file?path=nested/dir/minimal.yaml"), http.StatusNotFound)
	want(t, e.do(request{method: "DELETE", path: "/api/scenarios/file?path=nested/dir/minimal.yaml"}), http.StatusNotFound)

	// No temporary files are left behind.
	entries, _ := os.ReadDir(filepath.Join(e.workspace, "nested", "dir"))
	if len(entries) != 0 {
		t.Errorf("left behind: %v", entries)
	}
}

func TestFileTypesAndSizes(t *testing.T) {
	e := newEnv(t)
	if err := os.MkdirAll(filepath.Join(e.workspace, "dir.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	want(t, e.get("/api/scenarios/file?path=dir.yaml"), http.StatusBadRequest)
	want(t, e.do(request{method: "PUT", path: "/api/scenarios/file?path=dir.yaml", body: `{"content":"x"}`}), http.StatusBadRequest)
	want(t, e.do(request{method: "DELETE", path: "/api/scenarios/file?path=dir.yaml"}), http.StatusBadRequest)

	e.write("big.yaml", "# "+strings.Repeat("x", MaxFileBytes))
	want(t, e.get("/api/scenarios/file?path=big.yaml"), http.StatusRequestEntityTooLarge)
	e.write("notes.txt", "x")
	want(t, e.get("/api/scenarios/file?path=notes.txt"), http.StatusBadRequest)
}

func TestListing(t *testing.T) {
	e := newEnv(t)
	e.write("minimal.yaml", minimal)
	e.write("a/b/c/d/deep.yaml", strings.Replace(minimal, "name: minimal", "name: deep", 1))
	e.write("a/b/c/d/e/too-deep.yaml", minimal)
	e.write(".hidden/x.yaml", minimal)
	e.write("node_modules/pkg/x.yaml", minimal)
	e.write("vendor/x.yaml", minimal)
	e.write(".dot.yaml", minimal)
	e.write("compose.yaml", "services:\n  web:\n    image: nginx\n")
	e.write("broken.yml", "version: 1\nname: [unclosed\n")
	e.write("invalid.yaml", "version: 1\nname: Bad Name\ntarget: https://127.0.0.1:8443\nscope: {allow_hosts: [127.0.0.1:8443]}\nrace: {request: {request: GET /}}\ncheck: {invariant: 'true'}\n")
	e.write("big.yaml", "race: {}\n# "+strings.Repeat("x", MaxFileBytes))
	e.write("readme.md", "# not yaml")

	r := e.get("/api/scenarios")
	want(t, r, http.StatusOK)
	var resp scenariosResponse
	r.json(t, &resp)
	byPath := map[string]scenarioEntry{}
	for _, s := range resp.Scenarios {
		byPath[s.Path] = s
	}
	for _, p := range []string{"minimal.yaml", "a/b/c/d/deep.yaml", "broken.yml", "invalid.yaml", "big.yaml"} {
		if _, ok := byPath[p]; !ok {
			t.Errorf("%s not listed", p)
		}
	}
	for _, p := range []string{"a/b/c/d/e/too-deep.yaml", ".hidden/x.yaml", "node_modules/pkg/x.yaml", "vendor/x.yaml", ".dot.yaml", "compose.yaml", "readme.md"} {
		if _, ok := byPath[p]; ok {
			t.Errorf("%s listed", p)
		}
	}
	if m := byPath["minimal.yaml"]; !m.Valid || m.Name != "minimal" || m.Engine != "h2" || m.Target == "" || m.Description == "" || m.Error != "" {
		t.Errorf("minimal: %+v", m)
	}
	if b := byPath["broken.yml"]; b.Valid || !strings.Contains(b.Error, "line") {
		t.Errorf("broken: %+v", b)
	}
	if b := byPath["invalid.yaml"]; b.Valid || !strings.Contains(b.Error, "name") {
		t.Errorf("invalid: %+v", b)
	}
	if b := byPath["big.yaml"]; b.Valid || !strings.Contains(b.Error, "KiB") {
		t.Errorf("big: %+v", b)
	}
	if resp.Truncated {
		t.Error("truncated")
	}
	if len(resp.Examples) != 8 {
		t.Errorf("%d examples", len(resp.Examples))
	}
	for _, ex := range resp.Examples {
		if !ex.Valid || ex.Path != "examples/"+ex.Name+".yaml" || ex.InWorkspace || ex.Target == "" {
			t.Errorf("example %+v", ex)
		}
	}
}

func TestListingCap(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxListFiles+10; i++ {
		e.write(fmt.Sprintf("many/s%03d.yaml", i), "race: {}\n")
	}
	r := e.get("/api/scenarios")
	want(t, r, http.StatusOK)
	var resp scenariosResponse
	r.json(t, &resp)
	if len(resp.Scenarios) != maxListFiles || !resp.Truncated {
		t.Errorf("%d scenarios, truncated %v", len(resp.Scenarios), resp.Truncated)
	}
}

func TestEmptyListing(t *testing.T) {
	e := newEnv(t)
	r := e.get("/api/scenarios")
	want(t, r, http.StatusOK)
	if !strings.Contains(string(r.body), `"scenarios":[]`) {
		t.Errorf("empty workspace: %s", r.body)
	}
}

func TestCopyExample(t *testing.T) {
	e := newEnv(t)
	r := e.post("/api/examples/coupon-vuln/copy", nil)
	want(t, r, http.StatusCreated)
	var f fileResponse
	r.json(t, &f)
	if f.Path != "examples/coupon-vuln.yaml" {
		t.Errorf("path %q", f.Path)
	}
	data, err := os.ReadFile(filepath.Join(e.workspace, "examples", "coupon-vuln.yaml"))
	if err != nil || !strings.Contains(string(data), "https://127.0.0.1:8443") {
		t.Fatalf("copied: %v", err)
	}
	want(t, e.post("/api/examples/coupon-vuln/copy", nil), http.StatusConflict)
	for _, name := range []string{"nope", "..", "..%2f..%2fx", "Coupon-Vuln", "coupon-vuln.yaml"} {
		if r := e.post("/api/examples/"+name+"/copy", nil); r.code != http.StatusNotFound {
			t.Errorf("%s: %d", name, r.code)
		}
	}
	r = e.get("/api/scenarios")
	var resp scenariosResponse
	r.json(t, &resp)
	found := false
	for _, s := range resp.Scenarios {
		found = found || (s.Path == "examples/coupon-vuln.yaml" && s.Valid)
	}
	for _, ex := range resp.Examples {
		if ex.Name == "coupon-vuln" && !ex.InWorkspace {
			t.Error("example not marked as copied")
		}
	}
	if !found {
		t.Errorf("copied example not listed: %s", r.body)
	}
}
