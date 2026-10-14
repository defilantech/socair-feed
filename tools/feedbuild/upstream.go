package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The upstream check is the only networked part of the builder. It re-reads
// what each record cites and reports whether the record still holds: the
// report pages still print the hashes, the Hub still lists the same file at
// the same revision, and the pinned upstream files still have the recorded
// bytes. It downloads report pages, Hub API metadata, and small upstream
// JSON and template files; it never downloads a reported file.

// hubBase is the Hugging Face Hub, and newClient the HTTP client; a test
// points both at a local server.
var (
	hubBase   = "https://huggingface.co"
	newClient = func() *http.Client { return &http.Client{Timeout: 2 * time.Minute} }
)

// maxFetch bounds one download: the largest upstream file cited is a
// tokenizer.json of about 32 MB.
const maxFetch = 96 << 20

// CheckUpstream re-checks every active record against its sources and writes one
// line per check. It returns the number of checks that did not hold.
func CheckUpstream(r *Repo, w io.Writer, socair, only string) int {
	c := newClient()
	failed := 0
	report := func(what string, err error) {
		var n note
		switch {
		case errors.As(err, &n):
			fmt.Fprintf(w, "note  %s: %s\n", what, n)
		case err != nil:
			failed++
			fmt.Fprintf(w, "FAIL  %s: %v\n", what, err)
		default:
			fmt.Fprintf(w, "ok    %s\n", what)
		}
	}
	pick := func(name string) bool { return only == "" || only == name }
	for _, e := range r.Denylist {
		if e.Status != "active" || !pick(e.ID) {
			continue
		}
		s := e.Evidence.Source
		page, err := fetch(c, s.URL)
		if err == nil {
			low := strings.ToLower(string(page))
			switch e.Evidence.Class {
			case 1:
				if !strings.Contains(low, e.SHA256) {
					err = fmt.Errorf("the page no longer prints %s", e.SHA256)
				}
			case 2:
				if !strings.Contains(low, strings.ToLower(e.Evidence.Hub.Repo)) {
					err = fmt.Errorf("the page no longer names %s", e.Evidence.Hub.Repo)
				}
			}
		}
		report(e.ID+" source "+s.URL, err)
		if e.Evidence.Class == 2 {
			report(e.ID+" hub "+e.Evidence.Hub.Repo+"/"+e.Evidence.Hub.Path, checkHub(c, e))
		}
	}
	for _, e := range r.Templates {
		if e.Status != "active" || !pick(e.Name) {
			continue
		}
		want, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(e.Text)))
		if err != nil {
			report(e.Name+" text", err)
			continue
		}
		u := e.Upstream
		report(fmt.Sprintf("template %s %s@%s/%s", e.Name, u.Repo, u.Revision[:12], u.File), checkTemplate(c, u.Repo, u.Revision, u.File, u.Field, u.FileSHA256, want))
		for _, id := range e.AlsoIdenticalAt {
			report(fmt.Sprintf("template %s also at %s@%s/%s", e.Name, id.Repo, id.Revision[:12], id.File), checkTemplate(c, id.Repo, id.Revision, id.File, id.Field, "", want))
		}
		report(e.Name+" license", checkLicense(c, u))
	}
	for _, e := range r.Tokenizers {
		if e.Status != "active" || !pick(e.Name) {
			continue
		}
		u := e.Upstream
		b, err := fetch(c, resolveURL(u.Repo, u.Revision, u.File))
		if err == nil && sha256Hex(b) != u.FileSHA256 {
			err = fmt.Errorf("the file hashes to %s, not %s", sha256Hex(b), u.FileSHA256)
		}
		report(fmt.Sprintf("tokenizer %s %s@%s/%s", e.Name, u.Repo, u.Revision[:12], u.File), err)
		if err == nil && e.Table != nil {
			if socair == "" {
				fmt.Fprintf(w, "skip  tokenizer %s table: no -socair binary given to re-derive it\n", e.Name)
			} else {
				report("tokenizer "+e.Name+" table re-derived by socair", rederive(socair, e, b, r.Root))
			}
		}
		for _, id := range e.AlsoIdenticalAt {
			report(fmt.Sprintf("tokenizer %s also at %s@%s/%s", e.Name, id.Repo, id.Revision[:12], id.File), checkIdenticalFile(c, id, u.FileSHA256))
		}
		report(e.Name+" license", checkLicense(c, u))
	}
	return failed
}

// note is a finding that does not undo a record, printed but not counted
// as a failure.
type note string

func (n note) Error() string { return string(n) }

// statusError is an HTTP answer other than 200.
type statusError struct {
	url    string
	code   int
	status string
}

func (e *statusError) Error() string { return fmt.Sprintf("GET %s: %s", e.url, e.status) }

func resolveURL(repo, rev, file string) string {
	return hubBase + "/" + repo + "/resolve/" + rev + "/" + file
}

func fetch(c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	// Some report sites refuse clients that do not name themselves.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; socair-feed-upstream-check; +https://github.com/defilantech/socair-feed)")
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &statusError{url: url, code: resp.StatusCode, status: resp.Status}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxFetch+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFetch {
		return nil, fmt.Errorf("GET %s: over %d bytes", url, maxFetch)
	}
	return b, nil
}

// hubModel is the part of the Hub's model API answer the checks read.
type hubModel struct {
	SHA          string `json:"sha"`
	Disabled     bool   `json:"disabled"`
	LastModified string `json:"lastModified"`
	Siblings     []struct {
		Name   string `json:"rfilename"`
		Size   int64  `json:"size"`
		BlobID string `json:"blobId"`
		LFS    *struct {
			SHA256 string `json:"sha256"`
			Size   int64  `json:"size"`
		} `json:"lfs"`
	} `json:"siblings"`
}

func hubAPI(c *http.Client, repo string) (*hubModel, error) {
	b, err := fetch(c, hubBase+"/api/models/"+repo+"?blobs=true")
	if err != nil {
		return nil, err
	}
	m := new(hubModel)
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("Hub API answer does not parse: %w", err)
	}
	return m, nil
}

// checkHub re-runs a class 2 lookup. A repository that is gone (the Hub
// answers 401 or 404) does not undo the entry: its evidence was recorded when
// it could be read. A repository that lists different bytes for the file at
// the recorded revision does.
func checkHub(c *http.Client, e *DenyEntry) error {
	h := e.Evidence.Hub
	m, err := hubAPI(c, h.Repo)
	var se *statusError
	if errors.As(err, &se) && (se.code == http.StatusUnauthorized || se.code == http.StatusNotFound) {
		return note(fmt.Sprintf("the Hub no longer serves %s (%s); the recorded lookup of %s stands", h.Repo, se.status, h.ReadOn))
	}
	if err != nil {
		return err
	}
	if m.SHA != h.Revision {
		return fmt.Errorf("the repository is now at revision %s, not %s: read the new revision before keeping the entry", m.SHA, h.Revision)
	}
	for _, s := range m.Siblings {
		if s.Name != h.Path {
			continue
		}
		switch {
		case s.LFS == nil:
			return fmt.Errorf("%s is no longer an LFS file", h.Path)
		case s.LFS.SHA256 != e.SHA256 || s.LFS.Size != h.Size:
			return fmt.Errorf("the Hub lists %s, %d bytes", s.LFS.SHA256, s.LFS.Size)
		case s.BlobID != lfsBlobID(e.SHA256, h.Size):
			return fmt.Errorf("the blob id %s does not match the LFS pointer", s.BlobID)
		}
		return nil
	}
	return fmt.Errorf("%s is not listed at revision %s", h.Path, m.SHA)
}

// checkTemplate downloads a pinned upstream file and compares the template
// it holds with the shipped text.
func checkTemplate(c *http.Client, repo, rev, file, field, fileSHA string, want []byte) error {
	b, err := fetch(c, resolveURL(repo, rev, file))
	if err != nil {
		return err
	}
	if fileSHA != "" && sha256Hex(b) != fileSHA {
		return fmt.Errorf("the file hashes to %s, not %s", sha256Hex(b), fileSHA)
	}
	got := b
	if field != "" {
		var cfg map[string]json.RawMessage
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("%s does not parse: %w", file, err)
		}
		var s string
		if err := json.Unmarshal(cfg[field], &s); err != nil {
			return fmt.Errorf("%s has no string %s", file, field)
		}
		got = []byte(s)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("the template differs from the shipped text (sha256 %s)", sha256Hex(got))
	}
	return nil
}

// checkIdenticalFile confirms another repository carries the same file, by
// download or by the Hub's LFS id, as the record says it was established.
func checkIdenticalFile(c *http.Client, id Identical, want string) error {
	if id.How == howHubLFS {
		m, err := hubAPI(c, id.Repo)
		if err != nil {
			return err
		}
		if m.SHA != id.Revision {
			return fmt.Errorf("the repository is now at revision %s, not %s", m.SHA, id.Revision)
		}
		for _, s := range m.Siblings {
			if s.Name == id.File && s.LFS != nil {
				if s.LFS.SHA256 != want {
					return fmt.Errorf("the Hub lists %s", s.LFS.SHA256)
				}
				return nil
			}
		}
		return fmt.Errorf("%s is not an LFS file there", id.File)
	}
	b, err := fetch(c, resolveURL(id.Repo, id.Revision, id.File))
	if err != nil {
		return err
	}
	if sha256Hex(b) != want {
		return fmt.Errorf("the file hashes to %s", sha256Hex(b))
	}
	return nil
}

// checkLicense confirms the repository's LICENSE file at the revision is the
// copy that ships, when the record says the repository has one.
func checkLicense(c *http.Client, u Upstream) error {
	if u.LicenseFileSHA256 == "" {
		return nil
	}
	b, err := fetch(c, resolveURL(u.Repo, u.Revision, "LICENSE"))
	if err != nil {
		return err
	}
	if sha256Hex(b) != u.LicenseFileSHA256 {
		return fmt.Errorf("LICENSE hashes to %s, not %s", sha256Hex(b), u.LicenseFileSHA256)
	}
	return nil
}

// rederive runs `socair feed tokenizer-table` on the downloaded upstream
// file and compares its output with the committed table, byte for byte.
func rederive(socair string, e *TokenizerEntry, upstream []byte, root string) error {
	dir, err := os.MkdirTemp("", "feedbuild-tokenizer-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "tokenizer.json")
	if err := os.WriteFile(src, upstream, 0o600); err != nil {
		return err
	}
	var out, errOut bytes.Buffer
	cmd := exec.Command(socair, "feed", "tokenizer-table", src, "--name", e.Name)
	cmd.Stdout, cmd.Stderr = &out, &errOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("socair feed tokenizer-table: %v: %s", err, strings.TrimSpace(errOut.String()))
	}
	want, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(e.Table.File)))
	if err != nil {
		return err
	}
	if !bytes.Equal(out.Bytes(), want) {
		return fmt.Errorf("socair writes a different table (sha256 %s, committed %s)", sha256Hex(out.Bytes()), e.Table.SHA256)
	}
	return nil
}
