package main

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	reID       = regexp.MustCompile(`^SF-D-[0-9]{4}-[0-9]{4}$`)
	reName     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reRevision = regexp.MustCompile(`^[0-9a-f]{40}$`)
	reRepo     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

// kinds are the file kinds a denylist entry may name, with the words a label
// uses for each.
var kinds = map[string]string{
	"pickle-checkpoint": "pickle checkpoint",
	"weights":           "weights file",
	"loader-script":     "loader script",
	"executable":        "executable",
	"other":             "file",
}

// shippedLicenses are the licenses a text in texts/ may carry. A feed is
// redistributed by every site that imports it, so only licenses that allow
// that with a notice are accepted; anything else is cited by hash, never
// copied.
var shippedLicenses = map[string]bool{"Apache-2.0": true, "MIT": true}

// tableFormat is the canonical tokenizer table format Socair reads.
const tableFormat = "socair.tokenizer-table/v1"

// Size limits, matching what Socair accepts: a reviewed template is read with
// the analyser's 1 MiB bound, a feed file with 64 MiB.
const (
	maxTemplate = 1 << 20
	maxFeedFile = 64 << 20
)

// Validate checks every record, the texts they point at, the goodware list,
// and the NOTICE file, and returns every problem found, sorted.
func Validate(r *Repo) []string {
	v := &validator{r: r, problems: append([]string(nil), r.problems...)}
	v.denylist()
	v.templates()
	v.tokenizers()
	v.crossChecks()
	v.texts()
	v.notice()
	sort.Strings(v.problems)
	return v.problems
}

type validator struct {
	r        *Repo
	problems []string
}

func (v *validator) bad(where string, format string, args ...any) {
	v.problems = append(v.problems, where+": "+fmt.Sprintf(format, args...))
}

func (v *validator) denylist() {
	seen := map[string]string{}
	for _, e := range v.r.Denylist {
		at := v.r.rel(e)
		if e.Schema != schemaDenylist {
			v.bad(at, "schema must be %q", schemaDenylist)
		}
		if !reID.MatchString(e.ID) {
			v.bad(at, "id %q is not SF-D-<year>-<4 digits>", e.ID)
		} else if filepath.Base(at) != e.ID+".json" {
			v.bad(at, "file must be named %s.json", e.ID)
		}
		v.status(at, e.Status, e.Withdrawn)
		v.date(at, "added", e.Added)
		if !isSHA256(e.SHA256) {
			v.bad(at, "sha256 must be 64 lowercase hex characters")
		} else if other, dup := seen[e.SHA256]; dup {
			v.bad(at, "sha256 is also listed by %s", other)
		} else {
			seen[e.SHA256] = at
		}
		v.text(at, "file", e.File)
		if e.Size != nil && *e.Size <= 0 {
			v.bad(at, "size must be positive, or null when the source does not give it")
		}
		if _, ok := kinds[e.Kind]; !ok {
			v.bad(at, "kind %q is not one of pickle-checkpoint, weights, loader-script, executable, other", e.Kind)
		}
		v.text(at, "what", e.What)
		v.evidence(at, e)
	}
}

// evidence holds an entry to its evidence class. Class 1: the source prints
// the hash, and the quote shows it. Class 2: the source names the repository,
// the Hub API gave the hash of the file there, the lookup came after the
// report, the repository has not changed since before it, and the recorded
// LFS pointer matches the blob id the API listed.
func (v *validator) evidence(at string, e *DenyEntry) {
	ev := e.Evidence
	v.text(at, "evidence.basis", ev.Basis)
	s := ev.Source
	v.text(at, "evidence.source.publisher", s.Publisher)
	v.text(at, "evidence.source.title", s.Title)
	v.url(at, "evidence.source.url", s.URL)
	v.text(at, "evidence.source.quote", s.Quote)
	pub := v.date(at, "evidence.source.published", s.Published)
	read := v.date(at, "evidence.source.read_on", s.ReadOn)
	if !pub.IsZero() && !read.IsZero() && read.Before(pub) {
		v.bad(at, "evidence.source.read_on is before the source was published")
	}
	switch ev.Class {
	case 1:
		if ev.Hub != nil {
			v.bad(at, "a class 1 entry has no hub record")
		}
		if e.SHA256 != "" && !strings.Contains(strings.ToLower(s.Quote), e.SHA256) {
			v.bad(at, "evidence.source.quote must show the SHA-256 as the source prints it")
		}
	case 2:
		h := ev.Hub
		if h == nil {
			v.bad(at, "a class 2 entry needs evidence.hub")
			return
		}
		if !reRepo.MatchString(h.Repo) {
			v.bad(at, "evidence.hub.repo %q is not <owner>/<name>", h.Repo)
		}
		if !strings.Contains(s.Quote, h.Repo) {
			v.bad(at, "evidence.source.quote must show the repository %s as the source names it", h.Repo)
		}
		v.text(at, "evidence.hub.path", h.Path)
		if h.Path != e.File && !strings.HasSuffix(h.Path, "/"+e.File) {
			v.bad(at, "file must be the last element of evidence.hub.path")
		}
		if !reRevision.MatchString(h.Revision) {
			v.bad(at, "evidence.hub.revision must be a full 40-character commit id")
		}
		if want := "https://huggingface.co/api/models/" + h.Repo + "?blobs=true"; h.APIURL != want {
			v.bad(at, "evidence.hub.api_url must be %s", want)
		}
		hubRead := v.date(at, "evidence.hub.read_on", h.ReadOn)
		if !pub.IsZero() && !hubRead.IsZero() && !hubRead.After(pub) {
			v.bad(at, "evidence.hub.read_on must come after the source was published")
		}
		last, err := time.Parse(time.RFC3339, h.LastModified)
		if err != nil {
			v.bad(at, "evidence.hub.last_modified must be RFC 3339")
		} else if !pub.IsZero() && last.After(pub.Add(24*time.Hour)) {
			v.bad(at, "the repository changed after the source was published (last_modified %s), so the file hashed may not be the file reported", h.LastModified)
		}
		if e.Size == nil || *e.Size != h.Size {
			v.bad(at, "size must equal evidence.hub.size")
		}
		if isSHA256(e.SHA256) && h.Size > 0 && h.BlobID != lfsBlobID(e.SHA256, h.Size) {
			v.bad(at, "evidence.hub.blob_id %s is not the Git blob id of the LFS pointer for this sha256 and size (%s)", h.BlobID, lfsBlobID(e.SHA256, h.Size))
		}
	default:
		v.bad(at, "evidence.class must be 1 (the source prints the hash) or 2 (the source names the repository, the Hub gives the hash); nothing else is accepted")
	}
}

func (v *validator) templates() {
	names, hashes := map[string]bool{}, map[string]string{}
	for _, e := range v.r.Templates {
		at := v.r.rel(e)
		if e.Schema != schemaTemplate {
			v.bad(at, "schema must be %q", schemaTemplate)
		}
		v.name(at, e.Name, names)
		v.status(at, e.Status, e.Withdrawn)
		v.date(at, "added", e.Added)
		v.text(at, "what", e.What)
		v.text(at, "notes", e.Notes)
		if len(e.Checks) == 0 {
			v.bad(at, "checks must list the mechanical checks run on the text")
		}
		for i, c := range e.Checks {
			v.text(at, fmt.Sprintf("checks[%d]", i), c)
		}
		if !isSHA256(e.SHA256) {
			v.bad(at, "sha256 must be 64 lowercase hex characters")
		} else if other, dup := hashes[e.SHA256]; dup {
			v.bad(at, "sha256 is also listed by %s", other)
		} else {
			hashes[e.SHA256] = at
			if want := dirTextTpl + "/" + e.SHA256 + ".jinja"; e.Text != want {
				v.bad(at, "text must be %s", want)
			} else {
				v.templateText(at, e)
			}
		}
		v.upstream(at, e.Upstream, true)
		if e.Upstream.Field == "" && e.Upstream.FileSHA256 != e.SHA256 {
			v.bad(at, "the upstream file is the template (no field), so upstream.file_sha256 must equal sha256")
		}
		if e.Upstream.Field != "" && e.Upstream.Field != "chat_template" {
			v.bad(at, "upstream.field must be chat_template or absent")
		}
		v.identical(at, e.AlsoIdenticalAt, false)
		r := e.Review
		if r.Means != reviewMeans {
			v.bad(at, "review.means must be the project's definition of review, word for word (see CONTRIBUTING.md)")
		}
		switch r.Status {
		case "pending":
			if r.By != "" || r.On != "" {
				v.bad(at, "a pending review names no reviewer and no date")
			}
		case "reviewed":
			v.text(at, "review.by", r.By)
			v.date(at, "review.on", r.On)
		default:
			v.bad(at, "review.status must be pending or reviewed")
		}
	}
}

func (v *validator) templateText(at string, e *TemplateEntry) {
	b, err := os.ReadFile(filepath.Join(v.r.Root, filepath.FromSlash(e.Text)))
	if err != nil {
		v.bad(at, "text %s cannot be read: %v", e.Text, err)
		return
	}
	if sum := sha256Hex(b); sum != e.SHA256 {
		v.bad(at, "text %s hashes to %s, not its sha256", e.Text, sum)
	}
	if int64(len(b)) != e.Bytes {
		v.bad(at, "text is %d bytes, the record says %d", len(b), e.Bytes)
	}
	if len(b) > maxTemplate {
		v.bad(at, "text is over Socair's %d-byte template bound", maxTemplate)
	}
	if !utf8.Valid(b) {
		v.bad(at, "text is not valid UTF-8")
	}
}

func (v *validator) tokenizers() {
	names, hashes := map[string]bool{}, map[string]string{}
	for _, e := range v.r.Tokenizers {
		at := v.r.rel(e)
		if e.Schema != schemaTokenizer {
			v.bad(at, "schema must be %q", schemaTokenizer)
		}
		v.name(at, e.Name, names)
		v.status(at, e.Status, e.Withdrawn)
		v.date(at, "added", e.Added)
		v.text(at, "what", e.What)
		v.upstream(at, e.Upstream, e.Form == "table")
		if h := e.Upstream.FileSHA256; isSHA256(h) {
			if other, dup := hashes[h]; dup {
				v.bad(at, "upstream.file_sha256 is also listed by %s", other)
			}
			hashes[h] = at
		}
		v.identical(at, e.AlsoIdenticalAt, true)
		switch e.Form {
		case "table":
			if e.Table == nil {
				v.bad(at, "form table needs table")
				continue
			}
			if e.HashOnlyReason != "" {
				v.bad(at, "hash_only_reason is only for form hash-only")
			}
			v.table(at, e)
		case "hash-only":
			if e.Table != nil {
				v.bad(at, "form hash-only carries no table")
			}
			v.text(at, "hash_only_reason", e.HashOnlyReason)
		default:
			v.bad(at, "form must be table or hash-only")
		}
	}
}

// table holds a tokenizer table to its record: the file's hash, its format
// and name, its token count, and the vocabulary hash Socair would compute for
// the same tokens.
func (v *validator) table(at string, e *TokenizerEntry) {
	t := e.Table
	if want := dirTextTok + "/" + e.Name + ".json"; t.File != want {
		v.bad(at, "table.file must be %s", want)
		return
	}
	v.text(at, "table.derived_with", t.DerivedWith)
	b, err := os.ReadFile(filepath.Join(v.r.Root, filepath.FromSlash(t.File)))
	if err != nil {
		v.bad(at, "table %s cannot be read: %v", t.File, err)
		return
	}
	if len(b) > maxFeedFile {
		v.bad(at, "table is over Socair's %d-byte feed file bound", maxFeedFile)
	}
	if sum := sha256Hex(b); sum != t.SHA256 {
		v.bad(at, "table %s hashes to %s, not table.sha256", t.File, sum)
	}
	var tab struct {
		Format string   `json:"format"`
		Name   string   `json:"name"`
		Tokens []string `json:"tokens"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&tab); err != nil {
		v.bad(at, "table does not parse: %v", err)
		return
	}
	if tab.Format != tableFormat {
		v.bad(at, "table format must be %s", tableFormat)
	}
	if tab.Name != e.Name {
		v.bad(at, "table name %q must be the entry's name", tab.Name)
	}
	if len(tab.Tokens) != t.Tokens {
		v.bad(at, "table has %d tokens, the record says %d", len(tab.Tokens), t.Tokens)
	}
	empty := 0
	for _, s := range tab.Tokens {
		if s == "" {
			empty++
		}
	}
	if empty != t.Unassigned {
		v.bad(at, "table has %d unassigned ids, the record says %d", empty, t.Unassigned)
	}
	if got := vocabHash(tab.Tokens); got != t.VocabSHA256 {
		v.bad(at, "table's vocabulary hashes to %s, not table.vocab_sha256", got)
	}
}

// upstream checks the pin of an upstream file. shipped is true when a copy
// of (or derivation from) the file ships, so its license must allow that.
func (v *validator) upstream(at string, u Upstream, shipped bool) {
	if !reRepo.MatchString(u.Repo) {
		v.bad(at, "upstream.repo %q is not <owner>/<name>", u.Repo)
	}
	if !reRevision.MatchString(u.Revision) {
		v.bad(at, "upstream.revision must be a full 40-character commit id")
	}
	v.text(at, "upstream.file", u.File)
	if want := "https://huggingface.co/" + u.Repo + "/blob/" + u.Revision + "/" + u.File; u.URL != want {
		v.bad(at, "upstream.url must be %s", want)
	}
	if !isSHA256(u.FileSHA256) {
		v.bad(at, "upstream.file_sha256 must be 64 lowercase hex characters")
	}
	if u.FileBytes <= 0 {
		v.bad(at, "upstream.file_bytes must be positive")
	}
	v.date(at, "upstream.read_on", u.ReadOn)
	v.text(at, "upstream.license_evidence", u.LicenseEvidence)
	v.text(at, "upstream.copyright", u.Copyright)
	if shipped && !shippedLicenses[u.License] {
		v.bad(at, "upstream.license %q: only Apache-2.0 and MIT texts are shipped; cite anything else by hash only", u.License)
	}
	if u.License == "" {
		v.bad(at, "upstream.license must be an SPDX id")
	}
	if !strings.HasPrefix(u.LicenseText, dirLicenses+"/") {
		v.bad(at, "upstream.license_text must be a file under %s/", dirLicenses)
		return
	}
	b, err := os.ReadFile(filepath.Join(v.r.Root, filepath.FromSlash(u.LicenseText)))
	if err != nil {
		v.bad(at, "upstream.license_text %s cannot be read", u.LicenseText)
		return
	}
	if u.LicenseFileSHA256 != "" && sha256Hex(b) != u.LicenseFileSHA256 {
		v.bad(at, "upstream.license_text %s is not the repository's LICENSE (sha256 %s)", u.LicenseText, u.LicenseFileSHA256)
	}
}

func (v *validator) identical(at string, ids []Identical, tokenizer bool) {
	for i, id := range ids {
		where := fmt.Sprintf("also_identical_at[%d]", i)
		if !reRepo.MatchString(id.Repo) {
			v.bad(at, "%s.repo %q is not <owner>/<name>", where, id.Repo)
		}
		if !reRevision.MatchString(id.Revision) {
			v.bad(at, "%s.revision must be a full 40-character commit id", where)
		}
		v.text(at, where+".file", id.File)
		v.date(at, where+".read_on", id.ReadOn)
		switch {
		case id.How == howDownloaded:
		case id.How == howHubLFS && tokenizer:
		default:
			v.bad(at, "%s.how must be %q%s", where, howDownloaded, map[bool]string{true: " or " + fmt.Sprintf("%q", howHubLFS)}[tokenizer])
		}
	}
}

// crossChecks keeps the denylist apart from everything known to be good: a
// hash of a goodware file, or of any template, tokenizer, or table this feed
// itself vouches for, can never be known-bad.
func (v *validator) crossChecks() {
	good := map[string]string{}
	for h, why := range v.r.Goodware {
		good[h] = "goodware: " + why
	}
	for _, t := range v.r.Templates {
		good[t.SHA256] = "template " + t.Name
	}
	for _, t := range v.r.Tokenizers {
		good[t.Upstream.FileSHA256] = "tokenizer " + t.Name
		if t.Table != nil {
			good[t.Table.SHA256] = "tokenizer table " + t.Name
			good[t.Table.VocabSHA256] = "tokenizer vocabulary " + t.Name
		}
	}
	for _, e := range v.r.Denylist {
		if why, ok := good[e.SHA256]; ok {
			v.bad(v.r.rel(e), "sha256 is a known-good file (%s); it cannot be on the denylist", why)
		}
	}
}

// texts requires every file under texts/ to belong to exactly one record:
// an unreferenced copy of upstream material has no citation or license.
func (v *validator) texts() {
	want := map[string]bool{}
	for _, t := range v.r.Templates {
		want[t.Text] = true
	}
	for _, t := range v.r.Tokenizers {
		if t.Table != nil {
			want[t.Table.File] = true
		}
	}
	for _, dir := range []string{dirTextTpl, dirTextTok} {
		entries, err := os.ReadDir(filepath.Join(v.r.Root, dir))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			v.bad(dir, "%v", err)
			continue
		}
		for _, e := range entries {
			rel := dir + "/" + e.Name()
			if e.IsDir() || !want[rel] {
				v.bad(rel, "no source record cites this file")
			}
		}
	}
	if _, err := os.Stat(filepath.Join(v.r.Root, fileCC0)); err != nil {
		v.bad(fileCC0, "missing: the data dedication's text must ship")
	}
}

// notice requires the committed NOTICE to be the one the records generate.
func (v *validator) notice() {
	want := Notice(v.r.Templates, v.r.Tokenizers)
	got, err := os.ReadFile(filepath.Join(v.r.Root, fileNotice))
	if err != nil || string(got) != want {
		v.bad(fileNotice, "out of date with the records (run: go run ./tools/feedbuild notice > NOTICE)")
	}
}

func (v *validator) name(at, name string, seen map[string]bool) {
	if !reName.MatchString(name) {
		v.bad(at, "name %q must be lowercase [a-z0-9._-], as Socair names tables", name)
		return
	}
	if filepath.Base(at) != name+".json" {
		v.bad(at, "file must be named %s.json", name)
	}
	if seen[name] {
		v.bad(at, "name %q is used twice", name)
	}
	seen[name] = true
}

func (v *validator) status(at, status string, w *Withdrawal) {
	switch status {
	case "active":
		if w != nil {
			v.bad(at, "an active entry has no withdrawn record")
		}
	case "withdrawn":
		if w == nil {
			v.bad(at, "a withdrawn entry needs withdrawn {on, reason, link}")
			return
		}
		v.date(at, "withdrawn.on", w.On)
		v.text(at, "withdrawn.reason", w.Reason)
		v.url(at, "withdrawn.link", w.Link)
	default:
		v.bad(at, "status must be active or withdrawn")
	}
}

// text requires a non-empty single-line field with no control characters,
// since fields end up in feed labels and NOTICE lines.
func (v *validator) text(at, field, s string) {
	if strings.TrimSpace(s) == "" {
		v.bad(at, "%s must not be empty", field)
		return
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			v.bad(at, "%s holds a control or format character (U+%04X)", field, r)
			return
		}
	}
}

func (v *validator) url(at, field, s string) {
	v.text(at, field, s)
	if !strings.HasPrefix(s, "https://") || strings.ContainsAny(s, " \t") {
		v.bad(at, "%s must be an https URL", field)
	}
}

func (v *validator) date(at, field, s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		v.bad(at, "%s must be a date, YYYY-MM-DD", field)
		return time.Time{}
	}
	return t
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// vocabHash is Socair's tokenizer vocabulary hash: the SHA-256 of the tokens
// in id order, each followed by a NUL byte (tokenizer.VocabHash in Socair).
func vocabHash(tokens []string) string {
	h := sha256.New()
	for _, s := range tokens {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// lfsBlobID is the Git blob id of the LFS pointer for a file: the pointer
// names the file's SHA-256 and size, and Git names the pointer by the SHA-1
// of "blob <len>\x00<pointer>".
func lfsBlobID(sha string, size int64) string {
	ptr := fmt.Sprintf("version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize %d\n", sha, size)
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(ptr))
	h.Write([]byte(ptr))
	return hex.EncodeToString(h.Sum(nil))
}
