package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixture is a small repository generated in code: two denylist entries
// (one per evidence class), one template, one tokenizer table, a goodware
// list, licenses, and a NOTICE. Every rule test mutates one thing in it and
// expects one problem, so a rule that stops firing fails its test.

const (
	fxTemplate = "{% for m in messages %}<|{{ m.role }}|>{{ m.content }}<|end|>{% endfor %}"
	fxGoodware = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

var fxTokens = []string{"<s>", "</s>", "a", "b", "", "ab"}

type fixture struct {
	root  string
	deny1 *DenyEntry
	deny2 *DenyEntry
	tpl   *TemplateEntry
	tok   *TokenizerEntry
}

func write(t *testing.T, root, rel string, b []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeRecord(t *testing.T, root, rel string, v any) {
	t.Helper()
	b, err := canonical(v)
	if err != nil {
		t.Fatal(err)
	}
	write(t, root, rel, b)
}

func upstreamFixture(file, field, sha string) Upstream {
	return Upstream{
		Repo: "example/model", Revision: strings.Repeat("a", 40), File: file, Field: field,
		URL: "https://huggingface.co/example/model/blob/" + strings.Repeat("a", 40) + "/" + file, FileSHA256: sha, FileBytes: 100,
		ReadOn: "2026-10-14", License: "Apache-2.0", LicenseEvidence: "the card says apache-2.0", LicenseText: "LICENSES/Apache-2.0.txt",
		Copyright: "Copyright 2026 Example.",
	}
}

// newFixture writes the fixture repository and returns it, records included,
// so a test can change one and write it back.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	write(t, root, fileCC0, []byte("cc0 text\n"))
	write(t, root, "LICENSES/Apache-2.0.txt", []byte("apache text\n"))
	write(t, root, fileGoodware, []byte("# test goodware\n"+fxGoodware+" the empty file\n"))

	size1 := int64(495)
	h1 := strings.Repeat("1f", 32)
	d1 := &DenyEntry{Schema: schemaDenylist, ID: "SF-D-2026-0001", Status: "active", SHA256: h1, File: "ws.pth", Size: &size1,
		Kind: "pickle-checkpoint", What: "a reported pickle", Added: "2026-10-14",
		Evidence: Evidence{Class: 1, Basis: "the report prints it", Source: Citation{Publisher: "Example Labs", Title: "A report",
			URL: "https://example.com/report", Published: "2025-07-01", ReadOn: "2026-10-14", Quote: "SHA256: " + strings.ToUpper(h1)}}}
	h2, size2 := strings.Repeat("2", 64), int64(231139)
	d2 := &DenyEntry{Schema: schemaDenylist, ID: "SF-D-2026-0002", Status: "active", SHA256: h2, File: "pytorch_model.bin", Size: &size2,
		Kind: "pickle-checkpoint", What: "a reported repository's model", Added: "2026-10-14",
		Evidence: Evidence{Class: 2, Basis: "the report names the repository", Source: Citation{Publisher: "Example Labs", Title: "Another report",
			URL: "https://example.com/report2", Published: "2024-02-27", ReadOn: "2026-10-14", Quote: "One such instance remains active: bad/repo."},
			Hub: &HubRecord{Repo: "bad/repo", Path: "pytorch_model.bin", Revision: strings.Repeat("b", 40),
				APIURL: "https://huggingface.co/api/models/bad/repo?blobs=true", ReadOn: "2026-10-14", Size: size2,
				BlobID: lfsBlobID(h2, size2), Disabled: true, LastModified: "2024-01-13T13:53:28Z"}}}
	writeRecord(t, root, dirDenylist+"/SF-D-2026-0001.json", d1)
	writeRecord(t, root, dirDenylist+"/SF-D-2026-0002.json", d2)

	th := sha256Hex([]byte(fxTemplate))
	tp := &TemplateEntry{Schema: schemaTemplate, Name: "example-chat", Status: "active", SHA256: th, Bytes: int64(len(fxTemplate)),
		Text: dirTextTpl + "/" + th + ".jinja", What: "a chat template", Upstream: upstreamFixture("tokenizer_config.json", "chat_template", strings.Repeat("c", 64)),
		AlsoIdenticalAt: []Identical{}, Checks: []string{"byte-identical to upstream"}, Notes: "lays out turns",
		Review: Review{Means: reviewMeans, Status: "pending"}, Added: "2026-10-14"}
	write(t, root, tp.Text, []byte(fxTemplate))
	writeRecord(t, root, dirTemplates+"/example-chat.json", tp)

	table, _ := json.Marshal(map[string]any{"format": tableFormat, "name": "example", "tokens": fxTokens})
	tk := &TokenizerEntry{Schema: schemaTokenizer, Name: "example", Status: "active", What: "a tokenizer",
		Upstream: upstreamFixture("tokenizer.json", "", strings.Repeat("d", 64)), AlsoIdenticalAt: []Identical{}, Form: "table",
		Table: &Table{File: dirTextTok + "/example.json", SHA256: sha256Hex(table), Tokens: len(fxTokens), Unassigned: 1,
			VocabSHA256: vocabHash(fxTokens), DerivedWith: "socair feed tokenizer-table"}, Added: "2026-10-14"}
	write(t, root, tk.Table.File, table)
	writeRecord(t, root, dirTokenizers+"/example.json", tk)

	write(t, root, fileNotice, []byte(Notice([]*TemplateEntry{tp}, []*TokenizerEntry{tk})))
	return &fixture{root: root, deny1: d1, deny2: d2, tpl: tp, tok: tk}
}

func (f *fixture) problems(t *testing.T) []string {
	t.Helper()
	r, err := Load(f.root)
	if err != nil {
		t.Fatal(err)
	}
	return Validate(r)
}

func (f *fixture) save(t *testing.T) {
	t.Helper()
	writeRecord(t, f.root, dirDenylist+"/"+f.deny1.ID+".json", f.deny1)
	writeRecord(t, f.root, dirDenylist+"/"+f.deny2.ID+".json", f.deny2)
	writeRecord(t, f.root, dirTemplates+"/"+f.tpl.Name+".json", f.tpl)
	writeRecord(t, f.root, dirTokenizers+"/"+f.tok.Name+".json", f.tok)
	write(t, f.root, fileNotice, []byte(Notice([]*TemplateEntry{f.tpl}, []*TokenizerEntry{f.tok})))
}

func TestFixtureValidates(t *testing.T) {
	f := newFixture(t)
	if p := f.problems(t); len(p) > 0 {
		t.Fatalf("the fixture should validate:\n%s", strings.Join(p, "\n"))
	}
}

// The committed records must validate: this is the same check CI runs with
// `feedbuild check`, so `go test ./...` alone catches a broken record.
func TestRepositoryValidates(t *testing.T) {
	r, err := Load("../..")
	if err != nil {
		t.Fatal(err)
	}
	if p := Validate(r); len(p) > 0 {
		t.Fatalf("the repository's records do not validate:\n%s", strings.Join(p, "\n"))
	}
}

// Each case breaks one rule and names the problem it must produce. If a rule
// is removed or weakened, its case fails.
func TestEveryRuleFires(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(t *testing.T, f *fixture)
		want   string
	}{
		{"class 1 quote without the hash", func(t *testing.T, f *fixture) { f.deny1.Evidence.Source.Quote = "SHA256: elsewhere"; f.save(t) },
			"quote must show the SHA-256"},
		{"class 3 is refused", func(t *testing.T, f *fixture) { f.deny1.Evidence.Class = 3; f.save(t) },
			"evidence.class must be 1"},
		{"class 2 without hub", func(t *testing.T, f *fixture) { f.deny2.Evidence.Hub = nil; f.save(t) },
			"needs evidence.hub"},
		{"class 2 pointer mismatch", func(t *testing.T, f *fixture) { f.deny2.Evidence.Hub.BlobID = strings.Repeat("0", 40); f.save(t) },
			"is not the Git blob id"},
		{"class 2 repository changed after the report", func(t *testing.T, f *fixture) {
			f.deny2.Evidence.Hub.LastModified = "2025-01-01T00:00:00Z"
			f.save(t)
		}, "changed after the source was published"},
		{"class 2 quote does not name the repository", func(t *testing.T, f *fixture) { f.deny2.Evidence.Source.Quote = "some text"; f.save(t) },
			"must show the repository"},
		{"class 2 size differs", func(t *testing.T, f *fixture) { s := int64(1); f.deny2.Size = &s; f.save(t) },
			"size must equal evidence.hub.size"},
		{"citation without an https URL", func(t *testing.T, f *fixture) { f.deny1.Evidence.Source.URL = "http://example.com"; f.save(t) },
			"must be an https URL"},
		{"citation without a publisher", func(t *testing.T, f *fixture) { f.deny1.Evidence.Source.Publisher = ""; f.save(t) },
			"publisher must not be empty"},
		{"read before published", func(t *testing.T, f *fixture) { f.deny1.Evidence.Source.ReadOn = "2020-01-01"; f.save(t) },
			"read_on is before the source was published"},
		{"uppercase hash", func(t *testing.T, f *fixture) { f.deny1.SHA256 = strings.ToUpper(f.deny1.SHA256); f.save(t) },
			"64 lowercase hex"},
		{"duplicate hash", func(t *testing.T, f *fixture) { f.deny2.SHA256 = f.deny1.SHA256; f.save(t) },
			"also listed by"},
		{"goodware on the denylist", func(t *testing.T, f *fixture) {
			f.deny1.SHA256 = fxGoodware
			f.deny1.Evidence.Source.Quote = fxGoodware
			f.save(t)
		}, "known-good file (goodware"},
		{"a reviewed template on the denylist", func(t *testing.T, f *fixture) {
			f.deny1.SHA256 = f.tpl.SHA256
			f.deny1.Evidence.Source.Quote = f.tpl.SHA256
			f.save(t)
		}, "known-good file (template"},
		{"withdrawn without a reason", func(t *testing.T, f *fixture) { f.deny1.Status = "withdrawn"; f.save(t) },
			"needs withdrawn"},
		{"id does not match the file name", func(t *testing.T, f *fixture) {
			writeRecord(t, f.root, dirDenylist+"/SF-D-2026-0009.json", f.deny1)
			os.Remove(filepath.Join(f.root, dirDenylist, "SF-D-2026-0001.json"))
		}, "file must be named SF-D-2026-0001.json"},
		{"unknown field", func(t *testing.T, f *fixture) {
			write(t, f.root, dirDenylist+"/SF-D-2026-0001.json", []byte(`{"schema":"x","surprise":1}`))
		}, "does not parse"},
		{"not canonical", func(t *testing.T, f *fixture) {
			b, _ := canonical(f.deny1)
			write(t, f.root, dirDenylist+"/SF-D-2026-0001.json", bytes.Replace(b, []byte("  "), []byte("    "), 1))
		}, "not in canonical form"},
		{"template text changed", func(t *testing.T, f *fixture) { write(t, f.root, f.tpl.Text, []byte(fxTemplate+" ")) },
			"hashes to"},
		{"template review means something else", func(t *testing.T, f *fixture) { f.tpl.Review.Means = "looked at it"; f.save(t) },
			"word for word"},
		{"reviewed with no reviewer", func(t *testing.T, f *fixture) {
			f.tpl.Review.Status = "reviewed"
			f.tpl.Review.On = "2026-10-15"
			f.save(t)
		},
			"review.by must not be empty"},
		{"pending with a reviewer", func(t *testing.T, f *fixture) { f.tpl.Review.By = "Someone"; f.save(t) },
			"a pending review names no reviewer"},
		{"template under a license that may not ship", func(t *testing.T, f *fixture) { f.tpl.Upstream.License = "LicenseRef-llama3"; f.save(t) },
			"only Apache-2.0 and MIT"},
		{"upstream URL not at the revision", func(t *testing.T, f *fixture) { f.tpl.Upstream.URL = "https://huggingface.co/example/model"; f.save(t) },
			"upstream.url must be"},
		{"short revision", func(t *testing.T, f *fixture) { f.tpl.Upstream.Revision = "abc123"; f.save(t) },
			"full 40-character commit id"},
		{"license text is not the repository's LICENSE", func(t *testing.T, f *fixture) {
			f.tpl.Upstream.LicenseFileSHA256 = strings.Repeat("e", 64)
			f.save(t)
		}, "is not the repository's LICENSE"},
		{"table token changed", func(t *testing.T, f *fixture) {
			toks := append([]string(nil), fxTokens...)
			toks[2] = "z"
			b, _ := json.Marshal(map[string]any{"format": tableFormat, "name": "example", "tokens": toks})
			write(t, f.root, f.tok.Table.File, b)
			f.tok.Table.SHA256 = sha256Hex(b)
			f.save(t)
		}, "vocabulary hashes to"},
		{"table file changed", func(t *testing.T, f *fixture) { f.tok.Table.SHA256 = strings.Repeat("f", 64); f.save(t) },
			"not table.sha256"},
		{"table named for another tokenizer", func(t *testing.T, f *fixture) {
			b, _ := json.Marshal(map[string]any{"format": tableFormat, "name": "other", "tokens": fxTokens})
			write(t, f.root, f.tok.Table.File, b)
			f.tok.Table.SHA256 = sha256Hex(b)
			f.save(t)
		}, "must be the entry's name"},
		{"hash-only with a table", func(t *testing.T, f *fixture) { f.tok.Form = "hash-only"; f.save(t) },
			"carries no table"},
		{"orphan text", func(t *testing.T, f *fixture) {
			write(t, f.root, dirTextTpl+"/"+strings.Repeat("0", 64)+".jinja", []byte("x"))
		},
			"no source record cites this file"},
		{"stale NOTICE", func(t *testing.T, f *fixture) { write(t, f.root, fileNotice, []byte("old\n")) },
			"NOTICE: out of date"},
		{"bad goodware line", func(t *testing.T, f *fixture) { write(t, f.root, fileGoodware, []byte("nothex why\n")) },
			"want \"<sha256> <why>\""},
		{"a control character in a label field", func(t *testing.T, f *fixture) { f.deny1.File = "ws\u202e.pth"; f.save(t) },
			"control or format character"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			c.break_(t, f)
			p := f.problems(t)
			for _, s := range p {
				if strings.Contains(s, c.want) {
					return
				}
			}
			t.Fatalf("want a problem containing %q, got:\n%s", c.want, strings.Join(p, "\n"))
		})
	}
}

func readTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if !d.IsDir() {
			b, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			out[filepath.ToSlash(rel)] = string(b)
		}
		return nil
	})
	return out
}

func build(t *testing.T, f *fixture, opt Options) map[string]string {
	t.Helper()
	r, err := Load(f.root)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	if err := Build(r, out, opt); err != nil {
		t.Fatal(err)
	}
	return readTree(t, out)
}

func TestBuildIsReproducible(t *testing.T) {
	f := newFixture(t)
	a, b := build(t, f, Options{}), build(t, f, Options{})
	if len(a) == 0 {
		t.Fatal("empty build")
	}
	for name, body := range a {
		if b[name] != body {
			t.Errorf("%s differs between two builds of the same records", name)
		}
	}
	if len(a) != len(b) {
		t.Errorf("the builds hold %d and %d files", len(a), len(b))
	}
	for _, name := range []string{"feed/denylist.txt", "feed/tokenizers.txt", "feed/tokenizers/example.json", "NOTICE", "LICENSES/CC0-1.0.txt", "LICENSES/Apache-2.0.txt", "SHA256SUMS", "BUILD-REPORT.txt"} {
		if _, ok := a[name]; !ok {
			t.Errorf("the build lacks %s", name)
		}
	}
	for name := range a {
		if strings.HasPrefix(name, "feed/") && !strings.HasPrefix(name, "feed/denylist.txt") && !strings.HasPrefix(name, "feed/templates") && !strings.HasPrefix(name, "feed/tokenizers") {
			t.Errorf("feed/ holds %s, which Socair would refuse as unsigned", name)
		}
	}
	if !strings.Contains(a["SHA256SUMS"], sha256Hex([]byte(a["feed/denylist.txt"]))+"  feed/denylist.txt\n") {
		t.Error("SHA256SUMS does not name denylist.txt by its hash")
	}
}

func TestBuildLines(t *testing.T) {
	f := newFixture(t)
	a := build(t, f, Options{})
	deny := a["feed/denylist.txt"]
	for _, want := range []string{
		f.deny1.SHA256 + " SF-D-2026-0001: ws.pth (pickle checkpoint, 495 bytes), reported by Example Labs 2025-07-01, evidence class 1\n",
		f.deny2.SHA256 + " SF-D-2026-0002: pytorch_model.bin (pickle checkpoint, 231139 bytes), reported by Example Labs 2024-02-27, evidence class 2\n",
	} {
		if !strings.Contains(deny, want) {
			t.Errorf("denylist.txt lacks %q:\n%s", want, deny)
		}
	}
	tok := a["feed/tokenizers.txt"]
	for _, want := range []string{f.tok.Upstream.FileSHA256 + " example (tokenizer.json of example/model@aaaaaaaaaaaa)", f.tok.Table.VocabSHA256 + " example (vocabulary of"} {
		if !strings.Contains(tok, want) {
			t.Errorf("tokenizers.txt lacks %q:\n%s", want, tok)
		}
	}
}

// A template no person has reviewed never reaches a release build; a test
// build carries it with a label and banner that say so.
func TestUnreviewedTemplatesStayOut(t *testing.T) {
	f := newFixture(t)
	a := build(t, f, Options{})
	if _, ok := a["feed/templates.txt"]; ok {
		t.Fatal("a release build holds templates.txt with no reviewed template")
	}
	for name := range a {
		if strings.HasPrefix(name, "feed/templates/") {
			t.Fatalf("a release build holds %s", name)
		}
	}
	if !strings.Contains(a["BUILD-REPORT.txt"], "left out, review pending: example-chat") {
		t.Errorf("the build report does not name the pending template:\n%s", a["BUILD-REPORT.txt"])
	}

	test := build(t, f, Options{IncludeUnreviewed: true})
	tp := test["feed/templates.txt"]
	if !strings.HasPrefix(tp, "# TEST BUILD") || !strings.Contains(tp, "NOT REVIEWED (test build)") {
		t.Errorf("a test build's templates.txt does not say it is unreviewed:\n%s", tp)
	}
	if !strings.HasPrefix(test["feed/denylist.txt"], "# TEST BUILD") {
		t.Error("a test build's denylist.txt has no banner")
	}
	if test["feed/templates/"+f.tpl.SHA256+".jinja"] != fxTemplate {
		t.Error("a test build lacks the template text")
	}

	f.tpl.Review = Review{Means: reviewMeans, Status: "reviewed", By: "A Reviewer", On: "2026-10-15"}
	f.save(t)
	rel := build(t, f, Options{})
	if !strings.Contains(rel["feed/templates.txt"], f.tpl.SHA256+" example-chat: example/model@aaaaaaaaaaaa tokenizer_config.json chat_template, reviewed 2026-10-15 by A Reviewer\n") {
		t.Errorf("a reviewed template is not built with its reviewer:\n%s", rel["feed/templates.txt"])
	}
	if strings.Contains(rel["feed/templates.txt"], "TEST BUILD") {
		t.Error("a release build carries the test banner")
	}
}

func TestWithdrawnEntriesStayOut(t *testing.T) {
	f := newFixture(t)
	f.deny1.Status = "withdrawn"
	f.deny1.Withdrawn = &Withdrawal{On: "2026-11-01", Reason: "a false positive", Link: "https://github.com/defilantech/socair-feed/issues/1"}
	f.save(t)
	a := build(t, f, Options{})
	if strings.Contains(a["feed/denylist.txt"], f.deny1.SHA256) {
		t.Fatal("a withdrawn entry was built")
	}
	if !strings.Contains(a["BUILD-REPORT.txt"], "withdrawn, left out: SF-D-2026-0001") {
		t.Errorf("the build report does not name the withdrawn entry:\n%s", a["BUILD-REPORT.txt"])
	}
}

func TestBuildRefuses(t *testing.T) {
	f := newFixture(t)
	r, _ := Load(f.root)
	out := t.TempDir()
	write(t, out, "stale", []byte("x"))
	if err := Build(r, out, Options{}); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("a build into a non-empty directory: %v", err)
	}
	write(t, f.root, f.tpl.Text, []byte("changed"))
	r, _ = Load(f.root)
	if err := Build(r, filepath.Join(t.TempDir(), "out"), Options{}); err == nil || !strings.Contains(err.Error(), "do not validate") {
		t.Errorf("a build of invalid records: %v", err)
	}
}

func TestPackIsReproducible(t *testing.T) {
	f := newFixture(t)
	r, _ := Load(f.root)
	dir := filepath.Join(t.TempDir(), "out")
	if err := Build(r, dir, Options{}); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC)
	a, b := filepath.Join(t.TempDir(), "a.tar.gz"), filepath.Join(t.TempDir(), "b.tar.gz")
	if err := Pack(dir, a, "socair-feed-2026.10.1", at); err != nil {
		t.Fatal(err)
	}
	if err := Pack(dir, b, "socair-feed-2026.10.1", at); err != nil {
		t.Fatal(err)
	}
	ab, _ := os.ReadFile(a)
	bb, _ := os.ReadFile(b)
	if !bytes.Equal(ab, bb) {
		t.Fatal("two packs of the same directory differ")
	}
	gz, err := gzip.NewReader(bytes.NewReader(ab))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if h.Uid != 0 || h.Gid != 0 || !h.ModTime.Equal(at) {
			t.Errorf("%s: owner %d/%d, time %s", h.Name, h.Uid, h.Gid, h.ModTime)
		}
		names = append(names, h.Name)
	}
	if names[0] != "socair-feed-2026.10.1/" || !contains(names, "socair-feed-2026.10.1/feed/denylist.txt") {
		t.Errorf("unexpected entries: %v", names)
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func envelope(t *testing.T, issued, expires string) string {
	t.Helper()
	st, _ := json.Marshal(map[string]any{"_type": "https://in-toto.io/Statement/v1", "predicateType": "https://socair.ai/feed/v1",
		"predicate": map[string]string{"issuer": "Socair project feed", "version": "2026.10.1", "issued": issued, "expires": expires}})
	env, _ := json.Marshal(map[string]any{"payloadType": "application/vnd.in-toto+json", "payload": base64.StdEncoding.EncodeToString(st), "signatures": []any{}})
	p := filepath.Join(t.TempDir(), "feed.dsse.json")
	write(t, filepath.Dir(p), filepath.Base(p), env)
	return p
}

// The watch fires from the start of the last third of a feed's validity,
// where Socair starts warning sites, so the project hears first.
func TestExpiryAlarm(t *testing.T) {
	s, err := ReadStatement(envelope(t, "2026-10-01T00:00:00Z", "2026-12-30T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	day := func(d int) time.Time { return s.Issued.Add(time.Duration(d) * 24 * time.Hour) }
	for _, c := range []struct {
		at    time.Time
		alarm bool
		want  string
	}{
		{day(10), false, "in 80 days"},
		{day(59), false, "in 31 days"},
		{day(61), true, "sites are being warned"},
		{day(91), true, "EXPIRED"},
	} {
		alarm, msg := ExpiryAlarm(s, c.at)
		if alarm != c.alarm || !strings.Contains(msg, c.want) {
			t.Errorf("at %s: alarm %v, %q", c.at.Format(time.DateOnly), alarm, msg)
		}
	}
	if _, err := ReadStatement(envelope(t, "yesterday", "2026-12-30T00:00:00Z")); err == nil {
		t.Error("a statement with a bad time was read")
	}
}

func TestDiff(t *testing.T) {
	old, nw := t.TempDir(), t.TempDir()
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	write(t, old, "denylist.txt", []byte("# header\n"+a+" one\n"+b+" two\n"))
	write(t, nw, "denylist.txt", []byte(a+" one\n"+c+" three\n"))
	changes, err := Diff(old, nw)
	if err != nil {
		t.Fatal(err)
	}
	d := changes[0]
	if d.File != "denylist.txt" || len(d.Added) != 1 || len(d.Removed) != 1 || d.Added[0] != c+" three" || d.Removed[0] != b+" two" {
		t.Fatalf("diff: %+v", d)
	}
	if d.share() != 100 {
		t.Errorf("share %v, want 100 (two changes over two old entries)", d.share())
	}
}

// Known answers from the research: the Hub listed blob id e42638b2… for
// star23/baller13's pytorch_model.bin (LFS SHA-256 b36f04a7…, 231139 bytes).
func TestLFSBlobIDKnownAnswer(t *testing.T) {
	got := lfsBlobID("b36f04a774ed4f14104a053d077e029dc27cd1bf8d65a4c5dd5fa616e4ee81a4", 231139)
	if got != "e42638b28502788b8ead9a395d7962d001687c8c" {
		t.Fatalf("lfsBlobID = %s", got)
	}
}

func TestVocabHashKnownAnswer(t *testing.T) {
	if got, want := vocabHash([]string{"a", "", "b"}), sha256Hex([]byte("a\x00\x00b\x00")); got != want {
		t.Fatalf("vocabHash = %s, want %s", got, want)
	}
}

// The upstream check, against a local server standing in for the report
// sites and the Hub.
func TestCheckUpstream(t *testing.T) {
	f := newFixture(t)
	cfg, _ := json.Marshal(map[string]string{"chat_template": fxTemplate})
	f.tpl.Upstream.FileSHA256 = sha256Hex(cfg)
	pageHolds := true
	hubGone := false
	mux := http.NewServeMux()
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		if pageHolds {
			io.WriteString(w, "<p>SHA256: "+strings.ToUpper(f.deny1.SHA256)+"</p>")
		}
	})
	mux.HandleFunc("/report2", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "remains active: bad/repo") })
	mux.HandleFunc("/api/models/bad/repo", func(w http.ResponseWriter, r *http.Request) {
		if hubGone {
			http.Error(w, "gone", http.StatusUnauthorized)
			return
		}
		h := f.deny2.Evidence.Hub
		json.NewEncoder(w).Encode(map[string]any{"sha": h.Revision, "disabled": true, "siblings": []any{
			map[string]any{"rfilename": h.Path, "size": h.Size, "blobId": h.BlobID, "lfs": map[string]any{"sha256": f.deny2.SHA256, "size": h.Size}}}})
	})
	mux.HandleFunc("/example/model/resolve/"+strings.Repeat("a", 40)+"/tokenizer_config.json", func(w http.ResponseWriter, r *http.Request) { w.Write(cfg) })
	mux.HandleFunc("/example/model/resolve/"+strings.Repeat("a", 40)+"/tokenizer.json", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	defer srv.Close()
	oldBase, oldClient := hubBase, newClient
	hubBase, newClient = srv.URL, srv.Client
	defer func() { hubBase, newClient = oldBase, oldClient }()
	f.deny1.Evidence.Source.URL = srv.URL + "/report"
	f.deny2.Evidence.Source.URL = srv.URL + "/report2"
	f.save(t)

	r, err := Load(f.root)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if n := CheckUpstream(r, &out, "", "SF-D-2026-0001"); n != 0 {
		t.Errorf("a page that prints the hash: %d failures\n%s", n, out.String())
	}
	out.Reset()
	if n := CheckUpstream(r, &out, "", "SF-D-2026-0002"); n != 0 {
		t.Errorf("a Hub listing that matches: %d failures\n%s", n, out.String())
	}
	out.Reset()
	if n := CheckUpstream(r, &out, "", "example-chat"); n != 0 {
		t.Errorf("a template that matches upstream: %d failures\n%s", n, out.String())
	}
	out.Reset()
	if n := CheckUpstream(r, &out, "", "example"); n != 1 || !strings.Contains(out.String(), "404") {
		t.Errorf("a missing upstream tokenizer: %d failures\n%s", n, out.String())
	}

	pageHolds, hubGone = false, true
	out.Reset()
	if n := CheckUpstream(r, &out, "", "SF-D-2026-0001"); n != 1 || !strings.Contains(out.String(), "no longer prints") {
		t.Errorf("a page that dropped the hash: %d failures\n%s", n, out.String())
	}
	out.Reset()
	if n := CheckUpstream(r, &out, "", "SF-D-2026-0002"); n != 0 || !strings.Contains(out.String(), "note  SF-D-2026-0002 hub") {
		t.Errorf("a repository the Hub no longer serves is a note, not a failure: %d\n%s", n, out.String())
	}
	write(t, f.root, f.tpl.Text, []byte("tampered"))
	out.Reset()
	if n := CheckUpstream(r, &out, "", "example-chat"); n != 1 || !strings.Contains(out.String(), "differs from the shipped text") {
		t.Errorf("a shipped text that differs from upstream: %d\n%s", n, out.String())
	}
}
