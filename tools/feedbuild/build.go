package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Layout of a build's output directory. feed/ is exactly the directory
// Socair reads (SOCAIR_FEED); everything else sits beside it so the feed
// directory holds nothing its signature does not cover.
const (
	outFeed     = "feed"
	outNotice   = "NOTICE"
	outLicenses = "LICENSES"
	outReport   = "BUILD-REPORT.txt"
	outSums     = "SHA256SUMS"
)

// Options select what a build includes.
type Options struct {
	// IncludeUnreviewed builds templates no person has reviewed, for testing
	// the pipeline against Socair only. Every such line says so, and the
	// headers mark the whole build as a test build.
	IncludeUnreviewed bool
}

// Build writes the feed built from r into out, which must not exist or be
// empty. The same records always give the same bytes: entries are sorted,
// lines end in LF, and nothing records a time, a host, or a path.
func Build(r *Repo, out string, opt Options) error {
	if problems := Validate(r); len(problems) > 0 {
		return fmt.Errorf("the sources do not validate:\n  %s", strings.Join(problems, "\n  "))
	}
	if entries, err := os.ReadDir(out); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s is not empty", out)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	files := map[string][]byte{}
	report := &strings.Builder{}
	mode := "release candidate (unsigned)"
	if opt.IncludeUnreviewed {
		mode = "TEST BUILD: includes templates no person has reviewed; never sign it for release"
	}
	fmt.Fprintf(report, "socair-feed build\nmode: %s\n\n", mode)

	// denylist.txt
	var deny []string
	classes := map[int]int{}
	var withdrawn []string
	for _, e := range r.Denylist {
		if e.Status != "active" {
			withdrawn = append(withdrawn, e.ID)
			continue
		}
		deny = append(deny, e.SHA256+" "+denyLabel(e))
		classes[e.Evidence.Class]++
	}
	if len(deny) > 0 {
		files[outFeed+"/denylist.txt"] = []byte(denyHeader(opt) + strings.Join(deny, "\n") + "\n")
	}
	fmt.Fprintf(report, "denylist.txt: %d entries (evidence class 1: %d, class 2: %d)\n", len(deny), classes[1], classes[2])

	// templates.txt and templates/<sha256>.jinja
	var tpl, pending []string
	var shippedTpl []*TemplateEntry
	for _, e := range r.Templates {
		if e.Status != "active" {
			withdrawn = append(withdrawn, "template "+e.Name)
			continue
		}
		if e.Review.Status != "reviewed" && !opt.IncludeUnreviewed {
			pending = append(pending, e.Name)
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(e.Text)))
		if err != nil {
			return err
		}
		files[outFeed+"/templates/"+e.SHA256+".jinja"] = b
		tpl = append(tpl, e.SHA256+" "+templateLabel(e))
		shippedTpl = append(shippedTpl, e)
	}
	if len(tpl) > 0 {
		files[outFeed+"/templates.txt"] = []byte(templatesHeader(opt) + strings.Join(tpl, "\n") + "\n")
	}
	fmt.Fprintf(report, "templates.txt: %d reviewed templates, each with its text\n", len(tpl))
	if len(pending) > 0 {
		fmt.Fprintf(report, "  left out, review pending: %s\n", strings.Join(pending, ", "))
	}

	// tokenizers.txt and tokenizers/<name>.json
	var tok []string
	var shippedTok []*TokenizerEntry
	tables := 0
	for _, e := range r.Tokenizers {
		if e.Status != "active" {
			withdrawn = append(withdrawn, "tokenizer "+e.Name)
			continue
		}
		u := e.Upstream
		tok = append(tok, fmt.Sprintf("%s %s (%s of %s@%s)", u.FileSHA256, e.Name, u.File, u.Repo, u.Revision[:12]))
		if e.Table != nil {
			b, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(e.Table.File)))
			if err != nil {
				return err
			}
			files[outFeed+"/tokenizers/"+e.Name+".json"] = b
			tok = append(tok, fmt.Sprintf("%s %s (vocabulary of %s@%s %s, in id order)", e.Table.VocabSHA256, e.Name, u.Repo, u.Revision[:12], u.File))
			shippedTok = append(shippedTok, e)
			tables++
		}
	}
	if len(tok) > 0 {
		files[outFeed+"/tokenizers.txt"] = []byte(tokenizersHeader() + strings.Join(tok, "\n") + "\n")
	}
	fmt.Fprintf(report, "tokenizers.txt: %d hashes for %d tokenizers; %d tokenizer tables\n", len(tok), len(r.Tokenizers)-countWithdrawnTok(r), tables)
	sort.Strings(withdrawn)
	if len(withdrawn) > 0 {
		fmt.Fprintf(report, "withdrawn, left out: %s\n", strings.Join(withdrawn, ", "))
	}

	// NOTICE and the license texts the shipped copies need.
	files[outNotice] = []byte(Notice(shippedTpl, shippedTok))
	licenses := map[string]bool{fileCC0: true}
	for _, e := range shippedTpl {
		licenses[e.Upstream.LicenseText] = true
	}
	for _, e := range shippedTok {
		licenses[e.Upstream.LicenseText] = true
	}
	for p := range licenses {
		b, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(p)))
		if err != nil {
			return err
		}
		files[p] = b
	}
	files[outReport] = []byte(report.String())

	// SHA256SUMS over every other file, in sha256sum's format.
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var sums strings.Builder
	for _, name := range names {
		fmt.Fprintf(&sums, "%s  %s\n", sha256Hex(files[name]), name)
	}
	files[outSums] = []byte(sums.String())

	for name, b := range files {
		p := filepath.Join(out, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func countWithdrawnTok(r *Repo) int {
	n := 0
	for _, e := range r.Tokenizers {
		if e.Status != "active" {
			n++
		}
	}
	return n
}

// denyLabel is what a report prints for a match: the entry's id first, so a
// reader can find its record and citation, then the file, the source, and
// the evidence class.
func denyLabel(e *DenyEntry) string {
	size := ""
	if e.Size != nil {
		size = fmt.Sprintf(", %d bytes", *e.Size)
	}
	return fmt.Sprintf("%s: %s (%s%s), reported by %s %s, evidence class %d",
		e.ID, e.File, kinds[e.Kind], size, e.Evidence.Source.Publisher, e.Evidence.Source.Published, e.Evidence.Class)
}

// templateLabel names a reviewed template in a report: its upstream at the
// pinned revision and who reviewed it when.
func templateLabel(e *TemplateEntry) string {
	u := e.Upstream
	src := u.File
	if u.Field != "" {
		src += " " + u.Field
	}
	review := fmt.Sprintf("reviewed %s by %s", e.Review.On, e.Review.By)
	if e.Review.Status != "reviewed" {
		review = "NOT REVIEWED (test build)"
	}
	return fmt.Sprintf("%s: %s@%s %s, %s", e.Name, u.Repo, u.Revision[:12], src, review)
}

const repoURL = "https://github.com/defilantech/socair-feed"

func testBanner(opt Options) string {
	if !opt.IncludeUnreviewed {
		return ""
	}
	return "# TEST BUILD: includes templates no person has reviewed. Never sign it for release.\n"
}

func denyHeader(opt Options) string {
	return testBanner(opt) +
		"# Socair project feed: known-bad artifact hashes. Data: CC0-1.0.\n" +
		"# <sha256> <label>. The label starts with the entry's id; its source record,\n" +
		"# with the citation that supports it, is sources/denylist/<id>.json in\n" +
		"# " + repoURL + "\n"
}

func templatesHeader(opt Options) string {
	return testBanner(opt) +
		"# Socair project feed: reviewed chat templates. Data: CC0-1.0.\n" +
		"# <sha256> <label>. Each text is templates/<sha256>.jinja, under its upstream\n" +
		"# license (NOTICE). Review is defined in CONTRIBUTING.md of\n" +
		"# " + repoURL + "\n"
}

func tokenizersHeader() string {
	return "# Socair project feed: canonical tokenizers. Data: CC0-1.0.\n" +
		"# <sha256> <name> (<what was hashed>). A model directory's tokenizer.json is\n" +
		"# matched by file hash, a GGUF by its vocabulary hash. Tables are\n" +
		"# tokenizers/<name>.json, under their upstream licenses (NOTICE).\n"
}

// Notice is the NOTICE file for the given texts: the data dedication, then,
// for each shipped copy of upstream material, where it comes from, what was
// changed, its license, and its copyright line.
func Notice(templates []*TemplateEntry, tokenizers []*TokenizerEntry) string {
	var b strings.Builder
	b.WriteString("Socair project feed\n" + repoURL + "\n\n")
	b.WriteString("The known-bad hashes, labels, and citations (denylist.txt, templates.txt,\n" +
		"tokenizers.txt, and the source records they are built from) are dedicated\n" +
		"to the public domain under CC0 1.0 (LICENSES/CC0-1.0.txt). The build tooling\n" +
		"is licensed under the Apache License 2.0.\n\n" +
		"The files below are copies of upstream files, or are derived from them, and\n" +
		"stay under their upstream licenses. In the repository they are under texts/;\n" +
		"in a released feed, under feed/.\n")
	for _, e := range templates {
		if e.Status != "active" {
			continue
		}
		u := e.Upstream
		from := u.File
		if u.Field != "" {
			from = "the " + u.Field + " field of " + u.File
		}
		fmt.Fprintf(&b, "\ntemplates/%s.jinja\n", e.SHA256)
		fmt.Fprintf(&b, "  Copied byte for byte from %s in %s at revision %s.\n", from, u.Repo, u.Revision)
		fmt.Fprintf(&b, "  License: %s (%s). %s\n", u.License, u.LicenseText, u.Copyright)
	}
	for _, e := range tokenizers {
		if e.Status != "active" || e.Table == nil {
			continue
		}
		u := e.Upstream
		fmt.Fprintf(&b, "\ntokenizers/%s.json\n", e.Name)
		fmt.Fprintf(&b, "  Derived from %s in %s at revision %s.\n", u.File, u.Repo, u.Revision)
		fmt.Fprintf(&b, "  Changed: reduced to the vocabulary and added tokens in id order, written as a\n  %s table by `socair feed tokenizer-table`. Nothing was added.\n", tableFormat)
		fmt.Fprintf(&b, "  License: %s (%s). %s\n", u.License, u.LicenseText, u.Copyright)
	}
	return b.String()
}
