package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Schema names of the three source records. A record's "schema" field must
// hold its kind's name exactly.
const (
	schemaDenylist  = "socair-feed/denylist-entry/v1"
	schemaTemplate  = "socair-feed/template-entry/v1"
	schemaTokenizer = "socair-feed/tokenizer-entry/v1"
)

// Directories of the repository the builder reads.
const (
	dirDenylist   = "sources/denylist"
	dirTemplates  = "sources/templates"
	dirTokenizers = "sources/tokenizers"
	fileGoodware  = "sources/goodware.txt"
	dirTextTpl    = "texts/templates"
	dirTextTok    = "texts/tokenizers"
	dirLicenses   = "LICENSES"
	fileNotice    = "NOTICE"
	fileCC0       = "LICENSES/CC0-1.0.txt"
)

// reviewMeans is what a template entry's review is, word for word. Every
// template record carries it, so a reader of any one record knows what
// "reviewed" claims without looking elsewhere, and the builder holds every
// record to the same definition.
const reviewMeans = "A person read the whole template text at the pinned revision and confirmed that it only lays out the conversation it is given: it adds no instruction to the model beyond the publisher's own default system prompt and tool scaffolding, no branch adds text when a message contains a particular string, and it reaches nothing but the documented chat-template variables and filters. Byte identity with the upstream file and Socair's chat-template check are mechanical checks, listed under checks; they are not the review."

// Citation is the published source a denylist entry rests on.
type Citation struct {
	Publisher string `json:"publisher"`
	Title     string `json:"title"`
	URL       string `json:"url"`
	Published string `json:"published"`
	ReadOn    string `json:"read_on"`
	// Quote is the passage of the source that prints the hash (class 1) or
	// names the repository (class 2), as the page shows it.
	Quote string `json:"quote"`
}

// HubRecord is what the Hugging Face Hub API returned for the file a class 2
// entry hashes, kept because a repository can be deleted after the lookup.
type HubRecord struct {
	Repo     string `json:"repo"`
	Path     string `json:"path"`
	Revision string `json:"revision"`
	APIURL   string `json:"api_url"`
	ReadOn   string `json:"read_on"`
	// Size and BlobID are the file's size and Git blob id as the API lists
	// them. The blob id of an LFS file is the SHA-1 of its pointer, which
	// names the SHA-256 and the size; the builder recomputes it.
	Size         int64  `json:"size"`
	BlobID       string `json:"blob_id"`
	Disabled     bool   `json:"disabled"`
	LastModified string `json:"last_modified"`
}

// Evidence says why a hash is known-bad.
type Evidence struct {
	// Class is 1 when the source prints the SHA-256, 2 when the source names
	// the repository and the Hub API gives the SHA-256 of its file.
	Class  int        `json:"class"`
	Basis  string     `json:"basis"`
	Source Citation   `json:"source"`
	Hub    *HubRecord `json:"hub,omitempty"`
}

// Withdrawal records why an entry left the feed. A withdrawn record stays in
// the repository and is never built.
type Withdrawal struct {
	On     string `json:"on"`
	Reason string `json:"reason"`
	Link   string `json:"link"`
}

// DenyEntry is one known-bad file.
type DenyEntry struct {
	Schema    string      `json:"schema"`
	ID        string      `json:"id"`
	Status    string      `json:"status"`
	SHA256    string      `json:"sha256"`
	File      string      `json:"file"`
	Size      *int64      `json:"size"`
	Kind      string      `json:"kind"`
	What      string      `json:"what"`
	Evidence  Evidence    `json:"evidence"`
	Added     string      `json:"added"`
	Withdrawn *Withdrawal `json:"withdrawn,omitempty"`
}

// Upstream pins the file a template text or tokenizer table comes from.
type Upstream struct {
	Repo     string `json:"repo"`
	Revision string `json:"revision"`
	File     string `json:"file"`
	// Field is "chat_template" when the template is a string field of the
	// JSON file, and empty when the file itself is the template.
	Field      string `json:"field,omitempty"`
	URL        string `json:"url"`
	FileSHA256 string `json:"file_sha256"`
	FileBytes  int64  `json:"file_bytes"`
	ReadOn     string `json:"read_on"`
	// License is an SPDX id. LicenseText is the copy under LICENSES/ that
	// ships with the text; LicenseFileSHA256 is the SHA-256 of the
	// repository's own LICENSE file at the revision, when it has one, and
	// then LicenseText must be that file.
	License           string `json:"license"`
	LicenseEvidence   string `json:"license_evidence"`
	LicenseText       string `json:"license_text"`
	LicenseFileSHA256 string `json:"license_file_sha256,omitempty"`
	Copyright         string `json:"copyright"`
}

// Identical names another upstream file found to carry the same bytes.
type Identical struct {
	Repo     string `json:"repo"`
	Revision string `json:"revision"`
	File     string `json:"file"`
	Field    string `json:"field,omitempty"`
	ReadOn   string `json:"read_on"`
	How      string `json:"how"`
}

// How an Identical was established.
const (
	howDownloaded = "downloaded and compared"
	howHubLFS     = "Hub API LFS SHA-256"
)

// Review records whether a person has reviewed a template, in the sense of
// reviewMeans.
type Review struct {
	Means  string `json:"means"`
	Status string `json:"status"`
	By     string `json:"by"`
	On     string `json:"on"`
}

// TemplateEntry is one chat template offered as reviewed.
type TemplateEntry struct {
	Schema          string      `json:"schema"`
	Name            string      `json:"name"`
	Status          string      `json:"status"`
	SHA256          string      `json:"sha256"`
	Bytes           int64       `json:"bytes"`
	Text            string      `json:"text"`
	What            string      `json:"what"`
	Upstream        Upstream    `json:"upstream"`
	AlsoIdenticalAt []Identical `json:"also_identical_at"`
	Checks          []string    `json:"checks"`
	Notes           string      `json:"notes"`
	Review          Review      `json:"review"`
	Added           string      `json:"added"`
	Withdrawn       *Withdrawal `json:"withdrawn,omitempty"`
}

// Table describes a canonical tokenizer table under texts/tokenizers/.
type Table struct {
	File        string `json:"file"`
	SHA256      string `json:"sha256"`
	Tokens      int    `json:"tokens"`
	Unassigned  int    `json:"unassigned"`
	VocabSHA256 string `json:"vocab_sha256"`
	DerivedWith string `json:"derived_with"`
}

// TokenizerEntry is one canonical tokenizer.
type TokenizerEntry struct {
	Schema          string      `json:"schema"`
	Name            string      `json:"name"`
	Status          string      `json:"status"`
	What            string      `json:"what"`
	Upstream        Upstream    `json:"upstream"`
	AlsoIdenticalAt []Identical `json:"also_identical_at"`
	Form            string      `json:"form"`
	Table           *Table      `json:"table"`
	HashOnlyReason  string      `json:"hash_only_reason,omitempty"`
	Added           string      `json:"added"`
	Withdrawn       *Withdrawal `json:"withdrawn,omitempty"`
}

// Repo is the repository's sources as read, before validation.
type Repo struct {
	Root       string
	Denylist   []*DenyEntry
	Templates  []*TemplateEntry
	Tokenizers []*TokenizerEntry
	// Goodware maps a hash that must never be denylisted to why.
	Goodware map[string]string
	// path names each record's file, relative to Root, for messages.
	path map[any]string
	// problems found while reading: unparseable or non-canonical records.
	problems []string
}

// Load reads every source record under root. A record that does not parse is
// a problem reported by Validate, not an error here, so one run lists them
// all.
func Load(root string) (*Repo, error) {
	r := &Repo{Root: root, Goodware: map[string]string{}, path: map[any]string{}}
	if err := loadDir(r, dirDenylist, func(rel string, b []byte) error {
		e := new(DenyEntry)
		if err := r.decode(rel, b, e); err != nil {
			return err
		}
		r.Denylist = append(r.Denylist, e)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := loadDir(r, dirTemplates, func(rel string, b []byte) error {
		e := new(TemplateEntry)
		if err := r.decode(rel, b, e); err != nil {
			return err
		}
		r.Templates = append(r.Templates, e)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := loadDir(r, dirTokenizers, func(rel string, b []byte) error {
		e := new(TokenizerEntry)
		if err := r.decode(rel, b, e); err != nil {
			return err
		}
		r.Tokenizers = append(r.Tokenizers, e)
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Slice(r.Denylist, func(i, j int) bool { return r.Denylist[i].ID < r.Denylist[j].ID })
	sort.Slice(r.Templates, func(i, j int) bool { return r.Templates[i].Name < r.Templates[j].Name })
	sort.Slice(r.Tokenizers, func(i, j int) bool { return r.Tokenizers[i].Name < r.Tokenizers[j].Name })
	return r, loadGoodware(r)
}

// loadDir reads every file of one record directory. Only .json files belong
// there.
func loadDir(r *Repo, dir string, add func(rel string, b []byte) error) error {
	entries, err := os.ReadDir(filepath.Join(r.Root, dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		rel := dir + "/" + e.Name()
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			r.problems = append(r.problems, rel+": only .json source records belong in "+dir)
			continue
		}
		b, err := os.ReadFile(filepath.Join(r.Root, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if err := add(rel, b); err != nil {
			r.problems = append(r.problems, rel+": "+err.Error())
		}
	}
	return nil
}

// decode reads one record strictly: no unknown field, nothing after it, and
// the bytes must be the record's canonical form, so every record diffs the
// same way in review.
func (r *Repo) decode(rel string, b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("does not parse: %w", err)
	}
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("holds more than one JSON value")
	}
	r.path[v] = rel
	want, err := canonical(v)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, want) {
		r.problems = append(r.problems, rel+": not in canonical form (run: go run ./tools/feedbuild fmt -w)")
	}
	return nil
}

// canonical is a record's one accepted layout: the struct's field order,
// two-space indent, no HTML escaping, and a final newline.
func canonical(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// loadGoodware reads sources/goodware.txt: "<sha256> <why>" per line.
func loadGoodware(r *Repo) error {
	f, err := os.Open(filepath.Join(r.Root, fileGoodware))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, why, _ := strings.Cut(line, " ")
		if !isSHA256(h) || strings.TrimSpace(why) == "" {
			r.problems = append(r.problems, fmt.Sprintf("%s line %d: want \"<sha256> <why>\"", fileGoodware, n))
			continue
		}
		r.Goodware[h] = strings.TrimSpace(why)
	}
	return sc.Err()
}

// rel names a record's file for a message.
func (r *Repo) rel(v any) string { return r.path[v] }
