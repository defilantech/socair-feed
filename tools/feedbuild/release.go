package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Pack writes dir as a gzip-compressed tar under prefix/, the same bytes for
// the same files: names sorted, fixed modes, owner 0, a fixed modification
// time, and no name or time in the gzip header. Only regular files and
// directories are packed; anything else is refused.
func Pack(dir, out, prefix string, mtime time.Time) error {
	if prefix == "" || strings.ContainsAny(prefix, "/\\") {
		return errors.New("pack needs a one-element -prefix, for example socair-feed-2026.10.1")
	}
	var names []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == dir {
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("%s is neither a file nor a directory", p)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(names)
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(gz)
	hdr := func(name string, mode int64, typ byte, size int64) *tar.Header {
		return &tar.Header{Name: name, Mode: mode, Typeflag: typ, Size: size, ModTime: mtime.UTC(), Format: tar.FormatPAX}
	}
	if err := tw.WriteHeader(hdr(prefix+"/", 0o755, tar.TypeDir, 0)); err != nil {
		return err
	}
	for _, name := range names {
		p := filepath.Join(dir, filepath.FromSlash(name))
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err := tw.WriteHeader(hdr(prefix+"/"+name+"/", 0o755, tar.TypeDir, 0)); err != nil {
				return err
			}
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(hdr(prefix+"/"+name, 0o644, tar.TypeReg, int64(len(b)))); err != nil {
			return err
		}
		if _, err := tw.Write(b); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return os.WriteFile(out, buf.Bytes(), 0o644)
}

// Statement is what a signed feed says about itself, read from its DSSE
// envelope without checking the signature: the expiry watch only needs the
// dates, and `socair feed verify` is the check that trusts them.
type Statement struct {
	Issuer  string
	Version string
	Issued  time.Time
	Expires time.Time
}

// ReadStatement reads feed.dsse.json.
func ReadStatement(path string) (Statement, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Statement{}, err
	}
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return Statement{}, fmt.Errorf("%s is not a DSSE envelope: %w", path, err)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Statement{}, fmt.Errorf("%s: payload is not base64: %w", path, err)
	}
	var st struct {
		PredicateType string `json:"predicateType"`
		Predicate     struct {
			Issuer  string `json:"issuer"`
			Version string `json:"version"`
			Issued  string `json:"issued"`
			Expires string `json:"expires"`
		} `json:"predicate"`
	}
	if err := json.Unmarshal(payload, &st); err != nil || st.PredicateType != "https://socair.ai/feed/v1" {
		return Statement{}, fmt.Errorf("%s does not hold a Socair feed statement", path)
	}
	issued, err1 := time.Parse(time.RFC3339, st.Predicate.Issued)
	expires, err2 := time.Parse(time.RFC3339, st.Predicate.Expires)
	if err1 != nil || err2 != nil {
		return Statement{}, fmt.Errorf("%s: issued and expires must be RFC 3339", path)
	}
	return Statement{Issuer: st.Predicate.Issuer, Version: st.Predicate.Version, Issued: issued, Expires: expires}, nil
}

// ExpiryAlarm says whether a published feed needs a new release now: it is
// in the last third of its validity, the window in which Socair itself warns
// every site that uses it, or past it, when every scan using it has stopped.
func ExpiryAlarm(s Statement, now time.Time) (bool, string) {
	life, left := s.Expires.Sub(s.Issued), s.Expires.Sub(now)
	days := func(d time.Duration) int { return int(d / (24 * time.Hour)) }
	switch {
	case left <= 0:
		return true, fmt.Sprintf("feed %s %s EXPIRED at %s: every scan that uses it has stopped. Release a new feed now.", s.Issuer, s.Version, s.Expires.Format(time.RFC3339))
	case 3*left <= life:
		return true, fmt.Sprintf("feed %s %s expires at %s, in %d days, and sites are being warned. Release a new feed now.", s.Issuer, s.Version, s.Expires.Format(time.RFC3339), days(left))
	}
	return false, fmt.Sprintf("feed %s %s expires at %s, in %d days.", s.Issuer, s.Version, s.Expires.Format(time.RFC3339), days(left))
}

// Change is how one data file differs between two feeds.
type Change struct {
	File           string
	Old, New       int
	Added, Removed []string
}

// Diff compares the line-based data files of two feed directories by hash:
// the entries a release adds and removes, which the maintainer reads before
// signing.
func Diff(oldDir, newDir string) ([]Change, error) {
	var out []Change
	for _, name := range []string{"denylist.txt", "templates.txt", "tokenizers.txt"} {
		o, err := readLines(filepath.Join(oldDir, name))
		if err != nil {
			return nil, err
		}
		n, err := readLines(filepath.Join(newDir, name))
		if err != nil {
			return nil, err
		}
		c := Change{File: name, Old: len(o), New: len(n)}
		for h, line := range n {
			if _, ok := o[h]; !ok {
				c.Added = append(c.Added, line)
			}
		}
		for h, line := range o {
			if _, ok := n[h]; !ok {
				c.Removed = append(c.Removed, line)
			}
		}
		sort.Strings(c.Added)
		sort.Strings(c.Removed)
		out = append(out, c)
	}
	return out, nil
}

// readLines maps each entry's hash to its whole line. A missing file is an
// empty one.
func readLines(p string) (map[string]string, error) {
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h, _, _ := strings.Cut(line, " ")
		out[strings.ToLower(h)] = line
	}
	return out, sc.Err()
}

// share is the part of old entries a change touches, in percent.
func (c Change) share() float64 {
	base := c.Old
	if base == 0 {
		base = 1
	}
	return 100 * float64(len(c.Added)+len(c.Removed)) / float64(base)
}

func writeDiff(w io.Writer, changes []Change) {
	for _, c := range changes {
		fmt.Fprintf(w, "%s: %d -> %d entries, %d added, %d removed (%.0f%% of the old entries)\n", c.File, c.Old, c.New, len(c.Added), len(c.Removed), c.share())
		for _, l := range c.Removed {
			fmt.Fprintf(w, "  - %s\n", l)
		}
		for _, l := range c.Added {
			fmt.Fprintf(w, "  + %s\n", l)
		}
	}
}
