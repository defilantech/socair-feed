// Command feedbuild builds the Socair project feed from the source records in
// this repository and checks them. It writes the unsigned directory Socair
// reads as a feed (docs/feed.md in defilantech/socair); it never signs. The
// maintainer signs a candidate offline with `socair feed sign` (RELEASING.md).
//
//	feedbuild check    [-root dir]                      validate every record, text, and NOTICE
//	feedbuild fmt      [-root dir] [-w]                 list (or rewrite) records not in canonical form
//	feedbuild build    [-root dir] [-include-unreviewed] -out dir
//	feedbuild notice   [-root dir]                      print the NOTICE the records generate
//	feedbuild diff     [-max-change pct] <old feed dir> <new feed dir>
//	feedbuild pack     -prefix name [-mtime RFC3339] <dir> <out.tar.gz>
//	feedbuild expiry   [-now RFC3339] <feed.dsse.json>  exit 1 when a new release is due
//	feedbuild upstream [-root dir] [-socair path] [-only id|name]   networked re-check
//
// Everything but upstream is hermetic: no network, no clock in its output.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const usage = `usage:
  feedbuild check    [-root dir]
  feedbuild fmt      [-root dir] [-w]
  feedbuild build    [-root dir] [-include-unreviewed] -out dir
  feedbuild notice   [-root dir]
  feedbuild diff     [-max-change pct] <old feed dir> <new feed dir>
  feedbuild pack     -prefix name [-mtime RFC3339] <dir> <out.tar.gz>
  feedbuild expiry   [-now RFC3339] <feed.dsse.json>
  feedbuild upstream [-root dir] [-socair path] [-only id|name]`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	code, err := run(os.Args[1], os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "feedbuild:", err)
		if code == 0 {
			code = 1
		}
	}
	os.Exit(code)
}

func run(cmd string, args []string) (int, error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	root := fs.String("root", ".", "repository root")
	switch cmd {
	case "check":
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		r, err := Load(*root)
		if err != nil {
			return 1, err
		}
		if problems := Validate(r); len(problems) > 0 {
			for _, p := range problems {
				fmt.Println(p)
			}
			return 1, fmt.Errorf("%d problem(s)", len(problems))
		}
		fmt.Printf("ok: %d denylist, %d template, %d tokenizer records\n", len(r.Denylist), len(r.Templates), len(r.Tokenizers))
		return 0, nil

	case "fmt":
		write := fs.Bool("w", false, "rewrite records in canonical form")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		return formatRecords(*root, *write)

	case "build":
		out := fs.String("out", "", "output directory (must not exist or be empty)")
		unreviewed := fs.Bool("include-unreviewed", false, "TEST ONLY: include templates no person has reviewed")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		if *out == "" {
			return 2, errors.New("build needs -out")
		}
		r, err := Load(*root)
		if err != nil {
			return 1, err
		}
		if err := Build(r, *out, Options{IncludeUnreviewed: *unreviewed}); err != nil {
			return 1, err
		}
		b, _ := os.ReadFile(filepath.Join(*out, outReport))
		fmt.Print(string(b))
		return 0, nil

	case "notice":
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		r, err := Load(*root)
		if err != nil {
			return 1, err
		}
		fmt.Print(Notice(r.Templates, r.Tokenizers))
		return 0, nil

	case "diff":
		max := fs.Float64("max-change", 0, "exit 1 when a file's added plus removed entries exceed this percentage of its old entries (0: never)")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		if fs.NArg() != 2 {
			return 2, errors.New("diff needs <old feed dir> <new feed dir>")
		}
		changes, err := Diff(fs.Arg(0), fs.Arg(1))
		if err != nil {
			return 1, err
		}
		writeDiff(os.Stdout, changes)
		for _, c := range changes {
			if *max > 0 && c.share() > *max {
				return 1, fmt.Errorf("%s changes %.0f%% of its entries, over -max-change %.0f%%: a person must confirm a change this large", c.File, c.share(), *max)
			}
		}
		return 0, nil

	case "pack":
		prefix := fs.String("prefix", "", "top directory in the archive, for example socair-feed-2026.10.1")
		mtime := fs.String("mtime", "1970-01-01T00:00:00Z", "modification time recorded for every entry")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		if fs.NArg() != 2 {
			return 2, errors.New("pack needs <dir> <out.tar.gz>")
		}
		t, err := time.Parse(time.RFC3339, *mtime)
		if err != nil {
			return 2, fmt.Errorf("-mtime: %w", err)
		}
		return 0, Pack(fs.Arg(0), fs.Arg(1), *prefix, t)

	case "expiry":
		now := fs.String("now", "", "the time to judge by (default: the clock)")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		if fs.NArg() != 1 {
			return 2, errors.New("expiry needs <feed.dsse.json>")
		}
		at := time.Now()
		if *now != "" {
			t, err := time.Parse(time.RFC3339, *now)
			if err != nil {
				return 2, fmt.Errorf("-now: %w", err)
			}
			at = t
		}
		s, err := ReadStatement(fs.Arg(0))
		if err != nil {
			return 1, err
		}
		alarm, msg := ExpiryAlarm(s, at)
		fmt.Println(msg)
		if alarm {
			return 1, nil
		}
		return 0, nil

	case "upstream":
		socair := fs.String("socair", "", "a socair binary, to re-derive each tokenizer table from its upstream file")
		only := fs.String("only", "", "check one record, by denylist id or template/tokenizer name")
		if err := fs.Parse(args); err != nil {
			return 2, err
		}
		r, err := Load(*root)
		if err != nil {
			return 1, err
		}
		if n := CheckUpstream(r, os.Stdout, *socair, *only); n > 0 {
			return 1, fmt.Errorf("%d upstream check(s) did not hold", n)
		}
		return 0, nil
	}
	return 2, errors.New(usage)
}

// formatRecords lists, or with write rewrites, every record whose bytes are
// not its canonical form.
func formatRecords(root string, write bool) (int, error) {
	r, err := Load(root)
	if err != nil {
		return 1, err
	}
	var records []any
	for _, e := range r.Denylist {
		records = append(records, e)
	}
	for _, e := range r.Templates {
		records = append(records, e)
	}
	for _, e := range r.Tokenizers {
		records = append(records, e)
	}
	off := 0
	for _, rec := range records {
		rel := r.rel(rec)
		p := filepath.Join(root, filepath.FromSlash(rel))
		have, err := os.ReadFile(p)
		if err != nil {
			return 1, err
		}
		want, err := canonical(rec)
		if err != nil {
			return 1, err
		}
		if string(have) == string(want) {
			continue
		}
		off++
		fmt.Println(rel)
		if write {
			if err := os.WriteFile(p, want, 0o644); err != nil {
				return 1, err
			}
		}
	}
	for _, p := range r.problems {
		if !strings.Contains(p, "canonical form") {
			fmt.Println(p)
			off++
		}
	}
	if off > 0 && !write {
		return 1, fmt.Errorf("%d record(s) not in canonical form or unreadable", off)
	}
	return 0, nil
}
