# Contributing to the Socair project feed

The feed changes verdicts at every site that imports it. A known-bad entry
fails an artifact, and no acceptance clears that failure; a reviewed template
clears language leads. So every entry rests on evidence anyone can check, and
the rules below are strict on purpose.

## Proposing an entry

1. Add one source record per entry under `sources/` (see "Records" below).
   For a template or tokenizer, add its text under `texts/` too.
2. Run, from the repository root:

   ```
   go run ./tools/feedbuild fmt -w                 # canonical layout
   go run ./tools/feedbuild notice > NOTICE        # when texts/ changed
   go run ./tools/feedbuild check                  # every rule, offline
   go run ./tools/feedbuild upstream -only <id>    # re-reads your sources (network)
   ```

3. Open a pull request. Say where you found the evidence and paste the
   `upstream` output.

A contribution is a record with a link, **never a file**. A pull request that
attaches a sample of a reported file is closed without opening the sample, and
the maintainer reports the sample to the host that served it.

Each new known-bad entry and each template review waits seven days in an open
pull request before it is merged, so others can object. A file that is
circulating now can skip the wait.

## Evidence for a known-bad entry

Two classes are accepted:

1. **The source prints the hash.** A published report gives the file's
   SHA-256. The record quotes the passage that prints it (`evidence.source.quote`
   must contain the hash).
2. **The source names the repository, and the Hub gives the hash.** A
   published report names a Hugging Face repository (and the file, or the
   repository holds one file of the kind reported). The record holds what the
   Hub API returned for that file (`/api/models/<repo>?blobs=true`): revision,
   size, blob id, and the LFS SHA-256. The lookup must come after the report,
   the repository must not have changed since before the report, and the Git
   blob id of the LFS pointer built from the SHA-256 and size must equal the
   blob id the API lists. The builder recomputes that last check. The record
   keeps the API answer's fields, because the repository can be deleted later.

Refused:

- A hash that only scanners flag, with no report naming the file. A scanner
  verdict says a file can run code, not that someone used it to attack. (A
  separate scanner-corroborated list could raise a LEAD instead of a FAIL;
  that needs a Socair change first.)
- A source no one else can read: private, paywalled, or behind a login.
- A source with no first-party statement that the file is malicious.
- A test file (EICAR, scanner test repositories, proof-of-concept corpora)
  unless it is clearly labelled as a test vector, which the feed does not
  carry today.
- An MD5 or SHA-1 alone; the feed matches SHA-256.
- Payloads that never sat in a model repository (second-stage downloads from
  attacker hosts, dataset-hosted Windows payloads), for now: see D6 in
  [DECISIONS.md](DECISIONS.md).
- Any hash in `sources/goodware.txt`, or any hash a template or tokenizer
  record names. The builder refuses these.

## Templates: what review means

Every template record carries this definition, word for word, and the
builder refuses a record that changes it:

> A person read the whole template text at the pinned revision and confirmed
> that it only lays out the conversation it is given: it adds no instruction to
> the model beyond the publisher's own default system prompt and tool
> scaffolding, no branch adds text when a message contains a particular
> string, and it reaches nothing but the documented chat-template variables and
> filters. Byte identity with the upstream file and Socair's chat-template
> check are mechanical checks, listed under checks; they are not the review.

A record's `review` starts as `"status": "pending"` with no reviewer. A
template is built into a release only when `status` is `reviewed` and `by`
and `on` name the person and the date. Reviews are done by a maintainer, who
reads the text, not the notes: `checks` and `notes` are aids, written by
whoever prepared the record.

To prepare a template record:

- Pin the upstream repository at a full commit id. Cite the file and, for a
  template held in `tokenizer_config.json`, the field (`chat_template`). The
  text is the JSON-decoded string, or the `chat_template.jinja` file as it is:
  the hash covers every byte, trailing newline included.
- Run Socair's chat-template check on the text and record the result in
  `checks`:
  `SOCAIR_TEMPLATE_CORPUS=<dir with the .jinja> go test ./internal/checks/chattemplate -run RealTemplates -v`
  in a Socair checkout.
- Describe in `notes` what the template does: default system prompt, tool
  scaffolding, every condition on message text.
- An earlier upstream revision, or a variant a real artifact carries (for
  example a trailing newline added by a converter), is its own record with its
  own pin. Add one when a real artifact shows it, not speculatively.

## Tokenizers

A table is the upstream `tokenizer.json` laid out in id order by
`socair feed tokenizer-table <tokenizer.json> --name <name>`, run with the
Socair commit the record names. The record holds the upstream file's SHA-256,
the table's SHA-256, its token count, and the vocabulary hash; the builder
checks all of them, and the weekly `upstream` workflow re-derives every table
from the pinned upstream file.

When a vocabulary's license is unclear, list the tokenizer by hash only
(`"form": "hash-only"`, with the reason).

## Licenses of what ships

Only Apache-2.0 and MIT texts are copied into the feed, with the upstream
license text in `LICENSES/` and an entry in `NOTICE`. Llama, Gemma 2 and 3,
research-only, and other restricted licenses are not shipped (D8 in
[DECISIONS.md](DECISIONS.md)). By contributing a record you dedicate it under
CC0-1.0; tooling and docs are Apache-2.0 ([DATA-LICENSE.md](DATA-LICENSE.md)).

## Reporting a wrong entry

Open an issue with the entry's id or name and what is wrong. For a hostile
entry or a compromised key, use Socair's private security reporting
([SECURITY.md](https://github.com/defilantech/socair/blob/main/SECURITY.md)).

- Acknowledged within 3 business days, assessed within 10.
- An entry agreed to be wrong is removed by an out-of-cycle release within 5
  business days of agreeing. Its record stays, with `"status": "withdrawn"`
  and the reason and a link; the builder leaves it out. If the cause was a
  collision with a legitimate file, that hash goes into
  `sources/goodware.txt`.
- Sites import the new release and run `socair airlock recheck`, which clears
  a flag that rested on the removed entry. There is no site-side override:
  Socair lets no acceptance clear a FAIL, so a fast release is the remedy.

## Records

All records are JSON in the layout `feedbuild fmt -w` writes; unknown fields
are refused. Dates are `YYYY-MM-DD`. Every URL is https.

Denylist (`sources/denylist/<id>.json`): `schema`
(`socair-feed/denylist-entry/v1`), `id` (`SF-D-<year added>-<4 digits>`, also
the file name), `status` (`active` or `withdrawn`), `sha256`, `file`, `size`
(bytes, or `null` when the source does not give it), `kind`
(`pickle-checkpoint`, `weights`, `loader-script`, `executable`, `other`),
`what`, `evidence` (`class`, `basis`, `source` {`publisher`, `title`, `url`,
`published`, `read_on`, `quote`}, and for class 2 `hub` {`repo`, `path`,
`revision`, `api_url`, `read_on`, `size`, `blob_id`, `disabled`,
`last_modified`}), `added`, and `withdrawn` {`on`, `reason`, `link`} when
withdrawn.

Template (`sources/templates/<name>.json`): `schema`
(`socair-feed/template-entry/v1`), `name`, `status`, `sha256`, `bytes`, `text`
(`texts/templates/<sha256>.jinja`), `what`, `upstream` {`repo`, `revision`,
`file`, `field` (when the template is a JSON field), `url`, `file_sha256`,
`file_bytes`, `read_on`, `license` (SPDX), `license_evidence`, `license_text`,
`license_file_sha256` (when the repository has a LICENSE file), `copyright`},
`also_identical_at` (other pinned files with the same text), `checks`,
`notes`, `review` {`means`, `status`, `by`, `on`}, `added`.

Tokenizer (`sources/tokenizers/<name>.json`): `schema`
(`socair-feed/tokenizer-entry/v1`), `name` (lowercase `[a-z0-9._-]`, the
table's file name), `status`, `what`, `upstream` (as for templates, without
`field`), `also_identical_at`, `form` (`table` or `hash-only`), `table`
{`file`, `sha256`, `tokens`, `unassigned`, `vocab_sha256`, `derived_with`} or
`null`, `hash_only_reason` (for `hash-only`), `added`.

## Sign-off and AI assistance

As in Socair: sign off every commit with the Developer Certificate of Origin
(`git commit -s`); the `dco` check enforces it. Commit messages carry no
attribution trailers. If an AI tool generated or substantially assisted any
part of a contribution, say so in the pull request description, with what it
produced and what you checked. A person is accountable for every record,
however it was produced.
