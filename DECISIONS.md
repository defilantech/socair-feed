# Decisions

The decisions this repository was built on, each with its reason and its
state. D1 to D13 are the ones the research for Socair issue #159 left to the
maintainer (section 5 of that report); the pipeline uses the report's
recommendation for each as the default. L1 to L12 are choices made while
building it.

**Every decision here is proposed, not confirmed.** The repository was set up
while the maintainer was away. "Confirm" means the maintainer must agree, or
change it, before the first signed release. "Taken" means it is an
implementation choice that can be changed later without affecting any site.

## From the research (D1 to D13)

### D1. Repository, issuer name, and data license: confirm

- Repository `defilantech/socair-feed`. Issuer string, as every report's
  `scope.reference_data` will print it: **`Socair project feed`**, not a
  company name, because Socair's governance says Defilan never issues
  attestations for others.
- Licenses: build tooling and docs Apache-2.0 (`LICENSE`); source records
  (hashes, citations, and their other factual fields) CC0-1.0
  (`LICENSES/CC0-1.0.txt`); upstream texts (templates and tokenizer tables)
  under their upstream licenses, with copies in `LICENSES/` and a generated
  `NOTICE`. `DATA-LICENSE.md` maps paths to terms.
- Two limits stated there: short quotations of reports in the records stay the
  publishers' words and are not dedicated to the public domain, and CC0 grants
  nothing in any cited work.
- Why: a site should be able to copy the hashes into its own tooling without
  carrying terms; upstream texts can only be passed on under the terms they
  came with.
- Counsel should read the research report's section 2.2 (what the model
  licenses say about templates and tokenizers) and this split before the first
  release.

### D2. Signer, reviewer, and continuity: confirm

- One offline Ed25519 key, made with `socair key gen` and held only by the
  maintainer. CI never holds a signing key: it builds an unsigned candidate,
  and the maintainer rebuilds, verifies, and signs offline (`RELEASING.md`).
- No backup public key is published at launch. `SOCAIR_FEED_KEYS` trusts every
  key it lists, so a backup key with weaker custody than the primary would be
  the weaker point.
- Reviewer: the maintainer reviews every entry. No deputy is named; one should
  be found before the first renewal if possible.
- Continuity rule (proposed): if no release has been published for 60 days,
  the README says so and tells sites that, at expiry, their scans stop until
  they import a newer feed or unset `SOCAIR_FEED` (which returns the
  Known-bad row to NOT_TESTED).
- Why: the signature is what makes the data trusted, and a template entry can
  clear a language lead, so the key belongs off any machine a workflow can
  reach. The format has one signature, so "CI built it and a person approved
  it" is expressed by splitting build and signing, not inside the format.

### D3. Cadence and expiry: confirm

- A release every month, each expiring 90 days after it is issued. Emergency
  releases (a removal, or a hash for a file circulating now) go out of cycle
  on the same expiry rule.
- Socair warns sites from the last third of a feed's validity (30 days for a
  90-day feed), so a site that misses two monthly releases hears about it
  before its scans stop.
- The weekly `upstream` workflow fails from the same point, so the project
  hears first (Sigstore's 2022 outage was an expiry nobody was paged about).
- Why: an expired feed stops every scan that uses it, so the expiry must
  outlast an air-gapped site's import cycle; a stolen key or a bad entry is
  bounded by the same 90 days.

### D4. Evidence classes: confirm

- Accepted: class 1 (the source prints the file's SHA-256) and class 2 (the
  source names the repository, and the Hub API gives the SHA-256 of the file
  there, with the LFS pointer tied to the listed blob id). Nothing else.
- Refused: a hash only scanners flag. The seven `star23` hashes the research
  held back (repositories no report names) are not included.
- Why: a denylist match is a FAIL that no acceptance clears. The Hub's own
  docs call its scanners best-effort, and an unreviewed machine source put a
  FastAPI release on the OpenSSF malicious-packages list in May 2026. A
  scanner-only list could become a separate list that raises a LEAD, which is
  a Socair check-set change, not a denylist line.

### D5. Format changes to Socair: confirm none are needed for launch

- (a) rollback protection and (b) the near-expiry warning were merged in
  Socair #232. The pipeline relies on both (`RELEASING.md`, "Withdrawing a
  release").
- (c) a signed per-entry citation file, (d) more than one signature, and (e) a
  key-succession record are not needed for launch: every label starts with the
  entry's id, and the citation is the record of that id in this repository.
- Why: the format already carries a label per line, which is enough to point a
  report's reader at the evidence.

### D6. Non-model payloads: confirm

- Included: the four non-model files that sat in a Hugging Face repository,
  where an intake could meet them: Rapid7's ELF beacon `ws_linux_amd64`
  (SF-D-2026-0004), and HiddenLayer's two `loader.py` and `start.bat`
  (SF-D-2026-0005 to 0007).
- Left out, each confirmed on its page on 2026-10-14 and listed here so it can
  be added as a record if a site asks:

  | Source | SHA-256 | File | Why left out |
  |---|---|---|---|
  | HiddenLayer 2026-05-07 | `04f0569971ac7ff81c8656e8453a69189d8870040044909dad45c04c567e7564` | update.bat | served from an attacker domain, never in a repository |
  | HiddenLayer 2026-05-07 | `ba67720dd115293ec5a12d08be6b0ee982227a4c5e4662fb89269c76556df6e0` | infostealer payload | as above |
  | HiddenLayer 2026-05-07 | `c1b59cc25bdc1fe3f3ce8eda06d002dda7cb02dea8c29877b68d04cd089363c7` | unnamed payload | as above |
  | Acronis 2026-04-30 | `b5da6ffa5f85aa5016fbc02a3122361c85d21192c45df9544099d13e6ff84c36` | Bao_Cao_Tai_Chinh_2024.pdf.lnk | Windows payloads staged in Hub dataset repositories, not model files |
  | Acronis 2026-04-30 | `e84b1e2c432b2394c403b524b8361ffa9923a022eb05215f1dc811bc167c3c5e` | CDC1.bat | as above |
  | Acronis 2026-04-30 | `d42aecf76fb1531cd5b7139e669910b2fd82a90b7e11448128e226775bf5d42e` | xt53.bat | as above |
  | Acronis 2026-04-30 | `579a82dde4425d95e20a22171be0a37702c833fdca6e5e04f69099a025863136` | StartGD22OR21.bat | as above |
  | Acronis 2026-04-30 | `462af0a3a9094d44c30cc65544ec1171a62365cff09e67f5e87e061a3d604bd0` | WindowsDefender.exe | as above |

- Why: they add to the count without adding model-supply-chain value, and a
  larger N in "no entry matched among N" would overstate coverage (D7).

### D7. What a PASS tells the reader: confirm the description

- The row reads "no entry matched among 11 known-bad hashes (feed Socair
  project feed <version>)". Nothing in this repository claims coverage.
- Proposed `--description` at signing: "Known-bad hashes from published
  reports of malicious model files (11 entries, sources dated 2024-02-27 to
  2026-05-07); reviewed chat templates; canonical tokenizers. Exact-hash
  matching: any change to a file's bytes defeats it. No floor; not a measure
  of coverage." The report names the feed's version and issue date.
- No floor below which the row stays NOT_TESTED.
- Why: the list is truthful and small. Saying how small, and when it was
  issued, is the honest form.

### D8. Gated and restricted families: confirm

- Left out: Llama 3.x and 4, Gemma 2, 3, and 3n (gated; their licenses do not
  say whether a template or tokenizer is covered); Qwen2.5-3B and -72B (Qwen
  Research License, Qwen License); Mistral Research and Non-Production License
  models; the original DeepSeek-V3 template (separate model license); the
  DeepSeek-R1 distills (not checked).
- Included: Gemma 4 (`license: apache-2.0`, and its license page is the Apache
  text, both read on 2026-10-14).
- Phi-3-mini's tokenizer is hash-only: its `tokenizer.model` is byte-identical
  to the LLaMA `tokenizer.model`, so the vocabulary may carry LLaMA-family
  terms as well as the repository's MIT license. Its template ships.
- The builder enforces the shipped side: only Apache-2.0 and MIT texts can be
  built into a feed.
- Why: a bare hash with a citation copies nothing; a text copies the work.
  Revisit with counsel's reading.

### D9. Template variants: confirm

- A variant (for example the same text with or without a trailing newline) is
  a separate entry with its own upstream pin, added only when a real artifact
  shows it. None is seeded.
- An earlier upstream revision is a separate entry too, cited at that
  revision. One is seeded, `qwen2.5-instruct-2024-09-18`: Qwen's own GGUF of
  Qwen2.5-0.5B-Instruct carries the template Qwen published before its
  2024-09-19 fix, so a template list with only the current text matches none
  of it (seen in the end-to-end test).
- Why: no Socair code change, and every entry stays tied to text a publisher
  actually shipped.

### D10. Response times and comment period: confirm

- A report of a wrong entry is acknowledged within 3 business days and
  assessed within 10, as in Socair's `SECURITY.md`; an entry agreed to be
  wrong is removed by an out-of-cycle release within 5 business days.
- A new denylist entry or template review waits 7 days in an open pull
  request before it is merged, except for a file circulating now.
- Open question: whether the seed entries in this first pull request get the
  same 7 days.

### D11. Outside contributors: confirm

- Open to pull requests from the start, under the evidence policy in
  `CONTRIBUTING.md` and the comment period, since issue #159 asks for a feed
  built in the open.

### D12. Where the builder lives: taken

- In this repository, as a Go program using only the standard library
  (`tools/feedbuild`). It does not import Socair (Socair's `internal/`
  packages cannot be imported, and its CLI is a harness). It reimplements only
  two small, pinned formulas (Socair's vocabulary hash and the Git LFS blob
  id), each with a known-answer test, and shells out to a `socair` binary only
  in the networked check that re-derives tokenizer tables.

### D13. A site-local way to neutralize one entry: confirm none

- None. A wrong entry is removed by a fast release; `CONTRIBUTING.md` and
  `RELEASING.md` say so.
- Why: a local override would contradict Socair's rule that no acceptance
  clears a FAIL.

## Made while building (L1 to L12)

### L1. Source records are JSON: taken

JSON, strictly decoded (no unknown field), in one canonical layout the builder
enforces (`feedbuild fmt -w`). YAML would read better but needs a parser
outside the standard library. Revisit if contributors find JSON a barrier.

### L2. Entry ids: taken

Denylist ids are `SF-D-<year added>-<sequence>` (SF-D-2026-0001 to 0011), and
every label starts with the id. Templates and tokenizers are named
(`qwen3`, `gpt-oss`), and a tokenizer's name is its table's file name, as
Socair requires.

### L3. No template ships until a person reviews it: confirm

- A template record's `review.status` is `pending` until a named person
  reviews it; the builder leaves pending templates out of every release build.
- All 13 seed templates are pending. What was done for each is recorded in
  its `checks` (byte identity with upstream at the pinned revision; Socair's
  chat-template check over its probe conversations, all PASS with nothing
  added under a content condition) and its `notes` (what the template does,
  as a reading aid). Neither is a review.
- So the first release carries no templates unless the maintainer reviews
  them first. Either is a valid first release; the maintainer decides.
- `feedbuild build -include-unreviewed` exists for testing the pipeline only:
  every line of such a build says `NOT REVIEWED (test build)` and every data
  file starts with a TEST BUILD banner.

### L4. What review means: confirm the wording

The definition every template record carries, word for word (the builder
refuses any other):

> A person read the whole template text at the pinned revision and confirmed
> that it only lays out the conversation it is given: it adds no instruction to
> the model beyond the publisher's own default system prompt and tool
> scaffolding, no branch adds text when a message contains a particular
> string, and it reaches nothing but the documented chat-template variables and
> filters. Byte identity with the upstream file and Socair's chat-template
> check are mechanical checks, listed under checks; they are not the review.

### L5. Two tokenizer hashes per table: taken, may be revised

`tokenizers.txt` lists each upstream `tokenizer.json`'s SHA-256 (what a model
directory scan matches) and the vocabulary hash of the same tokens in id order
(what a GGUF scan computes). The end-to-end test showed the second rarely
matches a GGUF: llama.cpp pads the vocabulary to the model's `vocab_size`
(Qwen's own 0.5B GGUF has 271 padding tokens), so the hash differs while the
table comparison reports 100% agreement. Both lines are informational; the
table is the useful signal. Drop the vocabulary lines if they confuse readers.

### L6. Release layout: confirm

- A build writes `feed/` (exactly the directory `SOCAIR_FEED` names) with
  `NOTICE`, `LICENSES/`, `BUILD-REPORT.txt`, and `SHA256SUMS` beside it, not
  inside it, so the signed directory holds only what its signature covers.
- A release's assets: `socair-feed-<version>.tar.gz` (made by
  `feedbuild pack`, byte-reproducible), its `.sha256`, and the bare
  `feed.dsse.json` (which the expiry watch reads). Tag `v<version>`.

### L7. Version scheme: confirm

`YYYY.MM.N` (`2026.11.1`, then `2026.11.2` for an emergency release in the
same month). Socair orders feeds by their signed issue time, not by version,
so the scheme is for people.

### L8. Supported Socair releases: taken

The feed format used (template texts and tokenizer tables) loads in Socair
v0.1.0-rc.3 and later. CI signs the candidate with a throwaway key and loads
it in v0.1.0-rc.3 and in main at `ddfe650b5f50`. Rollback protection and the
expiry warning (#232) are in main only; no Socair release has them yet.

### L9. Goodware: taken

`sources/goodware.txt` holds hashes that can never be denylisted: the empty
file and the LLaMA `tokenizer.model` (present both in Phi-3-mini and in the
reported `star23`, `glockr1`, and `who-r-u0000` repositories). The builder
also refuses any denylist hash that a template or tokenizer record names.

### L10. Tokenizer tables are committed: taken

The tables (17 MB) are committed, as `socair feed tokenizer-table` wrote them
at `ddfe650b5f50`, so a build needs no network and is reproducible. The weekly
`upstream` workflow downloads each pinned `tokenizer.json` and re-derives its
table byte for byte. A Socair change to the table writer shows up there.

### L11. Mistral's tekken.json is not listed: taken

Socair reads `tokenizer.json`, so the Mistral entries hash and derive from
`tokenizer.json`. The research's note that Mistral names `mistral-common` as
the source of truth applies to `tekken.json`, which no Socair check reads.

### L12. The upstream workflow only reports: taken

It runs weekly with read-only permissions and fails when a check does not
hold; it opens no issues. A report page that a runner cannot reach (some sites
block datacenter clients) fails it too, so a failure means "look", not
"remove".
