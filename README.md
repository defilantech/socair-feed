# Socair project feed

Signed reference data for [Socair](https://github.com/defilantech/socair):
hashes of known-bad model files, reviewed chat templates, and canonical
tokenizer tables. A site imports it as a feed (`SOCAIR_FEED`), and Socair's
Known-bad hash match, Chat template, and Tokenizer config rows compare every
scanned artifact against it. Without a feed the Known-bad row is NOT_TESTED in
every report; this repository exists so that it need not be
([defilantech/socair#159](https://github.com/defilantech/socair/issues/159)).

Every entry is a source record in `sources/` that cites where it came from,
and every release is built from those records by a reproducible build and
signed offline by the maintainer.

**Status: no release yet.** The first signed release waits for the
maintainer to confirm the decisions in [DECISIONS.md](DECISIONS.md), create
the signing key, and decide whether to review the template entries first
([RELEASING.md](RELEASING.md)).

## What it holds

| Data | Entries | Built from |
|---|---|---|
| `denylist.txt` | 11 known-bad file hashes: 7 printed by the reports that analyse the files (Rapid7, HiddenLayer), 4 returned by the Hugging Face API for files in repositories the reports name (JFrog, ReversingLabs) | `sources/denylist/` |
| `templates.txt`, `templates/<sha256>.jinja` | 13 chat templates copied from Qwen, OpenAI gpt-oss, Microsoft Phi, DeepSeek, Mistral, and Google Gemma 4 repositories at pinned revisions. **All awaiting review**: none is built into a release until a person has reviewed it | `sources/templates/`, `texts/templates/` |
| `tokenizers.txt`, `tokenizers/<name>.json` | 11 canonical tokenizers from the same families: 10 vocabulary tables derived from the upstream `tokenizer.json`, and 1 listed by hash only | `sources/tokenizers/`, `texts/tokenizers/` |

No file the denylist names is stored here, and none ever will be: a record
holds a hash and a citation, never a sample.

## What it claims, and what it does not

- **Known-bad hash match FAIL**: the artifact's bytes are exactly a file that
  a cited, published report names as malicious (evidence class 1 or 2 in
  [CONTRIBUTING.md](CONTRIBUTING.md)). The report's row prints the entry's id;
  its record here holds the citation.
- **Known-bad hash match PASS**: the artifact's SHA-256 is not among the
  feed's known-bad hashes, and the row says how many there are. It does not
  mean the artifact is safe. The list is small, it matches exact bytes only (a
  one-byte change defeats it), and it says nothing about files no report has
  named. Socair's pickle and structure checks, not this list, are the main
  defence; the list adds "this is a file a named incident used", which a
  security team can cite.
- **Reviewed template**: a person read the whole upstream text and confirmed
  it only lays out the conversation (the full definition is in every template
  record and in [CONTRIBUTING.md](CONTRIBUTING.md)). An artifact whose template
  is byte-identical to one gets its language leads cleared; code-execution
  reach still fails, as Socair's `docs/feed.md` says. A reviewed template says
  nothing about the model's weights.
- **Canonical tokenizer**: the vocabulary of a named upstream file at a pinned
  revision. Socair diffs a model's vocabulary against it; a changed ordinary
  token is a LEAD for a person to look at, not a verdict.
- Nothing here comes from scanner verdicts alone, from private or paywalled
  sources, or from contributed samples.

## Using it with Socair

Socair v0.1.0-rc.3 and later read this format. Rollback protection and the
expiry warning ([Socair #232](https://github.com/defilantech/socair/pull/232))
are in Socair's main branch and will be in the next release.

On a connected machine:

```
gh release download v<version> --repo defilantech/socair-feed
sha256sum --check socair-feed-<version>.tar.gz.sha256
```

Get the feed's public key by a second route (this repository's `keys/`,
Socair's `docs/feed.md`, and the release notes all print its key id), and
compare the key id `socair feed verify` prints with it.

On the intake host:

```
tar -xzf socair-feed-<version>.tar.gz
socair feed verify socair-feed-<version>/feed --keys feed-keys/
export SOCAIR_FEED=$PWD/socair-feed-<version>/feed
export SOCAIR_FEED_KEYS=$PWD/feed-keys
socair scan --store <store> model.gguf      # a store refuses an older feed than it has used
socair airlock recheck                      # re-check promoted models against the new denylist
```

The report names the feed in `scope.reference_data` (issuer
`Socair project feed`, version, issue and expiry times, key id). Keep the
previous release's directory until the new one has been used once.

## Releases

- **Cadence**: one release a month; each expires 90 days after it is issued.
  Socair warns from 30 days before expiry. A wrong entry is removed by an
  out-of-cycle release, never by asking sites to go back to an older one
  (a store refuses that).
- **Build**: CI builds the unsigned candidate from `sources/` twice and fails
  if the builds differ by a byte, checks it loads in the supported Socair
  releases, and uploads it as a workflow artifact. It holds no key.
- **Signing**: the maintainer rebuilds the same commit locally, compares it
  with CI's candidate, reads every added and removed entry, and signs offline
  with `socair feed sign` using an Ed25519 key that never touches CI.
  [RELEASING.md](RELEASING.md) has the steps.
- **Verifying a release yourself**: check out the release's tag, run
  `go run ./tools/feedbuild build -out /tmp/rebuild`, and compare every data
  file with the release's `feed/` directory: they must be byte-identical
  (`feed.dsse.json`, which carries the signing time, is the only addition).

## Repository layout

```
sources/denylist/<id>.json        one known-bad file per record, with its evidence
sources/templates/<name>.json     one chat template per record, with its upstream pin and review state
sources/tokenizers/<name>.json    one tokenizer per record, with its upstream pin and table
sources/goodware.txt              hashes that can never be denylisted
texts/templates/<sha256>.jinja    template texts, under their upstream licenses
texts/tokenizers/<name>.json      tokenizer tables, under their upstream licenses
tools/feedbuild/                  the builder and checker (Go, standard library only)
LICENSES/, NOTICE                 license texts and attributions for texts/
DECISIONS.md                      the decisions this is built on, and their state
```

`go run ./tools/feedbuild check` validates everything; `build -out <dir>`
writes a candidate; `upstream` re-checks every record against its live source
(the only networked command).

## Licenses

Tooling and docs: Apache-2.0. Source records: CC0-1.0. Template texts and
tokenizer tables: their upstream licenses (Apache-2.0 or MIT), listed in
`NOTICE`. See [DATA-LICENSE.md](DATA-LICENSE.md).

## Reporting a wrong entry

Open an issue, or for anything sensitive (a hostile entry, a compromised key)
use Socair's private security reporting
([SECURITY.md](https://github.com/defilantech/socair/blob/main/SECURITY.md)).
[CONTRIBUTING.md](CONTRIBUTING.md) says how reports are handled and how fast.
