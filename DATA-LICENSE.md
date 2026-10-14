# Licensing

This repository holds three kinds of material under three sets of terms.

| Material | Where | Terms |
|---|---|---|
| Build tooling, scripts, workflows, and documentation | everything not listed below | Apache License 2.0 ([`LICENSE`](LICENSE)) |
| Reference facts: SHA-256 values, file names, sizes, dates, citations, and the other fields of each source record | `sources/` | CC0 1.0 Universal ([`LICENSES/CC0-1.0.txt`](LICENSES/CC0-1.0.txt)) |
| Upstream material: chat-template texts, and tokenizer tables derived from upstream tokenizer files | `texts/` | each file's upstream license, named in the source record that cites it and listed in `NOTICE`; copies of those licenses are in `LICENSES/` |

A released feed follows the same split. `denylist.txt`, `templates.txt`, and
`tokenizers.txt` are built from `sources/` and are CC0. `templates/*.jinja`
and `tokenizers/*.json` are built from `texts/` and stay under their upstream
licenses; every release carries `NOTICE` and the license texts beside the feed
directory.

Two limits on the CC0 dedication:

- A source record may quote a few lines of a published report (for example the
  row of an indicators table that prints a hash) so a reader can find the hash
  in the source. The quoted words remain the publisher's. They are reproduced
  as short quotations for identification and are not dedicated to the public
  domain.
- CC0 covers what the contributors of this repository can dedicate. It grants
  no rights in any model, report, or upstream file that a record cites.

By submitting a source record you dedicate your contribution to it under CC0
1.0; by submitting tooling or documentation you license it under Apache 2.0.
Either way, sign off your commits under the Developer Certificate of Origin.

This split is a project decision (D1 in the project's decision record), made
without legal advice and to be confirmed by counsel.
