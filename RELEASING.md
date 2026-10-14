# Releasing

How the maintainer cuts a signed release. CI builds an unsigned candidate and
never holds a key; the maintainer rebuilds it, checks it, and signs it on a
machine that holds the signing key, offline. The tools are `feedbuild` (this
repository) and `socair` (Socair's CLI).

Commands below use GNU `date`; on macOS replace `date -u -d '+90 days'` with
`date -u -v+90d`.

## Once: the signing key

1. On a machine that is offline, or an encrypted volume mounted only to sign:

   ```
   socair key gen --out socair-feed-2026 --issuer "Socair project feed"
   ```

   This writes `socair-feed-2026.key` (an unencrypted Ed25519 key, mode 0600;
   `socair` has no passphrase support, so protect it with the volume) and
   `socair-feed-2026.pub`, and prints the key id.
2. Keep a second encrypted copy of the `.key` in another place. Never put the
   key on a daily machine, in CI, or in any repository (`.gitignore` refuses
   `*.key` here).
3. Publish the public half by three routes, so a site can check one against
   another: commit `keys/socair-feed-2026.pub` here with its key id in the
   README, add the key id to Socair's `docs/feed.md`, and print it in every
   release's notes.

## Every month

Release in the first week of the month, so a site that misses two releases
still has 30 days of warning before its feed expires.

### 1. Freeze

- Everything for the release is merged into `main`, after the seven-day
  comment period (CONTRIBUTING.md).
- The latest `upstream` workflow run is green, or each failure is understood
  (a vendor page a runner cannot reach is not a reason to drop an entry).
- Choose the version, `YYYY.MM.N`: `2026.11.1`, or `2026.11.2` for a second
  release that month.

### 2. Get CI's candidate and rebuild it yourself

```
commit=$(git rev-parse origin/main)
gh run list --repo defilantech/socair-feed --workflow ci --commit "$commit"
gh run download <run id> --repo defilantech/socair-feed \
  --name "socair-feed-candidate-$commit" --dir ci-candidate

git checkout "$commit"
go run ./tools/feedbuild build -out rebuild
diff -r ci-candidate rebuild && echo "CI and local builds are byte-identical"
```

Any difference stops the release. Sign `rebuild`, the build you made.

### 3. Read what changes

```
go run ./tools/feedbuild diff -max-change 10 <previous release>/feed rebuild/feed
cat rebuild/BUILD-REPORT.txt
```

Read every added and removed line against its record in `sources/`. A change
to more than 10% of a file's entries stops the release until you have
confirmed it is meant. Check that every template line names a reviewer, and
that no line says TEST BUILD (a test build must never be signed).

### 4. Sign, offline

Check the signing machine's clock first (`date -u`): `feed sign` stamps the
current time as `issued`, and a site with a store refuses a feed issued before
the newest it has used, so a release signed with a slow clock can be refused
everywhere.

```
version=2026.11.1
socair feed sign rebuild/feed --key socair-feed-2026.key \
  --issuer "Socair project feed" --version "$version" \
  --expires "$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)" \
  --description "Known-bad hashes from published reports of malicious model files (11 entries, sources dated 2024-02-27 to 2026-05-07); reviewed chat templates; canonical tokenizers. Exact-hash matching: any change to a file's bytes defeats it. Not a measure of coverage."
socair feed verify rebuild/feed --keys socair-feed-2026.pub
```

Update the counts and dates in the description from `BUILD-REPORT.txt`
(D7 in DECISIONS.md). The issuer is always `Socair project feed`.

### 5. Package

```
go run ./tools/feedbuild pack -prefix "socair-feed-$version" rebuild "socair-feed-$version.tar.gz"
sha256sum "socair-feed-$version.tar.gz" > "socair-feed-$version.tar.gz.sha256"
cp rebuild/feed/feed.dsse.json .
```

`pack` is deterministic: the same signed directory gives the same tarball
(sorted names, owner 0, a fixed timestamp, no gzip name or time).

### 6. Publish

```
git tag -a "v$version" -m "Socair project feed $version" "$commit"
git push origin "v$version"
gh release create "v$version" --repo defilantech/socair-feed --title "Socair project feed $version" \
  --notes-file notes.md "socair-feed-$version.tar.gz" "socair-feed-$version.tar.gz.sha256" feed.dsse.json
```

The notes say: the key id, the issue and expiry times, the counts, every
entry added and removed (from step 3) with its id, and how to verify
(README, "Using it with Socair"). Upload `feed.dsse.json` as its own asset:
the weekly expiry watch reads it.

### 7. After

- The weekly `upstream` workflow's expiry job fails from 30 days before the
  latest release expires. If it fails, release.
- With no data change, still release monthly: a new version, a new expiry.

## Withdrawing a release

Socair's rollback protection (Socair #232) shapes this. A site that scans with
a store records the newest feed it has used and **refuses any feed issued
before it**. So a bad release is never fixed by telling sites to go back to
the previous one.

1. Mark the bad entry `"status": "withdrawn"` with the date, reason, and a
   link, and merge it (no comment period for a removal).
2. Cut a new release at once, following the steps above. It is issued after
   the bad one, so every store takes it.
3. Edit the bad release's notes to say it is withdrawn, why, and which release
   replaces it. Immutable releases keep its assets; that is intended, since
   sites must be able to see what they ran.
4. Tell sites to import the new release and run `socair airlock recheck`,
   which clears any flag that rested on the withdrawn entry.

Only when a new release cannot be signed soon (the key is unavailable) may a
site go back to the previous release, deliberately and on the record:

```
socair airlock feed accept <previous release>/feed --keys <feed keys> --reason "<why>"
```

That works only while the previous release is unexpired, and the store's log
keeps the reason. Scans run without a store have no rollback protection and
take any unexpired release; their operators only need to point `SOCAIR_FEED`
at the new one.

## A lost or stolen key

- **Lost**: nothing more can be signed, and every site's feed expires within
  90 days of the last release, after which its scans stop until it unsets
  `SOCAIR_FEED` or imports a feed under a new key. Make a new key at once,
  publish its id by the three routes, and sign a new release with it. Sites add
  the new `.pub` to `SOCAIR_FEED_KEYS`; a store takes the release because it is
  issued after the last one.
- **Stolen**: whoever holds the key can sign a feed that sites trusting it
  accept, with a denylist and reviews of their choosing. Announce the
  compromise by every route at once, publish a new key, and sign a new release
  with it. Sites remove the old `.pub` from `SOCAIR_FEED_KEYS`. A store that
  already took a forged feed has recorded it as newest; the new release is
  issued later and replaces it. A forged feed dated in the future is refused
  at load (Socair allows five minutes of skew), so it cannot block the new
  release unless the site's clock is wrong too, which
  `socair airlock feed accept` repairs.
- Expiry bounds the damage of a stolen key to the longest unexpired forged
  feed: at most 90 days if the thief follows the cadence, longer if not.
  Socair's format has no revocation list; removing the key is the revocation.

## Continuity

There is one signer (D2 in DECISIONS.md). If the maintainer cannot release for
more than 60 days, the README must say so, so sites know their feed will
expire and scans with it will stop; unsetting `SOCAIR_FEED` returns the
Known-bad row to NOT_TESTED. A deputy with their own key, published in advance
in `keys/`, would remove this gap.
