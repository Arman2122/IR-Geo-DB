# Contributing

Thanks for helping out. There are two useful ways to contribute, and picking
the right one matters — one of them fixes the problem for everyone using this
kind of data, and the other only fixes it here.

## 1. Fix it upstream (preferred)

Every domain in this repository comes from a source listed in the README. If a
domain is wrong, the fix belongs upstream, where it also reaches everyone else
consuming that list. (The IP sets are different: this project derives those
itself. See section 2.)

| What you found | Where it belongs |
|---|---|
| An Iranian site missing from the `ir` domain set | [bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains/issues) |
| A Persian ad or tracker not blocked | [PersianBlocker/PersianBlocker](https://github.com/PersianBlocker/PersianBlocker/issues), the maintained fork |
| A false positive in the ads list | [PersianBlocker](https://github.com/PersianBlocker/PersianBlocker/issues) or [HaGeZi](https://github.com/hagezi/dns-blocklists/issues) |
| A wrong malware / phishing entry | [HaGeZi](https://github.com/hagezi/dns-blocklists/issues) (malware), [CERT Polska](https://cert.pl/en/warning-list/) (phishing) |
| A wrong cryptominers / nsfw entry | [NoCoin](https://github.com/hoshsadiq/adblock-nocoin-list/issues) (cryptominers), [StevenBlack](https://github.com/StevenBlack/hosts/issues) (nsfw) |
| An IP prefix wrongly attributed to Iran | See below — this one is usually ours |

Once upstream merges it, the next daily build picks it up automatically. No
action needed here.

## 2. IP attribution problems

IP data is derived here. `ir` starts from the Regional Internet Registries'
delegation records and is then adjusted by RIPE RIS routing data, so an address
can be in `ir`, or out of it, because of how it is announced and not only
because of who it was delegated to. A genuine problem is a registry error, an
odd route, or a bug in our parsing or routing logic.

Open an issue with:

- the exact prefix or address
- what you believe it should be
- the origin AS that announces it (bgp.he.net or RIPEstat will show it)
- evidence — `whois`, the RIR record, or a traceroute

Check first whether the address is in `ir` or in `ir-cdn`. Those are different
sets on purpose: `ir-cdn` carries each Iranian provider's published ranges plus
every prefix its networks announce, and some of those are foreign edge nodes.
That is expected, not a bug.

## 3. Code

```bash
git clone https://github.com/Arman2122/IR-Geo-DB && cd IR-Geo-DB
( for t in build/test_*.py; do python3 "$t" || exit 1; done )   # offline, fast
python3 build/geodat.py         # protobuf round-trip self-test
python3 build/build.py --outdir dist --cache .cache
python3 build/verify.py dist
```

Python 3.10+, standard library only. **Please keep it that way** — this has to
run on a bare GitHub Actions runner with no install step, and a dependency
that breaks takes the daily build down with it.

`sing-box` and `mihomo` on `PATH` (or `$SING_BOX` / `$MIHOMO`) enable the
`.srs` and `.mrs` outputs. Without them everything else still builds.

`--lkg-dir` (default `.lkg`, git-ignored) keeps the last validated copy of every
input between runs, as the `state` branch does in CI. Delete it to test a first
run. `--cache` only saves downloads, for local iteration.

### Adding a source

First check the licence. A source whose terms forbid redistribution or
derivative works is not accepted, however good the data is — URLhaus,
ThreatFox, OpenPhish and Spamhaus DROP were turned down for this. Prefer the
body that creates the data over an aggregator that republishes it.

1. Add a `Source(...)` entry in `build/sources.py`, with a comment saying
   whether it is an authority, derived, a maintainer or an aggregator. Besides
   `license` and `homepage`:
   - `optional=True` unless the build is worthless without it. A required
     source that goes offline for longer than its stored copy lasts stops the
     daily release for everyone.
   - `mirrors`: the official mirrors of the same file, tried in order after
     `url` (HaGeZi's GitLab and Codeberg, jsDelivr for a GitHub-hosted file).
   - `min_entries` and `min_bytes`: the floors. Set each to about 70 % of what
     the source returns the day you add it, rounded down, with the measured
     figure in a comment, e.g. `# 1,747 entries, 28 KB on 2026-10-23`. A source
     under 20 entries gets about half instead, so one removed line does not
     trip it. A source that can legitimately be empty or near zero (Feodo
     Tracker) keeps `min_entries=0`, sets `max_shrink=1.0` and relies on
     `min_bytes`.
   - `max_stale_days`: how long the stored copy may stand in when every URL
     fails (default 14). Pick it by how fast the data goes bad: 90 for provider
     lists and RIPE lookups, 30 for Iranian domains, ads, nsfw and cloud
     ranges, 14 for RIR and RIS data and cross-checks, 7 for threat feeds.
   - `attribution`: any text the licence requires the README and `stats.json`
     to carry.
2. Reuse an existing `parser`, or add one to `PARSERS`. A parser returns
   `Parsed(values, invalid)` and must be strict about what it accepts; cover it
   in `build/test_units.py`.
3. Wire it into a dataset in `build/build.py`.
4. Add the attribution row to the README table, in the group for its origin.
   This is not optional; several sources require it by licence.

### Adding an Iranian provider

Providers are added by RIPE organisation handle, in `PROVIDERS` in
`build/sources.py`:

```python
"Example Cloud": {"orgs": ["ORG-XXXX1-RIPE"], "lists": ["example"]},
```

- Find the handle by looking up one of the provider's ASNs in the RIPE database
  (`whois -h whois.ripe.net AS12345`) and reading its `org:` attribute. A
  provider can have several organisations; list them all.
- Every build looks up the ASNs registered to each organisation and takes every
  prefix they announce in RIS, so a network the provider registers later is
  picked up without a code change.
- Each new organisation also needs an entry in `_RIPE_ORG_FLOOR` in
  `build/sources.py`: the fewest ASNs the lookup may return, about half of those
  found and at least 1, with the count in a comment. Without it `sources.py`
  fails to import.
- `lists` names the provider's own published ranges, each an ordinary `Source`
  with `tier="provider"` as above. A provider that owns no ASN has `"orgs": []`,
  and one that publishes no list has `"lists": []`.
- Add the provider to the README table.

### Adding an output format

Add one function to `build/emitters.py` and register it in the relevant list.
Emitters must not mutate the dataset.

If the format cannot express a match type — keywords and regexes have no
meaning in a hosts file — **drop what you cannot represent and record the
count** via the `note=` argument. Never emit a rule that means something
different from what the source said.

### Before opening a PR

- `( for t in build/test_*.py; do python3 "$t" || exit 1; done )` passes
- `python3 build/geodat.py` passes
- A full build followed by `python3 build/verify.py dist` passes

CI runs the first two on every pull request, and on pushes to `main` that touch
`build/`. The third needs network access, so it runs in the build workflow:
daily, on those same pushes, and on a manual dry run.

## Style

Match what is already there. Comments explain *why* a thing is the way it is,
not what the line does — the non-obvious constraint, the format quirk, the
reason an approach that looks simpler is wrong.
