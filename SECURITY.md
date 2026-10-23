# Security Policy

## Scope

This project publishes routing and filtering **data**. The realistic risk is
not a crash — it is bad data quietly sending traffic the wrong way, or a
blocklist entry taking down a site that should work.

Things worth reporting:

- A non-Iranian prefix appearing in the `ir` set, or the reverse
- A legitimate domain in `malware`, `phishing`, or `ads` (a false positive)
- Anything suggesting a source feed, or its stored copy on the `state` branch,
  has been tampered with
- A flaw in the build that could let a source inject arbitrary output
- Credential or token exposure in the workflow

## Reporting

For anything with security impact, use
[**private vulnerability reporting**](https://github.com/Arman2122/IR-Geo-DB/security/advisories/new)
rather than a public issue.

For a plain false positive with no security angle, a normal
[issue](https://github.com/Arman2122/IR-Geo-DB/issues/new/choose) is fine and
faster.

Please include the affected set, the exact entry, and how you determined it is
wrong. Expect a first response within a few days.

## What protects the data

Three layers: a bad download is rejected before it is believed, a bad result
stops the build, and the evidence is published for you to check. When a build
stops, nothing is published and the previous release stays current.

**A bad download is rejected**

- **Per-source floors.** Every source has a minimum size and, where its volume
  is stable, a minimum entry count. A smaller download is rejected, which
  catches a truncated or half-served file. One that shrank past its limit
  against the last good copy (half, by default) is rejected too.
- **HTML rejection.** An error page served where a list should be is rejected,
  never parsed.
- **Stored copies.** A rejected download is treated as that URL being down: the
  next mirror is tried, and then the source's stored copy. Every validated input
  is committed to this repository's `state` branch, and the stored copy stands
  in for a window set per source — 7 to 90 days, by how fast that data goes
  stale. After that an optional source is dropped, and a required one (the RIPE
  NCC delegation file, the Iranian domain list) stops the build. A source that
  is not served fresh appears in the release notes' "Source health" table and
  in `stats.json`.

**A bad result stops the build**

- **Registry plus routing, with anomaly limits.** An address is Iranian only if
  a Regional Internet Registry delegated it to an organisation registered in
  Iran, adjusted by RIPE NCC RIS routing data, where the most specific route
  wins. If routing would add more than 20 % or remove more than 10 % of the
  registry's addresses, IPv4 or IPv6, the build fails: that is a leak or a
  broken dump, not a change in Iran. An Iranian prefix under a route that only
  foreign networks announce is not added, since that is the shape of a hijack.
  Without routing data, `ir` is registry-only.
- **Known-good and known-bad probes.** The build requires `2.144.0.0/14` (TCI)
  in the Iranian set and `8.8.8.8` out of it, and refuses a set that is
  implausibly small (`ir` under 1,000 IPv4 prefixes, 100 IPv6 prefixes or 1,000
  domains, or `ads` under 1,000). `verify.py` then checks that seven
  long-standing Iranian addresses are in, and that seven others — Google DNS,
  Cloudflare DNS, Cloudflare, Microsoft, Google and AWS addresses, and an
  RFC 1918 address — are not.
- **Day-over-day guard.** The build refuses to publish if `ir` IPv4 addresses
  fall more than 5 % against the previous release, `ir` domains more than
  10 %, or a blocklist more than 60 %. A set whose source list changed, or a
  previous release that can't be fetched after retries, skips the comparison,
  and the log says why. A maintainer can override it with `allow_shrink` after
  reading why.
- **Shared-platform guard.** `verify.py` refuses to publish if a blocklist
  covers a shared platform such as `sites.google.com`, `bit.ly` or `github.io`,
  since a suffix rule there would block every site hosted under it.
- **Clean threat IPs.** The build removes private and reserved ranges, every
  foreign-cloud range and `ir-cdn` from the threat IP sets, and `verify.py`
  refuses to publish if any prefix still overlaps a private range.
- **Output checks.** `verify.py` re-reads what was written and decodes the
  binary formats, checking for duplicate or redundant entries and that the
  counts match the text lists.

**Published so you can check**

- **Cross-checks.** The Iranian set is compared against two independent parses
  of the same registry data on every run, and the agreement figure is published
  in the release notes. A disagreement is reported, never silently merged in.
- **Provenance.** `stats.json` records each source's status, the URL it was
  read from, the sha256 of the file, its dates and its licence.
- **Checksums.** `SHA256SUMS` covers every published file.

## Verifying what you downloaded

```bash
curl -sfLO https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

`stats.json` in the same release records where each input came from and its
sha256, so a build can be traced back to exactly what it was made from.

## Supported versions

Only the most recent release. It is rebuilt daily; older releases are pruned
and should not be relied on.
