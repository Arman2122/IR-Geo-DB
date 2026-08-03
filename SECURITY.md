# Security Policy

## Scope

This project publishes routing and filtering **data**. The realistic risk is
not a crash — it is bad data quietly sending traffic the wrong way, or a
blocklist entry taking down a site that should work.

Things worth reporting:

- A non-Iranian prefix appearing in the `ir` set, or the reverse
- A legitimate domain in `malware`, `phishing`, or `ads` (a false positive)
- Anything suggesting a source feed has been tampered with upstream
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

Every build must pass these before anything is published — a failure aborts
the run and the previous release stays current:

- **Registry-only IP attribution.** An address is Iranian only if a Regional
  Internet Registry delegated it to an organisation registered in Iran.
- **Cross-checks.** The Iranian set is compared against two independent
  parses of the same registry data on every run, and the agreement figure is
  published in the release notes.
- **Known-good and known-bad probes.** The build refuses to publish if
  long-standing Iranian blocks go missing, or if addresses such as `8.8.8.8`,
  Cloudflare or AWS ranges appear inside the Iranian set.
- **Volume floors.** A collapsed set — the signature of a truncated or
  half-served upstream file — aborts the build.
- **Checksums.** `SHA256SUMS` covers every published file.

## Verifying what you downloaded

```bash
curl -sfLO https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

## Supported versions

Only the most recent release. It is rebuilt daily; older releases are pruned
and should not be relied on.
