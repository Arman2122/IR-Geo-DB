#!/usr/bin/env python3
"""Where the data comes from, and how each feed is parsed.

Everything is fetched from the primary publisher. IP allocations come from the
five Regional Internet Registries, Iranian CDN ranges from the Iranian CDNs,
each blocklist from the project that maintains it.

An address is Iranian only if a RIR delegated it to an organisation whose
registered country is IR. ipverse and ipdeny are fetched purely to cross-check
that parsing and never contribute addresses.

How a source is fetched and when its body is trusted lives in fetch.py.

Standard library only — a GitHub Actions runner needs no install step.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from typing import NamedTuple

import geodat
from model import clean_domain


@dataclass
class Source:
    key: str
    name: str
    url: str
    parser: str
    kind: str                 # "ip" | "domain"
    tier: str                 # registry | provider | official | crosscheck | cloud | blocklist
    license: str = ""
    homepage: str = ""
    optional: bool = False    # a failure here warns instead of aborting
    note: str = ""
    # how fetch.py acquires and trusts it; the defaults reject nothing
    mirrors: tuple[str, ...] = ()     # tried in order after url
    min_entries: int = 0              # fewer parsed entries: reject the body
    min_bytes: int = 0                # a smaller raw body: reject it
    max_shrink: float = 0.5           # reject a body with fewer than
                                      # (1 - max_shrink) x the stored copy's
                                      # entries, once that copy has >= 100
    max_age_days: int | None = None   # reject a Last-Modified older than this
    max_stale_days: int = 14          # how long the stored copy may stand in
    attribution: str = ""             # text the README and stats.json must carry

    @property
    def credit(self) -> str:
        return f"{self.name} ({self.license})" if self.license else self.name


# --------------------------------------------------------------- the registry

RIR_STATS = [
    ("ripencc", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"),
    ("apnic", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"),
    ("arin", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"),
    ("lacnic", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"),
    ("afrinic", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"),
]

SOURCES: list[Source] = [
    # ---- tier 1: registry truth. Iran's space is overwhelmingly RIPE NCC,
    # but an Iranian org can hold space from any RIR, so all five are read.
    *[
        Source(key=f"rir-{rir}", name=f"{rir.upper()} delegated statistics",
               url=url, parser="rir", kind="ip", tier="registry",
               license="Registry public data",
               homepage="https://www.nro.net/about/rirs/statistics/",
               optional=(rir != "ripencc"),
               note="authoritative country delegation")
        for rir, url in RIR_STATS
    ],

    # ---- tier 2: first-party Iranian infrastructure. Published by the
    # operators themselves; the only authority on their own ranges.
    Source(key="arvancloud", name="ArvanCloud", parser="cidr", kind="ip",
           tier="provider", url="https://www.arvancloud.ir/en/ips.txt",
           homepage="https://www.arvancloud.ir/en/dev/ips",
           license="All rights reserved", optional=True),
    Source(key="parspack", name="ParsPack CDN", parser="cidr", kind="ip",
           tier="provider", url="https://parspack.com/cdnips.txt",
           homepage="https://parspack.com", license="All rights reserved",
           optional=True, note="includes foreign edge nodes"),

    # The ITO government messenger-IP page renders its table client-side, so
    # there is nothing to scrape from the HTML. It is no loss: Iranian
    # messengers run on Iranian address space, which the registry feed
    # already covers.

    # ---- cross-checks: independent implementations of the same RIR parse.
    # Used to validate our parser, never to add addresses.
    Source(key="xc-ipverse-v4", name="ipverse rir-ip", parser="cidr", kind="ip",
           tier="crosscheck", optional=True, license="Public domain",
           homepage="https://github.com/ipverse/rir-ip",
           url="https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt"),
    Source(key="xc-ipverse-v6", name="ipverse rir-ip", parser="cidr", kind="ip",
           tier="crosscheck", optional=True, license="Public domain",
           homepage="https://github.com/ipverse/rir-ip",
           url="https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv6-aggregated.txt"),
    Source(key="xc-ipdeny-v4", name="ipdeny country zones", parser="cidr",
           kind="ip", tier="crosscheck", optional=True, license="Free to use",
           homepage="https://www.ipdeny.com",
           url="https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone"),

    # ---- foreign clouds and CDNs, subtracted from the Iranian set
    Source(key="cloud-cloudflare-v4", name="Cloudflare", parser="cidr", kind="ip",
           tier="cloud", url="https://www.cloudflare.com/ips-v4", optional=True,
           homepage="https://www.cloudflare.com/ips"),
    Source(key="cloud-cloudflare-v6", name="Cloudflare", parser="cidr", kind="ip",
           tier="cloud", url="https://www.cloudflare.com/ips-v6", optional=True,
           homepage="https://www.cloudflare.com/ips"),
    Source(key="cloud-aws", name="Amazon AWS", parser="aws_json", kind="ip",
           tier="cloud", url="https://ip-ranges.amazonaws.com/ip-ranges.json",
           optional=True, homepage="https://ip-ranges.amazonaws.com"),
    Source(key="cloud-google", name="Google", parser="google_json", kind="ip",
           tier="cloud", url="https://www.gstatic.com/ipranges/goog.json",
           optional=True, homepage="https://www.gstatic.com/ipranges/goog.json"),
    Source(key="cloud-gcloud", name="Google Cloud", parser="google_json", kind="ip",
           tier="cloud", url="https://www.gstatic.com/ipranges/cloud.json",
           optional=True, homepage="https://www.gstatic.com/ipranges/cloud.json"),
    Source(key="cloud-fastly", name="Fastly", parser="fastly_json", kind="ip",
           tier="cloud", url="https://api.fastly.com/public-ip-list",
           optional=True, homepage="https://api.fastly.com/public-ip-list"),
    Source(key="cloud-gcore", name="G-Core", parser="gcore_json", kind="ip",
           tier="cloud", url="https://api.gcore.com/cdn/public-ip-list",
           optional=True, homepage="https://gcore.com"),

    # ---- Iranian domains
    Source(key="ir-domains", name="Iran Hosted Domains", parser="domains",
           kind="domain", tier="blocklist", license="MIT",
           homepage="https://github.com/bootmortis/iran-hosted-domains",
           url="https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt"),

    # ---- advertising and tracking
    # Despite the [AdBlock] header this file is a plain domain list with #
    # comments, not hosts syntax.
    Source(key="ads-persian", name="PersianBlocker", parser="domains",
           kind="domain", tier="blocklist", license="AGPL-3.0",
           homepage="https://github.com/MasterKia/PersianBlocker",
           url="https://raw.githubusercontent.com/MasterKia/PersianBlocker/main/PersianBlockerHosts.txt"),
    # "light" rather than "pro": pro is ~217k domains and pushes geosite.dat
    # past what is comfortable to ship to a phone, for a false-positive rate
    # that is worse, not better.
    Source(key="ads-hagezi", name="HaGeZi Multi LIGHT", parser="domains",
           kind="domain", tier="blocklist", license="GPL-3.0", optional=True,
           homepage="https://github.com/hagezi/dns-blocklists",
           url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/light-onlydomains.txt"),
    Source(key="ads-adguard", name="AdGuard DNS filter", parser="adblock",
           kind="domain", tier="blocklist", license="GPL-3.0", optional=True,
           homepage="https://github.com/AdguardTeam/AdGuardSDNSFilter",
           url="https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/gh-pages/Filters/filter.txt"),

    # ---- threat IPs, for firewall drop rules rather than DNS
    # The phishing IP feed was Phishing.Database, which stopped updating on
    # 2026-10-02 and carried Google, Cloudflare and CloudFront addresses. The
    # `phishing` IP set stays, empty, so geoip:phishing still resolves.
    Source(key="threat-ip-malware", name="Feodo Tracker botnet C2",
           parser="cidr", kind="ip", tier="blocklist", license="CC0",
           optional=True, homepage="https://feodotracker.abuse.ch/blocklist/",
           url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),

    # ---- security
    # URLhaus data is off limits: abuse.ch's terms (effective 2025-11-04)
    # restrict it to authenticated not-for-profit use and forbid derivative
    # works, and that carries into every mirror of it. HaGeZi's TIF mini is a
    # size-optimised aggregate of threat feeds under the project's own
    # licence, built to stay off popular domains.
    Source(key="malware-hagezi-tif", name="HaGeZi Threat Intelligence Feeds mini",
           parser="domains", kind="domain", tier="blocklist",
           license="GPL-3.0", optional=True,
           homepage="https://github.com/hagezi/dns-blocklists",
           url="https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.mini-onlydomains.txt"),
    # Replaces Phishing.Database, which stopped updating on 2026-10-02 and
    # listed whole platforms (sites.google.com, bit.ly, nflxvideo.net). CERT
    # Polska's terms allow use "for any purpose, including commercial".
    Source(key="phishing-certpl", name="CERT Polska warning list",
           parser="domains", kind="domain", tier="blocklist",
           license="free for any use", optional=True,
           homepage="https://cert.pl/en/warning-list/",
           url="https://hole.cert.pl/domains/v2/domains.txt"),
    Source(key="crypto-nocoin", name="NoCoin adblock list", parser="hosts",
           kind="domain", tier="blocklist", license="MIT", optional=True,
           homepage="https://github.com/hoshsadiq/adblock-nocoin-list",
           url="https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt"),
    Source(key="nsfw-stevenblack", name="StevenBlack unified hosts (porn)",
           parser="hosts", kind="domain", tier="blocklist", license="MIT",
           optional=True, homepage="https://github.com/StevenBlack/hosts",
           url="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts"),
]

BY_KEY = {s.key: s for s in SOURCES}


# ------------------------------------------------------------------- parsers


class Parsed(NamedTuple):
    """What every parser returns.

    `invalid` counts lines that have the shape of an entry but fail
    validation. Lines skipped on purpose (comments, other countries, rules
    with options this parser does not support) are not invalid, so a feed that
    turns to garbage stands out in the count instead of hiding in it.
    """
    values: list[str]
    invalid: int


_HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)")
_ADBLOCK_RE = re.compile(r"^\|\|([A-Za-z0-9._-]+)\^")
_ADGUARD_ALLOW_RE = re.compile(r"^(?:@@)?\|\|([A-Za-z0-9._-]+)\^\|?$")
_AS_RE = re.compile(r"AS([0-9]+)")

_MAX_ASN = 2 ** 32 - 1

# A route seen by only a few collectors is more likely a leak or a bad
# announcement than a real route, and so is a prefix shorter than these.
_RIS_MIN_PEERS = 10
_RIS_MIN_LENGTH = {4: 8, 6: 16}


def _text(raw: bytes) -> str:
    # utf-8-sig: a BOM would otherwise stay glued to the first entry
    return raw.decode("utf-8-sig", errors="replace")


def _networks(items) -> Parsed:
    """Validate CIDR strings. Bare addresses become /32 or /128."""
    out, bad = [], 0
    for item in items:
        # ip_network() would read a JSON number as an integer address
        if not isinstance(item, str):
            bad += 1
            continue
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            bad += 1
    return Parsed(out, bad)


def _domains(names) -> Parsed:
    """Run clean_domain over candidate names and count the rejects."""
    out, bad = [], 0
    for name in names:
        cleaned = clean_domain(name)
        if cleaned is None:
            bad += 1
        else:
            out.append(cleaned)
    return Parsed(out, bad)


def parse_cidr(raw: bytes) -> Parsed:
    lines = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            lines.append(line)
    return _networks(lines)


def parse_rir(raw: bytes, country: str = "IR") -> Parsed:
    """Extract one country's delegations from a RIR delegated-stats file.

    Lines are registry|cc|type|start|value|date|status[|opaque-id]. For IPv4
    `value` is a host count, not a prefix length; for IPv6 it is the prefix
    length; for an asn record it is how many consecutive ASNs start at `start`.
    Only allocated and assigned records are delegated to anyone. Prefixes come
    out as CIDRs and ASNs as "AS<n>".
    """
    out, bad = [], 0
    for line in _text(raw).splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7 or parts[1] != country:
            continue
        _, _, kind, start, value, _date, status = parts[:7]
        if status not in ("allocated", "assigned"):
            continue
        try:
            if kind == "ipv4":
                first = ipaddress.IPv4Address(start)
                last = ipaddress.IPv4Address(int(first) + int(value) - 1)
                out.extend(str(n) for n in
                           ipaddress.summarize_address_range(first, last))
            elif kind == "ipv6":
                out.append(str(ipaddress.ip_network(f"{start}/{int(value)}",
                                                    strict=False)))
            elif kind == "asn":
                first, count = int(start), int(value)
                # bounded so one corrupt count cannot expand into billions
                if first < 0 or count < 1 or first + count - 1 > _MAX_ASN:
                    raise ValueError(line)
                out.extend(f"AS{n}" for n in range(first, first + count))
        except ValueError:
            bad += 1
    return Parsed(out, bad)


def parse_aws_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    return _networks([p["ip_prefix"] for p in data.get("prefixes", [])] +
                     [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", [])])


def parse_google_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    out = []
    for p in data.get("prefixes", []):
        if "ipv4Prefix" in p:
            out.append(p["ipv4Prefix"])
        if "ipv6Prefix" in p:
            out.append(p["ipv6Prefix"])
    return _networks(out)


def parse_fastly_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    return _networks(data.get("addresses", []) + data.get("ipv6_addresses", []))


def parse_gcore_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    return _networks(data.get("addresses", []) + data.get("addresses_v6", []))


def parse_ris(raw: bytes) -> Parsed:
    """Read a RIPE RIS whois dump: origin, prefix and peer count per row.

    The dump is published gzipped, so a gzip stream is unpacked first (a
    truncated one raises rather than parsing as a shorter table). Values are
    "<origin> <prefix>". Rows seen by fewer than 10 peers or shorter than
    /8 (IPv4) or /16 (IPv6) are dropped, and so are AS-set origins like
    "{1,2}", which name no single owner. Those are filters, not errors.
    """
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    out, bad = [], 0
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("%"):
            continue
        parts = line.split()
        if len(parts) < 3:
            bad += 1
            continue
        origin, prefix, peers = parts[:3]
        if origin.startswith("{"):
            continue
        try:
            asn, seen = int(origin), int(peers)
            net = ipaddress.ip_network(prefix)
            if not 0 <= asn <= _MAX_ASN or seen < 0:
                raise ValueError(line)
        except ValueError:
            bad += 1
            continue
        if seen >= _RIS_MIN_PEERS and net.prefixlen >= _RIS_MIN_LENGTH[net.version]:
            out.append(f"{asn} {net}")
    return Parsed(out, bad)


def parse_ripe_org_asns(raw: bytes) -> Parsed:
    """Take the aut-num of every object in a RIPE database search result."""
    data = json.loads(_text(raw))
    out, bad = [], 0
    for obj in data.get("objects", {}).get("object", []):
        for attr in obj.get("attributes", {}).get("attribute", []):
            if attr.get("name") != "aut-num":
                continue
            m = _AS_RE.fullmatch(str(attr.get("value", "")).strip().upper())
            if m and int(m.group(1)) <= _MAX_ASN:
                out.append(f"AS{int(m.group(1))}")
            else:
                bad += 1
    return Parsed(out, bad)


def parse_v2fly_dlc(raw: bytes) -> Parsed:
    """Pull CATEGORY-IR out of a v2fly dlc.dat.

    `domain` entries come out as the bare name and `full` entries as
    "full:<name>", so a later stage can tell a suffix from an exact match.
    Keywords and regexps cannot be expressed as a name and are skipped.
    """
    out, bad = [], 0
    for cat in geodat.decode_geosite(raw):
        if cat.code.upper() != "CATEGORY-IR":
            continue
        for kind, value in cat.domains:
            if kind not in (geodat.ROOT_DOMAIN, geodat.FULL):
                continue
            name = clean_domain(value)
            if name is None:
                bad += 1
            else:
                out.append(f"full:{name}" if kind == geodat.FULL else name)
    return Parsed(out, bad)


def parse_psl(raw: bytes) -> Parsed:
    """Read the Public Suffix List.

    ICANN rules come out as written and private-section rules as
    "private:<rule>", lower-cased, with any "*." or "!" kept as is. They are
    rules rather than hostnames, so they do not go through clean_domain, which
    would strip the wildcard and reject the exception marker.
    """
    out, bad = [], 0
    private = False
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("//"):
            # the section markers are comments, so they are read before the
            # comments are skipped
            if "===BEGIN PRIVATE DOMAINS===" in line:
                private = True
            elif "===END PRIVATE DOMAINS===" in line:
                private = False
            continue
        # a line is read only up to its first whitespace
        rule = line.split()[0].lower()
        body = rule[1:] if rule.startswith("!") else rule
        if body.startswith("*."):
            body = body[2:]
        labels = body.split(".")
        if not all(labels) or any(c in label for label in labels for c in "*!/"):
            bad += 1
            continue
        out.append(f"private:{rule}" if private else rule)
    return Parsed(out, bad)


def parse_hosts(raw: bytes) -> Parsed:
    names = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0]
        m = _HOSTS_RE.match(line)
        if m:
            names.append(m.group(1))
    return _domains(names)


def parse_domains(raw: bytes) -> Parsed:
    names = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", "[")):
            continue
        # a few upstreams ship "0.0.0.0 domain" inside a "domains" file
        parts = line.split()
        names.append(parts[-1] if len(parts) > 1 else line)
    return _domains(names)


def parse_adblock(raw: bytes) -> Parsed:
    """Take only plain ||domain^ rules.

    Anything with options ($third-party), an exception (@@) or a path is not a
    whole-domain block and must not be turned into one.
    """
    names = []
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "@@", "[")):
            continue
        if "$" in line or "/" in line.rstrip("^"):
            continue
        m = _ADBLOCK_RE.match(line)
        if m:
            names.append(m.group(1))
    return _domains(names)


def parse_adguard_allow(raw: bytes) -> Parsed:
    """Take the names from plain ||name^ and @@||name^ rules.

    AdGuard's allowlist files use both ||name^ and @@||name^| for "do not
    block this name", so both are read. A rule with options ($important) or a
    regexp is not a whole-name rule and is skipped.
    """
    names = []
    for line in _text(raw).splitlines():
        m = _ADGUARD_ALLOW_RE.match(line.strip())
        if m:
            names.append(m.group(1))
    return _domains(names)


PARSERS = {
    "cidr": parse_cidr, "rir": parse_rir,
    "aws_json": parse_aws_json, "google_json": parse_google_json,
    "fastly_json": parse_fastly_json, "gcore_json": parse_gcore_json,
    "ris": parse_ris, "ripe_org_asns": parse_ripe_org_asns,
    "v2fly_dlc": parse_v2fly_dlc, "psl": parse_psl,
    "hosts": parse_hosts, "domains": parse_domains,
    "adblock": parse_adblock, "adguard_allow": parse_adguard_allow,
}


if __name__ == "__main__":
    # every source against a throwaway state store: python3 build/sources.py [cache]
    import tempfile

    import fetch

    with tempfile.TemporaryDirectory() as tmp:
        try:
            h = fetch.harvest(SOURCES, fetch.StateStore(tmp),
                              cache_dir=sys.argv[1] if len(sys.argv) > 1 else None)
        except fetch.SourceUnavailable as exc:
            sys.exit(f"ERROR: {exc}")
    print(f"\n{len(h.values)} sources ok, {len(h.failed)} failed")
