#!/usr/bin/env python3
"""
sources.py — where the data comes from, and how each feed is parsed.

Everything is fetched straight from the primary publisher. Nothing here is
second-hand: IP allocations come from the five Regional Internet Registries
themselves, Iranian CDN ranges come from the Iranian CDNs, and each blocklist
comes from the project that maintains it.

On what counts as an Iranian IP
-------------------------------
The default ``ir`` set is **registry-authoritative**: an address is Iranian
only if a RIR has delegated it to an organisation whose registered country is
``IR``. That is the strongest definition available without a paid
geolocation database, and it is the one that answers "is this actually hosted
in Iran" rather than "does some database guess Iran".

Two deliberate consequences:

* Iranian CDN providers publish edge ranges that are **not** in Iran —
  ParsPack's list includes Leaseweb (``95.211.0.0/16``) and Vultr
  (``45.77.0.0/16``) space, for example. Those ranges are therefore kept in a
  separate ``ir-cdn`` set instead of being folded into ``ir``. Users who want
  "everything that serves Iranian traffic" take ``ir-full``; users who want
  "machines in Iran" take ``ir``.
* Published ranges belonging to foreign clouds and CDNs are subtracted from
  ``ir`` outright. In practice the overlap is near zero because those ranges
  are registered to non-Iranian entities, but the subtraction is cheap and it
  makes a whole class of mistake impossible rather than unlikely.

Two independent RIR-derived lists (ipverse, ipdeny) are fetched purely to
cross-check our own parsing. They never contribute addresses — a disagreement
is reported in the audit, not silently merged in.

Only the standard library is used, so a GitHub Actions runner needs nothing
beyond the Python it already ships with.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

USER_AGENT = "IR-Geo-DB/1.0 (+https://github.com/Arman2122/IR-Geo-DB)"
TIMEOUT = 120


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
    Source(key="threat-ip-phishing", name="Phishing.Database (IPs)",
           parser="cidr", kind="ip", tier="blocklist", license="MIT",
           optional=True,
           homepage="https://github.com/mitchellkrogza/Phishing.Database",
           url="https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-IPs-ACTIVE.txt"),
    Source(key="threat-ip-malware", name="Feodo Tracker botnet C2",
           parser="cidr", kind="ip", tier="blocklist", license="CC0",
           optional=True, homepage="https://feodotracker.abuse.ch/blocklist/",
           url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),

    # ---- security
    Source(key="malware-urlhaus", name="URLhaus", parser="hosts", kind="domain",
           tier="blocklist", license="CC0", optional=True,
           homepage="https://urlhaus.abuse.ch",
           url="https://urlhaus.abuse.ch/downloads/hostfile/"),
    Source(key="phishing-db", name="Phishing.Database", parser="domains",
           kind="domain", tier="blocklist", license="MIT", optional=True,
           homepage="https://github.com/mitchellkrogza/Phishing.Database",
           url="https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"),
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


# ------------------------------------------------------------------ fetching


def fetch(url: str, cache_dir: str | None = None, retries: int = 4) -> bytes:
    """GET with retries and an optional on-disk cache.

    The cache exists so a local run does not hammer five RIR mirrors on every
    iteration; CI starts cold and always fetches fresh.
    """
    cache_path = None
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", url)[-150:]
        cache_path = os.path.join(cache_dir, safe)
        if os.path.exists(cache_path) and os.path.getsize(cache_path) > 0:
            with open(cache_path, "rb") as fh:
                return fh.read()

    last = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": USER_AGENT,
                              "Accept-Encoding": "gzip, identity"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw = resp.read()
                if resp.headers.get("Content-Encoding") == "gzip":
                    raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read()
            if cache_path:
                with open(cache_path, "wb") as fh:
                    fh.write(raw)
            return raw
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
            if attempt < retries - 1:
                time.sleep(2 ** attempt * 2)
    raise RuntimeError(f"fetch failed after {retries} attempts: {url} ({last})")


# ------------------------------------------------------------------- parsers

_CIDR_RE = re.compile(
    r"\b(?:(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}|[0-9A-Fa-f:]{2,}:[0-9A-Fa-f:]*/\d{1,3})\b")
_HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)")
_ADBLOCK_RE = re.compile(r"^\|\|([A-Za-z0-9._-]+)\^")


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def parse_cidr(raw: bytes) -> list[str]:
    out = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            out.append(line)
    return out


def parse_html_cidr(raw: bytes) -> list[str]:
    """Pull every CIDR out of an HTML page. Deliberately loose."""
    return _CIDR_RE.findall(_text(raw))


def parse_rir(raw: bytes, country: str = "IR") -> list[str]:
    """Extract delegations for one country from a RIR delegated-stats file.

    Line format is ``registry|cc|type|start|value|date|status[|opaque-id]``.
    For IPv4 ``value`` is a *host count*, not a prefix length, and it is not
    always an aligned power of two — 1536 addresses is a /23 plus a /22. For
    IPv6 ``value`` is the prefix length.

    Only ``allocated`` and ``assigned`` records count. ``reserved`` and
    ``available`` are not delegated to anyone.
    """
    import ipaddress

    out = []
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
                out.append(f"{start}/{int(value)}")
        except (ValueError, ipaddress.AddressValueError):
            continue
    return out


def parse_aws_json(raw: bytes) -> list[str]:
    data = json.loads(_text(raw))
    return ([p["ip_prefix"] for p in data.get("prefixes", [])] +
            [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", [])])


def parse_google_json(raw: bytes) -> list[str]:
    data = json.loads(_text(raw))
    out = []
    for p in data.get("prefixes", []):
        if "ipv4Prefix" in p:
            out.append(p["ipv4Prefix"])
        if "ipv6Prefix" in p:
            out.append(p["ipv6Prefix"])
    return out


def parse_fastly_json(raw: bytes) -> list[str]:
    data = json.loads(_text(raw))
    return data.get("addresses", []) + data.get("ipv6_addresses", [])


def parse_gcore_json(raw: bytes) -> list[str]:
    data = json.loads(_text(raw))
    return data.get("addresses", []) + data.get("addresses_v6", [])


def parse_hosts(raw: bytes) -> list[str]:
    out = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0]
        m = _HOSTS_RE.match(line)
        if m:
            out.append(m.group(1))
    return out


def parse_domains(raw: bytes) -> list[str]:
    out = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", "[")):
            continue
        # a few upstreams ship "0.0.0.0 domain" inside a "domains" file
        parts = line.split()
        out.append(parts[-1] if len(parts) > 1 else line)
    return out


def parse_adblock(raw: bytes) -> list[str]:
    """Take only plain ``||domain^`` rules.

    Anything carrying options (``$third-party``), an exception (``@@``) or a
    path is not a whole-domain block and must not be turned into one.
    """
    out = []
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "@@", "[")):
            continue
        if "$" in line or "/" in line.rstrip("^"):
            continue
        m = _ADBLOCK_RE.match(line)
        if m:
            out.append(m.group(1))
    return out


PARSERS = {
    "cidr": parse_cidr, "rir": parse_rir, "html_cidr": parse_html_cidr,
    "aws_json": parse_aws_json, "google_json": parse_google_json,
    "fastly_json": parse_fastly_json, "gcore_json": parse_gcore_json,
    "hosts": parse_hosts, "domains": parse_domains, "adblock": parse_adblock,
}


# ------------------------------------------------------------------- harvest


@dataclass
class Harvest:
    values: dict[str, list[str]] = field(default_factory=dict)
    failed: dict[str, str] = field(default_factory=dict)
    bytes_read: dict[str, int] = field(default_factory=dict)

    def get(self, key: str) -> list[str]:
        return self.values.get(key, [])

    def any_of(self, prefix: str) -> list[str]:
        out = []
        for key, vals in self.values.items():
            if key.startswith(prefix):
                out.extend(vals)
        return out


def harvest(keys: list[str] | None = None, cache_dir: str | None = None,
            log=print) -> Harvest:
    """Fetch and parse every configured source (or a named subset)."""
    result = Harvest()
    wanted = [s for s in SOURCES if keys is None or s.key in keys]
    for src in wanted:
        try:
            raw = fetch(src.url, cache_dir=cache_dir)
            values = PARSERS[src.parser](raw)
            result.values[src.key] = values
            result.bytes_read[src.key] = len(raw)
            log(f"  ok    {src.key:<22} {len(values):>7} entries  "
                f"({len(raw) / 1024:.0f} KiB)")
        except Exception as exc:                       # noqa: BLE001
            result.failed[src.key] = str(exc)
            level = "warn " if src.optional else "ERROR"
            log(f"  {level} {src.key:<22} {exc}")
            if not src.optional:
                raise
    return result


if __name__ == "__main__":
    cache = sys.argv[1] if len(sys.argv) > 1 else None
    h = harvest(cache_dir=cache)
    print(f"\n{len(h.values)} sources ok, {len(h.failed)} failed")
