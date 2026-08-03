#!/usr/bin/env python3
"""
model.py — the normalised in-memory representation every emitter reads from.

Two container types, ``IPSet`` and ``DomainSet``, plus the normalisation that
turns messy upstream input into something worth shipping:

* IP prefixes are parsed, de-duplicated and **collapsed** — ``5.160.0.0/17``
  plus ``5.160.128.0/17`` becomes ``5.160.0.0/16``. Malformed entries are
  dropped and counted rather than silently poisoning a router import.
* Domains are lower-cased, stripped of stray dots and wildcards, and **pruned**
  of redundant children: every consumer we emit for matches subdomains, so if
  ``example.com`` is in the set then ``ads.example.com`` is dead weight.
* ``collapse_tld("ir")`` replaces tens of thousands of individual ``.ir``
  entries with the single suffix rule that covers all of them.

Domain rules keep their match type. sing-box rule-sets distinguish exact
matches, suffix matches, keywords and regexes, and formats that can express
that distinction (Xray, sing-box, Clash, Surge) should not have it flattened
away. Formats that cannot (hosts files, MikroTik adlists) drop what they
cannot represent and report the count.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# A hostname label: alphanumerics and hyphens, plus underscore, which is
# invalid per RFC 1035 but shows up in real blocklists often enough to keep.
_LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})*$")


# ------------------------------------------------------------------- IP sets


@dataclass
class IPSet:
    slug: str
    title: str
    v4: list = field(default_factory=list)
    v6: list = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    malformed: int = 0

    @property
    def total(self) -> int:
        return len(self.v4) + len(self.v6)

    def all_networks(self) -> list:
        return self.v4 + self.v6

    def stats(self) -> dict:
        return {"kind": "ip", "set": self.slug, "ipv4": len(self.v4),
                "ipv6": len(self.v6), "malformed": self.malformed,
                "sources": self.sources}


def parse_networks(raw) -> tuple[list, list, int]:
    """Parse, de-duplicate and collapse an iterable of CIDR strings."""
    nets, bad = [], 0
    for item in raw:
        if not isinstance(item, str):
            item = str(item)
        item = item.strip()
        if not item or item.startswith("#"):
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            bad += 1
    v4 = sorted(ipaddress.collapse_addresses([n for n in nets if n.version == 4]))
    v6 = sorted(ipaddress.collapse_addresses([n for n in nets if n.version == 6]))
    return v4, v6, bad


def make_ipset(slug: str, title: str, raw, sources: list[str]) -> IPSet:
    v4, v6, bad = parse_networks(raw)
    return IPSet(slug=slug, title=title, v4=v4, v6=v6,
                 sources=sources, malformed=bad)


def range_to_cidrs(start: str, count: int) -> list:
    """Convert a RIPE-style ``start address + address count`` into CIDRs.

    The delegated-stats files give an inclusive host count, not a prefix
    length, and the count is not always a single aligned block — 2.57.3.0
    with 256 addresses is one /24, but a 1536-address range is a /23 plus a
    /22. ``summarize_address_range`` handles both.
    """
    first = ipaddress.ip_address(start)
    last = ipaddress.ip_address(int(first) + count - 1)
    return list(ipaddress.summarize_address_range(first, last))


# --------------------------------------------------------------- domain sets


@dataclass
class DomainSet:
    slug: str
    title: str
    suffix: set[str] = field(default_factory=set)   # domain + all subdomains
    full: set[str] = field(default_factory=set)     # exact match only
    keyword: set[str] = field(default_factory=set)  # substring match
    regex: set[str] = field(default_factory=set)    # regular expression
    sources: list[str] = field(default_factory=list)
    pruned: int = 0
    malformed: int = 0

    @property
    def total(self) -> int:
        return len(self.suffix) + len(self.full) + len(self.keyword) + len(self.regex)

    def plain_domains(self) -> list[str]:
        """Suffix + full, sorted — for formats with no notion of match type.

        hosts files, MikroTik adlists and AdGuard rules all treat a bare
        domain as covering its subdomains anyway, so folding the two together
        loses nothing for those consumers. Keywords and regexes are not
        representable and are excluded; callers report the shortfall.
        """
        return sorted(self.suffix | self.full)

    def unrepresentable(self) -> int:
        return len(self.keyword) + len(self.regex)

    def stats(self) -> dict:
        return {"kind": "domain", "set": self.slug, "suffix": len(self.suffix),
                "full": len(self.full), "keyword": len(self.keyword),
                "regex": len(self.regex), "pruned": self.pruned,
                "malformed": self.malformed, "sources": self.sources}


def clean_domain(name: str) -> str | None:
    """Normalise one hostname, or return None if it is not usable."""
    name = name.strip().lower().rstrip(".")
    if not name:
        return None
    # "*.example.com" and ".example.com" both mean the suffix example.com
    if name.startswith("*."):
        name = name[2:]
    name = name.lstrip(".")
    if not name or len(name) > 253:
        return None
    if not _DOMAIN_RE.match(name):
        return None
    return name


def prune_covered(names: set[str]) -> tuple[list[str], int]:
    """Drop every domain whose parent is already in the set.

    ``example.com`` present means ``ads.example.com`` will match anyway, in
    every format emitted here. On real ad lists this removes a large fraction
    of the entries, which is what makes the result fit on a router.
    """
    kept = []
    for name in names:
        parts = name.split(".")
        # walk every proper parent: a.b.c -> b.c, c
        if any(".".join(parts[i:]) in names for i in range(1, len(parts))):
            continue
        kept.append(name)
    return sorted(kept), len(names) - len(kept)


def make_domainset(slug: str, title: str, *, suffix=(), full=(), keyword=(),
                   regex=(), sources: list[str], collapse_tld: str | None = None,
                   prune: bool = True) -> DomainSet:
    """Build a normalised DomainSet from raw upstream values."""
    ds = DomainSet(slug=slug, title=title, sources=list(sources))

    clean_suffix, clean_full, bad = set(), set(), 0
    for name in suffix:
        c = clean_domain(name)
        if c:
            clean_suffix.add(c)
        else:
            bad += 1
    for name in full:
        c = clean_domain(name)
        if c:
            clean_full.add(c)
        else:
            bad += 1

    ds.keyword = {k.strip().lower() for k in keyword if k and k.strip()}
    ds.regex = {r.strip() for r in regex if r and r.strip()}

    if collapse_tld:
        # Replace every *.tld entry with the single rule that covers them all.
        tld = collapse_tld.lower().lstrip(".")
        dot = "." + tld
        clean_suffix = {n for n in clean_suffix if n != tld and not n.endswith(dot)}
        clean_full = {n for n in clean_full if n != tld and not n.endswith(dot)}
        clean_suffix.add(tld)

    if prune:
        # An exact-match entry already covered by a suffix rule is redundant.
        clean_full -= clean_suffix
        kept, dropped = prune_covered(clean_suffix)
        ds.suffix = set(kept)
        ds.pruned = dropped
        # and drop exact entries whose parent suffix survived
        before = len(clean_full)
        clean_full = {
            n for n in clean_full
            if not any(".".join(n.split(".")[i:]) in ds.suffix
                       for i in range(1, len(n.split(".")) + 1))
        }
        ds.pruned += before - len(clean_full)
        ds.full = clean_full
    else:
        ds.suffix, ds.full = clean_suffix, clean_full

    ds.malformed = bad
    return ds


# ------------------------------------------------ sing-box rule-set ingestion


def from_singbox_rules(rules: list) -> dict[str, set]:
    """Flatten a decompiled sing-box rule-set into our four match buckets.

    A headless rule-set is a list of rule objects, each of which may carry any
    of ``domain`` / ``domain_suffix`` / ``domain_keyword`` / ``domain_regex`` /
    ``ip_cidr``. Logical rules nest another list under ``rules``.
    """
    out = {"domain": set(), "domain_suffix": set(), "domain_keyword": set(),
           "domain_regex": set(), "ip_cidr": set()}

    def walk(items):
        for rule in items:
            if not isinstance(rule, dict):
                continue
            if isinstance(rule.get("rules"), list):
                walk(rule["rules"])
            for key in out:
                val = rule.get(key)
                if val is None:
                    continue
                out[key].update([val] if isinstance(val, str) else val)

    walk(rules)
    return out
