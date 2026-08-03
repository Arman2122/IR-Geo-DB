#!/usr/bin/env python3
"""The normalised representation every emitter reads from.

IPSet and DomainSet, plus the normalisation that turns messy upstream input
into something worth shipping: prefixes collapsed, malformed entries counted
rather than passed through, redundant subdomains pruned, and match types
preserved for the formats that can express them.
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
    """Convert a RIR-style start address plus host count into CIDRs.

    The count is an inclusive number of addresses, not a prefix length, and
    is not always one aligned block: 1536 addresses is a /22 plus a /23.
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
        """Suffix + full, for formats with no notion of match type.

        hosts files, adlists and AdGuard rules treat a bare domain as covering
        its subdomains anyway. Keywords and regexes are not representable;
        callers report the shortfall.
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

    With example.com present, ads.example.com matches anyway in every format
    emitted here.
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
    """Flatten a decompiled sing-box rule-set into the match buckets.

    Logical rules nest another rule list under "rules".
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
