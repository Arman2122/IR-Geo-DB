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


def exclude_networks(base: list, drop: list) -> tuple[list, int]:
    """Remove every part of ``base`` that overlaps ``drop``.

    Returns the remainder and the number of *addresses* removed; a prefix
    count would be misleading, since excluding a /24 from a /8 leaves more
    prefixes than it started with. ``base`` may mix IPv4 and IPv6; the
    remainder is collapsed per family, IPv4 first.
    """
    if not drop:
        return base, 0
    drop_by_ver = {4: sorted(n for n in drop if n.version == 4),
                   6: sorted(n for n in drop if n.version == 6)}
    before = sum(n.num_addresses for n in base)
    kept = []
    for net in base:
        pieces = [net]
        for bad in drop_by_ver[net.version]:
            if not pieces:
                break
            nxt = []
            for piece in pieces:
                if not piece.overlaps(bad):
                    nxt.append(piece)
                elif bad.subnet_of(piece):
                    nxt.extend(piece.address_exclude(bad))
                # otherwise piece sits inside bad and is dropped
            pieces = nxt
        kept.extend(pieces)
    # collapse_addresses raises on a mixed list, and a provider list with one
    # bad IPv4 and one bad IPv6 entry must not stop the build
    kept = [n for v in (4, 6) for n in sorted(ipaddress.collapse_addresses(
        [k for k in kept if k.version == v]))]
    return kept, before - sum(n.num_addresses for n in kept)


def invert_networks(exclude: list, version: int = 4) -> list:
    """Return the complement of ``exclude`` within the full address space.

    Used for split-tunnel configs (e.g. WireGuard AllowedIPs) that route
    everything *except* domestic and private ranges through a tunnel.
    """
    universe = [ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")]
    drop = [n for n in exclude if n.version == version]
    kept, _ = exclude_networks(universe, drop)
    return kept


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
    """Normalise one hostname (including Unicode IDNs), or return None."""
    name = name.strip().lower().rstrip(".")
    if not name:
        return None
    # "*.example.com" and ".example.com" both mean the suffix example.com
    if name.startswith("*."):
        name = name[2:]
    name = name.lstrip(".")
    if not name:
        return None
    # Convert Unicode IDNs (e.g. Persian .ایران labels) to ASCII punycode;
    # pure ASCII takes the fast path without IDNA overhead.
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
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
                   regex=(), sources: list[str],
                   collapse_tld: str | tuple[str, ...] | None = None,
                   prune: bool = True) -> DomainSet:
    """Build a normalised DomainSet from raw upstream values.

    collapse_tld is one TLD or a tuple of them; each is collapsed the same way.
    """
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
        tlds = (collapse_tld,) if isinstance(collapse_tld, str) else collapse_tld
        for tld in tlds:
            tld = tld.lower().lstrip(".")
            if not tld:
                continue
            dot = "." + tld
            clean_suffix = {n for n in clean_suffix
                            if n != tld and not n.endswith(dot)}
            clean_full = {n for n in clean_full
                          if n != tld and not n.endswith(dot)}
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
            if not any(p in ds.suffix for p in _parents(n))
        }
        ds.pruned += before - len(clean_full)
        ds.full = clean_full
    else:
        ds.suffix, ds.full = clean_suffix, clean_full

    ds.malformed = bad
    return ds


# ------------------------------------------------------------ domain filters


def _parents(name: str):
    """Yield name, then each proper parent suffix: a.b.c -> a.b.c, b.c, c."""
    parts = name.split(".")
    for i in range(len(parts)):
        yield ".".join(parts[i:])


def _rule_forms(rule: str) -> tuple[str, ...]:
    """Return the rule itself plus its ASCII punycode form when non-ASCII."""
    if rule.isascii():
        return (rule,)
    try:
        ascii_form = rule.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return (rule,)
    return (rule, ascii_form) if ascii_form != rule else (rule,)


def public_suffixes(rules: list[str]) -> set[str]:
    """Rule names from both PSL sections, with `private:`, `*.` and `!` stripped.

    `rules` are sources.parse_psl values. Non-ASCII IDN rules are included in
    both Unicode and punycode forms so punycode hostnames always match.
    """
    out = set()
    for rule in rules:
        if rule.startswith("private:"):
            rule = rule[len("private:"):]
        if rule.startswith("!"):
            rule = rule[1:]
        if rule.startswith("*."):
            rule = rule[2:]
        if rule:
            out.update(_rule_forms(rule))
    return out


def psl_filter(names: set[str], rules: list[str],
               keep: frozenset[str] = frozenset()) -> tuple[set[str], int]:
    """Drop names that are shared-hosting suffixes from the PSL private section.

    A suffix rule for `dyndns.org` would route every host under it, so the
    suffix itself must not be emitted. Only `private:` rules count. A name goes
    if it equals a plain rule, or is a direct child of a `*.x` rule unless a
    `!name` exception covers that exact name. Names deeper under a suffix
    (foo.dyndns.org) are specific hosts and stay, and `keep` overrides all.
    Returns (kept, removed_count).
    """
    plain, wild, exempt = set(), set(), set()
    for rule in rules:
        if not rule.startswith("private:"):
            continue
        rule = rule[len("private:"):]
        if rule.startswith("!"):
            exempt.update(_rule_forms(rule[1:]))
        elif rule.startswith("*."):
            wild.update(_rule_forms(rule[2:]))
        else:
            plain.update(_rule_forms(rule))

    kept = set()
    for name in names:
        if name not in keep:
            if name in plain:
                continue
            parent = name.partition(".")[2]
            if parent in wild and name not in exempt:
                continue
        kept.add(name)
    return kept, len(names) - len(kept)


def subtract_allowlist(names: set[str], allow: set[str],
                       public_suffixes: set[str]) -> tuple[set[str], int]:
    """Drop names that equal, or sit under, an allowlist entry.

    An entry that is a single label or a public suffix is ignored: allowing
    `com` must not wipe out every .com name. Each name's parent suffixes are
    looked up in a set, so the cost is names x labels, not names x allow.
    Returns (kept, removed_count).
    """
    effective = {a for a in allow if "." in a and a not in public_suffixes}
    kept = {n for n in names if not any(p in effective for p in _parents(n))}
    return kept, len(names) - len(kept)


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
