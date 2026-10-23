#!/usr/bin/env python3
"""Correct the registry's view of Iran with what is actually routed.

The registry says which address space was delegated to an organisation in
Iran. RIPE RIS says which network originates each prefix today. Where the two
disagree, routing wins, decided by longest match:

- Add: prefixes originated by an Iranian ASN, minus the foreign-only prefixes
  strictly inside them (Iranian prefixes inside those count again), minus the
  registry space they overlap. Only announced prefixes are added, never a
  covering block. An Iranian prefix under a less-specific foreign-only route
  is not added at all: that is the shape of a hijack.
- Remove: prefixes inside registry space whose origins are all foreign, minus
  the Iranian-origin prefixes strictly inside them. A foreign route that
  covers registry space (a less-specific aggregate) never removes anything.
- A prefix with several origins (MOAS) counts as Iranian if any origin is.
- The Iranian providers' own ASNs that are registered abroad are neutral: a
  prefix only they originate is ignored, so it neither removes the
  provider's Iranian space nor is added.

Both main rules are the same test: the most specific route covering an
address decides whose it is.

The IPv4 table is over a million routes, so everything here works on integer
intervals. ip_network objects would cost hundreds of megabytes; they are only
built for the outputs.
"""

from __future__ import annotations

import ipaddress
import socket
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from typing import NamedTuple

_BITS = {4: 32, 6: 128}
_FAMILY = {4: socket.AF_INET, 6: socket.AF_INET6}
_ADDRESS = {4: ipaddress.IPv4Address, 6: ipaddress.IPv6Address}


class Route(NamedTuple):
    """One RIS row: a prefix as inclusive integer bounds, and its origin."""
    version: int
    start: int
    end: int
    prefixlen: int
    origin: int


@dataclass
class Adjustment:
    """The adjusted `ir` and what changed.

    `networks`, `added`, `removed` and `excluded` hold both families (IPv4
    first). The unsuffixed address counts are IPv4 and the `_v6` ones IPv6:
    each family is held to the anomaly limits against its own registry space.
    """
    networks: list
    added: list
    removed: list
    added_addresses: int
    removed_addresses: int
    registry_addresses: int
    added_addresses_v6: int = 0
    removed_addresses_v6: int = 0
    registry_addresses_v6: int = 0
    # space an Iranian-origin prefix would have added, left out because a
    # foreign-only route covers that prefix; the address count is IPv4
    excluded: list = field(default_factory=list)
    excluded_addresses: int = 0


class BGPAnomaly(Exception):
    """The adjustment would change `ir` by more than routing noise explains."""


# ------------------------------------------------------------------ inputs


def routes_from(values: list[str]) -> list[Route]:
    """Turn "<origin> <prefix>" values from the RIS parser into Routes.

    One Route per value, so a prefix with several origins appears several
    times. The parser has already validated each prefix; a value that does not
    convert is a bug upstream and raises ValueError.
    """
    out: list[Route] = []
    append = out.append
    asns: dict[str, int] = {}  # one int object per distinct origin
    for value in values:
        try:
            origin, prefix = value.split()
            asn = asns.get(origin)
            if asn is None:
                asn = asns[origin] = int(origin)
            addr, _, length = prefix.partition("/")
            version = 6 if ":" in addr else 4
            bits = _BITS[version]
            plen = int(length)
            if not 0 <= plen <= bits:
                raise ValueError
            host = (1 << (bits - plen)) - 1
            start = int.from_bytes(socket.inet_pton(_FAMILY[version], addr),
                                   "big") & ~host
        except (ValueError, OSError):
            raise ValueError(f"not a RIS route value: {value!r}") from None
        append(Route(version, start, start | host, plen, asn))
    return out


def asns_from(values: list[str]) -> set[int]:
    """The ASNs among the values: "AS<n>" tokens. Prefixes are ignored."""
    return {int(v[2:]) for v in values
            if v.startswith("AS") and v[2:].isdigit() and v[2:].isascii()}


# ------------------------------------------------------ interval arithmetic
# An interval is an inclusive (start, end) pair of integer addresses. A "runs"
# list is sorted, non-overlapping and non-touching.


def _merge(intervals) -> list[tuple[int, int]]:
    """Sort intervals and join the ones that overlap or touch."""
    out: list[list[int]] = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1] + 1:
            if e > out[-1][1]:
                out[-1][1] = e
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def _subtract(runs, holes) -> list[tuple[int, int]]:
    """runs minus holes; both must be runs lists."""
    out = []
    j = 0
    for s, e in runs:
        while j < len(holes) and holes[j][1] < s:
            j += 1
        cur, k = s, j
        while k < len(holes) and holes[k][0] <= e:
            hs, he = holes[k]
            if hs > cur:
                out.append((cur, hs - 1))
            cur = max(cur, he + 1)
            if cur > e:
                break
            k += 1
        if cur <= e:
            out.append((cur, e))
    return out


def _size(runs) -> int:
    return sum(e - s + 1 for s, e in runs)


def _networks(version: int, runs) -> list:
    """The CIDRs that exactly cover runs, in order (collapsed, as runs are)."""
    addr = _ADDRESS[version]
    out = []
    for s, e in runs:
        out.extend(ipaddress.summarize_address_range(addr(s), addr(e)))
    return out


def _registry_runs(registry) -> dict[int, list[tuple[int, int]]]:
    by_family: dict[int, list] = {4: [], 6: []}
    for item in registry:
        n = (item if isinstance(item, (ipaddress.IPv4Network,
                                       ipaddress.IPv6Network))
             else ipaddress.ip_network(item, strict=False))
        by_family[n.version].append((int(n.network_address),
                                     int(n.broadcast_address)))
    return {v: _merge(iv) for v, iv in by_family.items()}


def _longest(prefixes, rivals) -> list[tuple[int, int]]:
    """The space where one of `prefixes` is the longest match over `rivals`.

    Each prefix keeps its addresses except those under a rival strictly
    inside it. CIDR prefixes are nested or disjoint, so the union of those
    pieces is exactly that space at any depth: a prefix inside a rival inside
    another prefix gets its addresses back as a piece of its own. A rival that
    starts at the same address but is larger covers the prefix and takes
    nothing from it.
    """
    rivals = sorted(rivals)
    starts = [s for s, _ in rivals]
    pieces = []
    for s, e in prefixes:
        holes = []
        j = bisect_left(starts, s)
        while j < len(rivals) and starts[j] <= e:
            rs, r_end = rivals[j]
            if r_end <= e and (rs, r_end) != (s, e):
                holes.append((rs, r_end))
            j += 1
        pieces.extend(_subtract([(s, e)], _merge(holes)))
    return _merge(pieces)


def _supernets(version: int, start: int, end: int):
    """Every prefix strictly containing the prefix start..end, as bounds."""
    bits = _BITS[version]
    for plen in range(bits + 1 - (end - start + 1).bit_length()):
        host = (1 << (bits - plen)) - 1
        yield start & ~host, (start & ~host) | host


# -------------------------------------------------------------- adjustment


def adjust(registry: list, routes: list[Route], ir_asns: set[int],
           neutral_asns: set[int] = frozenset()) -> Adjustment:
    """Apply longest-match routing to the registry's Iranian space.

    `registry` holds ip_network objects (or CIDR strings) of both families.
    "Inside registry space" is tested against the collapsed registry, so a
    route equal to a registry block, or to adjacent blocks that collapse into
    it, is inside; a route larger than that covers it and is never removed.

    `neutral_asns` are the Iranian providers' own ASNs. Some are registered
    abroad (Sotoon's AS41227 in the Netherlands, ArvanCloud's AGTL2 ASNs in
    the UAE), so the registry does not count them as Iranian, yet a route
    they originate inside the provider's Iranian registry space is its own
    network, not space leased to a foreign host. A prefix whose origins are
    all neutral is therefore ignored: it removes nothing, cuts nothing out of
    an addition, and is not added (outside the registry it may be a foreign
    edge, which `ir-cdn` carries instead). With a foreign origin beside it, a
    prefix is foreign as before. An ASN in both sets is Iranian: most
    providers' ASNs are registered in Iran, and the registry's word stands.
    """
    reg = _registry_runs(registry)
    neutral = set(neutral_asns) - set(ir_asns)

    iranian: dict[int, set] = {4: set(), 6: set()}   # any IR origin
    for version, start, end, _, origin in routes:
        if origin in ir_asns:
            iranian[version].add((start, end))
    ir_runs = {v: _merge(iranian[v]) for v in (4, 6)}
    # every prefix that would cover an Iranian one, so that finding the
    # foreign ones below is one set lookup per route
    supernets = {v: {c for p in iranian[v] for c in _supernets(v, *p)}
                 for v in (4, 6)}

    # Foreign routes matter only inside registry space (removal), inside
    # Iranian-announced space (where they cut into an addition), or over an
    # Iranian prefix (which they keep out of the addition). The rest of the
    # table is bisected and dropped. A row is one origin, so skipping neutral
    # rows leaves a neutral-only prefix out, and neutral + foreign foreign.
    bounds = {v: ([s for s, _ in reg[v]], [e for _, e in reg[v]],
                  [s for s, _ in ir_runs[v]], [e for _, e in ir_runs[v]])
              for v in (4, 6)}
    in_registry: dict[int, set] = {4: set(), 6: set()}
    in_iranian: dict[int, set] = {4: set(), 6: set()}
    over_iranian: dict[int, set] = {4: set(), 6: set()}
    for version, start, end, _, origin in routes:
        if origin in ir_asns or origin in neutral:
            continue
        reg_s, reg_e, ir_s, ir_e = bounds[version]
        i = bisect_right(reg_s, start) - 1
        if i >= 0 and end <= reg_e[i]:
            in_registry[version].add((start, end))
        i = bisect_right(ir_s, start) - 1
        if i >= 0 and end <= ir_e[i]:
            in_iranian[version].add((start, end))
        if (start, end) in supernets[version]:
            over_iranian[version].add((start, end))

    networks, added, removed, excluded = [], [], [], []
    counts = {}
    for v in (4, 6):
        # MOAS: a prefix with any Iranian origin is Iranian, never foreign.
        removed_runs = _longest(in_registry[v] - iranian[v], iranian[v])
        # Addition mirrors removal: a foreign-only more-specific inside an
        # Iranian prefix (e.g. 188.159.224.0/19 under 188.158.0.0/15) is
        # routed abroad, so it is not added.
        rivals = in_iranian[v] - iranian[v]
        # An Iranian prefix under a foreign-only less-specific route is a
        # more-specific of someone else's block: the shape of a hijack, which
        # Iranian networks have done before, and adding it would send that
        # block's traffic "direct". It is left out. A covering prefix with
        # any Iranian origin is Iranian, so it does not count.
        foreign_over = over_iranian[v] - iranian[v]
        hijack = {p for p in iranian[v]
                  if not foreign_over.isdisjoint(_supernets(v, *p))}
        added_runs = _subtract(_longest(iranian[v] - hijack, rivals), reg[v])
        # what the addition would have been without that rule, so the audit
        # shows exactly the space it kept out
        excluded_runs = _subtract(
            _subtract(_longest(iranian[v], rivals), reg[v]), added_runs)
        result = _merge(_subtract(reg[v], removed_runs) + added_runs)

        networks += _networks(v, result)
        added += _networks(v, added_runs)
        removed += _networks(v, removed_runs)
        excluded += _networks(v, excluded_runs)
        counts[v] = (_size(added_runs), _size(removed_runs), _size(reg[v]),
                     _size(excluded_runs))

    return Adjustment(networks=networks, added=added, removed=removed,
                      added_addresses=counts[4][0],
                      removed_addresses=counts[4][1],
                      registry_addresses=counts[4][2],
                      added_addresses_v6=counts[6][0],
                      removed_addresses_v6=counts[6][1],
                      registry_addresses_v6=counts[6][2],
                      excluded=excluded, excluded_addresses=counts[4][3])


def check_limits(adj: Adjustment, max_add: float = 0.20,
                 max_remove: float = 0.10) -> None:
    """Raise BGPAnomaly if the adjustment moves too much of either family.

    On 2026-10-23 the adjustment was +1.7 % / -0.7 % of IPv4 and
    +0.2 % / -3.1 % of IPv6. A jump past the limits means a leak, a broken
    dump or a lost ASN list, not a change in Iran. Each family is measured
    against its own registry space; one with none is skipped.
    """
    problems = []
    for family, base, adds, removes in (
            ("IPv4", adj.registry_addresses, adj.added_addresses,
             adj.removed_addresses),
            ("IPv6", adj.registry_addresses_v6, adj.added_addresses_v6,
             adj.removed_addresses_v6)):
        if base <= 0:
            continue
        for verb, count, limit in (("add", adds, max_add),
                                   ("remove", removes, max_remove)):
            if count > limit * base:
                problems.append(
                    f"BGP adjustment would {verb} {count / base:.1%} of "
                    f"registry {family} addresses (limit {limit * 100:g}%; "
                    f"{count:,} of {base:,})")
    if problems:
        raise BGPAnomaly("; ".join(problems))


# ---------------------------------------------------------- provider ranges


def announced_by(routes: list[Route], asns: set[int]) -> list:
    """Every prefix originated by one of `asns`, collapsed, IPv4 first."""
    by_family: dict[int, list] = {4: [], 6: []}
    for version, start, end, _, origin in routes:
        if origin in asns:
            by_family[version].append((start, end))
    return (_networks(4, _merge(by_family[4]))
            + _networks(6, _merge(by_family[6])))
