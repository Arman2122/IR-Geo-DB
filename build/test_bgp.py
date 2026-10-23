#!/usr/bin/env python3
"""Offline tests for bgp.py: the RIS adjustment of `ir` and provider prefixes.

    python3 build/test_bgp.py

Synthetic routes only. The rule under test is longest match: an address is
foreign only when the most specific route covering it has no Iranian origin,
and that route lies inside registry space.
"""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from testkit import done, eq, ok  # noqa: E402

import bgp  # noqa: E402
from bgp import Adjustment, BGPAnomaly, Route  # noqa: E402
from model import exclude_networks  # noqa: E402


def net(s: str):
    return ipaddress.ip_network(s)


def nets(*items: str) -> list:
    return [net(s) for s in items]


def strs(networks) -> list[str]:
    return [str(n) for n in networks]


def raises(fn, exc=BGPAnomaly):
    """The exception's message if fn raises exc, else None."""
    try:
        fn()
    except exc as e:
        return str(e) or "<raised>"
    return None


# ------------------------------------------------------------ routes_from

V4_10 = int(ipaddress.IPv4Address("10.0.0.0"))
V6_DB8 = int(ipaddress.IPv6Address("2001:db8::"))

eq(bgp.routes_from([]), [], "no values, no routes")
eq(bgp.routes_from(["100 10.0.0.0/16"]),
   [Route(4, V4_10, V4_10 + 2 ** 16 - 1, 16, 100)],
   "an IPv4 row becomes integer bounds plus its origin")
eq(bgp.routes_from(["4200000000 2001:db8::/32"]),
   [Route(6, V6_DB8, V6_DB8 + 2 ** 96 - 1, 32, 4200000000)],
   "an IPv6 row becomes integer bounds; 32-bit ASNs survive")
eq(bgp.routes_from(["1 1.2.3.4/32"]),
   [Route(4, 0x01020304, 0x01020304, 32, 1)], "a host route spans one address")
moas = bgp.routes_from(["100 10.0.8.0/24", "200 10.0.8.0/24"])
eq([r.origin for r in moas], [100, 200], "one route per RIS row, MOAS kept")
ok(all(type(x) is int for r in moas for x in r),
   "routes hold plain ints, not ip_network objects")

# -------------------------------------------------------------- asns_from

eq(bgp.asns_from(["AS100", "10.0.0.0/8", "AS4200000000", "2001:db8::/32",
                  "AS100"]),
   {100, 4200000000}, "AS tokens are read and prefixes ignored")
eq(bgp.asns_from([]), set(), "no values, no ASNs")

# --------------------------------------------------------- the main fixture
# Registry 10.0.0.0/16 + 2001:db8::/48, IR ASNs {100}.

REGISTRY = nets("10.0.0.0/16", "2001:db8::/48")
IR = {100}
ROUTES = bgp.routes_from([
    "100 20.0.0.0/24",           # add: IR route outside the registry
    "100 10.0.1.0/24",           # covered: IR route inside the registry
    "200 10.0.2.0/24",           # remove: foreign more-specific
    "200 10.0.0.0/8",            # keep: foreign LESS-specific removes nothing
    "200 10.0.4.0/22",           # nested: foreign /22 ...
    "100 10.0.5.0/24",           # ... with an IR /24 inside it
    "300 10.0.6.0/24",           # ... and a foreign /24 inside it (count once)
    "100 10.0.8.0/24",           # MOAS inside the registry: IR + foreign
    "200 10.0.8.0/24",           #   origins, so it stays Iranian
    "100 10.0.0.0/16",           # IR aggregate over the foreign more-specifics
    "100 30.0.0.0/24",           # MOAS outside the registry: eligible
    "400 30.0.0.0/24",           #   for addition
    "100 2001:db8:1::/52",       # v6 add: outside registry v6 (1/16 of it)
    "300 2001:db8:0:1::/64",     # v6 remove: foreign inside registry v6
])

adj = bgp.adjust(REGISTRY, ROUTES, IR)

ok(isinstance(adj, Adjustment), "adjust returns an Adjustment")
eq(strs(adj.added), ["20.0.0.0/24", "30.0.0.0/24", "2001:db8:1::/52"],
   "IR routes outside the registry (MOAS included) are added, v4 then v6")
ok(not any(n.overlaps(net("10.0.1.0/24")) for n in adj.added),
   "an IR route already inside the registry is not added")
ok(not any(n.overlaps(net("10.0.0.0/16")) for n in adj.added),
   "an IR route equal to the registry adds nothing")
eq(strs(adj.removed),
   ["10.0.2.0/24", "10.0.4.0/24", "10.0.6.0/23", "2001:db8:0:1::/64"],
   "foreign more-specifics are removed, minus IR routes inside them")
eq(adj.removed_addresses, 256 + 1024 - 256, "longest-match removal counts")
eq(adj.added_addresses, 512, "added_addresses counts IPv4 only")
eq(adj.registry_addresses, 2 ** 16, "registry_addresses counts IPv4 only")
ok(not any(n.overlaps(net("10.0.5.0/24")) for n in adj.removed),
   "an IR route inside a foreign route is kept")
ok(not any(n.overlaps(net("10.0.8.0/24")) for n in adj.removed),
   "a MOAS prefix with an IR origin is never removed")
ok(not any(n.overlaps(net("10.0.1.0/24")) for n in adj.removed),
   "a foreign less-specific route removes nothing")
eq((adj.excluded, adj.excluded_addresses), ([], 0),
   "an IR prefix inside the registry under a foreign route is not an "
   "excluded addition, and it still shields removal (10.0.5.0/24)")
eq((adj.registry_addresses_v6, adj.added_addresses_v6,
    adj.removed_addresses_v6), (2 ** 80, 2 ** 76, 2 ** 64),
   "IPv6 registry, added and removed addresses are counted too")

kept4, _ = exclude_networks(nets("10.0.0.0/16"),
                            [n for n in adj.removed if n.version == 4])
kept6, _ = exclude_networks(nets("2001:db8::/48"),
                            [n for n in adj.removed if n.version == 6])
want = (sorted(ipaddress.collapse_addresses(kept4 + nets("20.0.0.0/24",
                                                         "30.0.0.0/24")))
        + sorted(ipaddress.collapse_addresses(kept6 + nets("2001:db8:1::/52"))))
eq(adj.networks, want, "networks = collapse((registry - removed) + added)")
ok(any(net("10.0.5.0/24").subnet_of(n) for n in adj.networks if n.version == 4),
   "the IR /24 inside the foreign /22 is in the result")
ok(not any(n.overlaps(net("10.0.2.0/24")) for n in adj.networks),
   "the removed /24 is gone from the result")
eq(raises(lambda: bgp.check_limits(adj)), None,
   "a small adjustment passes the anomaly limits")

# announced_by: collapsed, both families
eq(strs(bgp.announced_by(ROUTES, {200})), ["10.0.0.0/8"],
   "announced_by collapses an ASN's routes into its covering prefix")
eq(strs(bgp.announced_by(ROUTES, {100, 300})),
   ["10.0.0.0/16", "20.0.0.0/24", "30.0.0.0/24",
    "2001:db8:0:1::/64", "2001:db8:1::/52"],
   "announced_by covers every listed ASN, v4 then v6")
eq(bgp.announced_by(ROUTES, set()), [], "no ASNs, no prefixes")
eq(bgp.announced_by(ROUTES, {999}), [], "an ASN with no routes, no prefixes")

# ------------------------------------------------------- equal to registry

# A foreign route equal to a registry prefix is inside it.
adj = bgp.adjust(nets("10.1.0.0/16"), bgp.routes_from(["200 10.1.0.0/16"]), IR)
eq(strs(adj.removed), ["10.1.0.0/16"],
   "a foreign route equal to a registry prefix removes it")
eq(adj.networks, [], "and nothing is left")
eq(adj.removed_addresses, 2 ** 16, "all of it is counted")

adj = bgp.adjust(nets("10.1.0.0/16"),
                 bgp.routes_from(["200 10.1.0.0/16", "100 10.1.7.0/24"]), IR)
eq(adj.removed_addresses, 2 ** 16 - 256,
   "an IR more-specific inside an equal foreign route is kept")
eq(strs(adj.networks), ["10.1.7.0/24"], "only the IR /24 survives")

# Registry space is collapsed before the inside test: two adjacent registry
# /17s form one /16, and a foreign route equal to it is inside.
adj = bgp.adjust(nets("10.2.0.0/17", "10.2.128.0/17"),
                 bgp.routes_from(["200 10.2.0.0/16"]), IR)
eq(adj.removed_addresses, 2 ** 16,
   "a foreign route equal to collapsed registry space is inside it")

# An IR aggregate that starts where a foreign more-specific starts does not
# shield it: the aggregate covers the foreign route, it is not inside it.
adj = bgp.adjust(nets("10.4.0.0/16"),
                 bgp.routes_from(["100 10.4.0.0/16", "200 10.4.0.0/24"]), IR)
eq(strs(adj.removed), ["10.4.0.0/24"],
   "a covering IR route at the same start keeps nothing of the foreign one")

# A foreign route over registry space plus more is covering, not inside.
adj = bgp.adjust(nets("10.3.0.0/17"), bgp.routes_from(["200 10.3.0.0/16"]), IR)
eq((adj.removed, adj.removed_addresses), ([], 0),
   "a foreign route larger than the registry block removes nothing")

# ------------------------------------------------- longest match on addition

# A foreign-only more-specific inside an IR prefix is not added. Longest
# match alone would put back an IR prefix inside that foreign one, but it sits
# under a foreign route, so the hijack rule keeps it out.
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "100 30.0.0.0/16", "200 30.0.4.0/22", "100 30.0.5.0/24"]), IR)
eq(adj.added_addresses, 65536 - 1024,
   "addition: IR /16 minus the foreign /22")
eq(strs(adj.added),
   ["30.0.0.0/22", "30.0.8.0/21", "30.0.16.0/20", "30.0.32.0/19",
    "30.0.64.0/18", "30.0.128.0/17"],
   "addition: the foreign /22 is cut out")
eq((strs(adj.excluded), adj.excluded_addresses), (["30.0.5.0/24"], 256),
   "addition: the IR /24 inside the foreign /22 is hijack-shaped, left out")
ok(not any(n.overlaps(net("30.0.4.0/22")) for n in adj.networks),
   "addition: foreign-routed space stays out of the result")

# Deeper nesting: IR /16 > foreign /22 > IR /24 > foreign /25. The /24 is
# under a foreign route, so only the /16's own share is added.
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "100 40.0.0.0/16", "200 40.0.4.0/22", "100 40.0.5.0/24",
    "300 40.0.5.128/25"]), IR)
eq((adj.added_addresses, adj.excluded_addresses), (65536 - 1024, 256 - 128),
   "addition: the nested IR /24 is excluded, minus the foreign /25 it lost")

# MOAS inside an IR prefix is Iranian, so it does not cut the addition.
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "100 30.0.0.0/16", "200 30.0.8.0/24", "100 30.0.8.0/24"]), IR)
eq(strs(adj.added), ["30.0.0.0/16"], "addition: a MOAS more-specific stays")

# A foreign route covering an IR prefix outside the registry: hijack-shaped.
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "200 50.0.0.0/8", "100 50.1.0.0/16"]), IR)
eq((adj.added, strs(adj.excluded), adj.excluded_addresses),
   ([], ["50.1.0.0/16"], 65536),
   "addition: an IR prefix under a foreign less-specific route is excluded")

# An IR prefix straddling the registry: only the uncovered part, minus a
# foreign more-specific there, is added; one inside the registry is removed.
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "100 10.0.0.0/15", "200 10.1.4.0/22", "200 10.0.9.0/24"]), IR)
eq(adj.added_addresses, 65536 - 1024, "addition: registry and foreign cut out")
eq(strs(adj.removed), ["10.0.9.0/24"],
   "removal is unchanged under an IR aggregate")

# v6 follows the same rule.
adj = bgp.adjust(nets("2001:db8::/48"), bgp.routes_from([
    "100 2001:db8:100::/40", "200 2001:db8:100::/48"]), IR)
eq(strs(adj.added),
   ["2001:db8:101::/48", "2001:db8:102::/47", "2001:db8:104::/46",
    "2001:db8:108::/45", "2001:db8:110::/44", "2001:db8:120::/43",
    "2001:db8:140::/42", "2001:db8:180::/41"],
   "addition: v6 foreign more-specifics are cut out too")

# ---------------------------------------------------- neutral provider ASNs
# AS500 stands for a provider's own ASN registered abroad (Sotoon's AS41227).

NEUTRAL = {500}

adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from(["500 10.0.9.0/24"]),
                 IR)
eq(strs(adj.removed), ["10.0.9.0/24"],
   "control: without neutral_asns the provider's route counts as foreign")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from(["500 10.0.9.0/24"]),
                 IR, NEUTRAL)
eq((adj.removed, adj.added, strs(adj.networks)), ([], [], ["10.0.0.0/16"]),
   "neutral: its more-specific inside the registry is neither removed nor "
   "added")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from(["500 60.0.0.0/24"]),
                 IR, NEUTRAL)
eq((adj.added, adj.added_addresses, strs(adj.networks)),
   ([], 0, ["10.0.0.0/16"]),
   "neutral: a prefix outside the registry is not added (a foreign edge)")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "500 10.0.9.0/24", "200 10.0.9.0/24"]), IR, NEUTRAL)
eq(strs(adj.removed), ["10.0.9.0/24"],
   "neutral: MOAS with neutral + foreign origins is still foreign")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "500 10.0.9.0/24", "100 10.0.9.0/24"]), IR, NEUTRAL)
eq(adj.removed, [], "neutral: MOAS with neutral + Iranian origins is Iranian")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "200 10.0.8.0/22", "500 10.0.9.0/24"]), IR, NEUTRAL)
eq(strs(adj.removed), ["10.0.8.0/22"],
   "neutral: a prefix is ignored entirely, so it shields nothing inside a "
   "foreign route")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "100 30.0.0.0/16", "500 30.0.9.0/24"]), IR, NEUTRAL)
eq(strs(adj.added), ["30.0.0.0/16"],
   "neutral: a more-specific inside an IR addition cuts nothing out of it")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "100 70.0.0.0/24", "100 10.0.9.0/24", "200 10.0.8.0/22"]), IR, {100})
eq((strs(adj.added), strs(adj.removed)),
   (["70.0.0.0/24"], ["10.0.8.0/24", "10.0.10.0/23"]),
   "neutral: an ASN that is also Iranian stays Iranian (adds and shields)")

# -------------------------------------------------- hijack-shaped additions

adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "200 60.0.0.0/16", "100 60.0.1.0/24"]), IR)
eq((adj.added, strs(adj.excluded), adj.excluded_addresses),
   ([], ["60.0.1.0/24"], 256),
   "hijack: an IR /24 outside the registry under a foreign /16 is excluded")
ok(not any(n.overlaps(net("60.0.0.0/16")) for n in adj.networks),
   "hijack: and nothing of it reaches the result")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from(["100 60.0.1.0/24"]),
                 IR)
eq((strs(adj.added), adj.excluded, adj.excluded_addresses),
   (["60.0.1.0/24"], [], 0),
   "hijack: the same /24 under no covering route is added")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "500 60.0.0.0/16", "100 60.0.1.0/24"]), IR, NEUTRAL)
eq((strs(adj.added), adj.excluded), (["60.0.1.0/24"], []),
   "hijack: under a neutral covering route it is added")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "500 60.0.0.0/16", "200 60.0.0.0/16", "100 60.0.1.0/24"]), IR, NEUTRAL)
eq(strs(adj.excluded), ["60.0.1.0/24"],
   "hijack: a neutral + foreign covering route is foreign")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "200 60.0.0.0/16", "100 60.0.0.0/16", "100 60.0.1.0/24"]), IR)
eq((strs(adj.added), adj.excluded), (["60.0.0.0/16"], []),
   "hijack: a covering route with any Iranian origin does not count")
adj = bgp.adjust(nets("10.0.0.0/16"), bgp.routes_from([
    "200 60.0.0.0/8", "100 60.1.0.0/16", "100 60.1.2.0/24"]), IR)
eq((adj.added, strs(adj.excluded), adj.excluded_addresses),
   ([], ["60.1.0.0/16"], 65536),
   "hijack: every IR prefix under the foreign one is excluded, nested too")
adj = bgp.adjust(nets("60.0.1.0/24"), bgp.routes_from([
    "200 60.0.0.0/16", "100 60.0.1.0/24"]), IR)
eq((adj.added, adj.excluded, strs(adj.networks)), ([], [], ["60.0.1.0/24"]),
   "hijack: an IR prefix inside the registry is no addition to exclude")
adj = bgp.adjust(nets("2001:db8::/32"), bgp.routes_from([
    "200 2001:db9::/32", "100 2001:db9:1::/48"]), IR)
eq((adj.added, strs(adj.excluded), adj.excluded_addresses),
   ([], ["2001:db9:1::/48"], 0),
   "hijack: IPv6 too; excluded_addresses counts IPv4 only")

# --------------------------------------------------------------- edge cases

adj = bgp.adjust(nets("10.0.0.0/16", "10.0.1.0/24", "10.0.0.0/17"), [], IR)
eq(strs(adj.networks), ["10.0.0.0/16"], "no routes: the registry, collapsed")
eq((adj.added, adj.removed, adj.added_addresses, adj.removed_addresses),
   ([], [], 0, 0), "no routes: nothing added or removed")
eq(adj.registry_addresses, 2 ** 16, "overlapping registry entries count once")

adj = bgp.adjust(["10.0.0.0/16"], bgp.routes_from(["100 20.0.0.0/24"]), IR)
eq(strs(adj.networks), ["10.0.0.0/16", "20.0.0.0/24"],
   "registry entries may be CIDR strings")

adj = bgp.adjust(nets("2001:db8::/32"),
                 bgp.routes_from(["200 2001:db8:5::/48", "100 9.9.9.0/24"]),
                 IR)
eq((adj.registry_addresses, adj.added_addresses, adj.removed_addresses),
   (0, 256, 0), "v6-only registry: no IPv4 registry addresses")
eq(strs(adj.removed), ["2001:db8:5::/48"], "v6 removal with a v6-only registry")

# ------------------------------------------------------------ check_limits


def made(added: int, removed: int, registry: int) -> Adjustment:
    return Adjustment(networks=[], added=[], removed=[], added_addresses=added,
                      removed_addresses=removed, registry_addresses=registry)


msg = raises(lambda: bgp.check_limits(made(25, 0, 100)))
ok(msg is not None, "adding 25% of the registry is an anomaly")
ok(msg and "25.0%" in msg and "20%" in msg and "add" in msg,
   "the add anomaly names the share and the limit")
eq(raises(lambda: bgp.check_limits(made(15, 0, 100))), None,
   "adding 15% passes")
eq(raises(lambda: bgp.check_limits(made(20, 0, 100))), None,
   "adding exactly the limit passes")
msg = raises(lambda: bgp.check_limits(made(0, 11, 100)))
ok(msg and "11.0%" in msg and "10%" in msg and "remove" in msg,
   "removing 11% is an anomaly naming the share and the limit")
eq(raises(lambda: bgp.check_limits(made(0, 10, 100))), None,
   "removing exactly the limit passes")
eq(raises(lambda: bgp.check_limits(made(25, 0, 100), max_add=0.30)), None,
   "the add limit is configurable")
ok(raises(lambda: bgp.check_limits(made(0, 5, 100), max_remove=0.04)),
   "the remove limit is configurable")
eq(raises(lambda: bgp.check_limits(made(500, 500, 0))), None,
   "an empty IPv4 registry skips the limits")
ok(issubclass(BGPAnomaly, Exception), "BGPAnomaly is an Exception")

# IPv6 is held to the same limits against its own registry


def made6(added: int, removed: int, registry: int) -> Adjustment:
    return Adjustment(networks=[], added=[], removed=[], added_addresses=0,
                      removed_addresses=0, registry_addresses=100,
                      added_addresses_v6=added, removed_addresses_v6=removed,
                      registry_addresses_v6=registry)


msg = raises(lambda: bgp.check_limits(made6(25 << 80, 0, 100 << 80)))
ok(msg and "add 25.0%" in msg and "IPv6" in msg and "IPv4" not in msg,
   f"adding 25% of registry IPv6 is an anomaly naming the family ({msg})")
msg = raises(lambda: bgp.check_limits(made6(0, 11 << 80, 100 << 80)))
ok(msg and "remove 11.0%" in msg and "IPv6" in msg,
   "removing 11% of registry IPv6 is an anomaly")
eq(raises(lambda: bgp.check_limits(made6(20 << 80, 10 << 80, 100 << 80))),
   None, "IPv6 at exactly the limits passes")
eq(raises(lambda: bgp.check_limits(made6(500, 500, 0))), None,
   "an empty IPv6 registry skips the IPv6 limits")
both = Adjustment(networks=[], added=[], removed=[], added_addresses=0,
                  removed_addresses=50, registry_addresses=100,
                  added_addresses_v6=0, removed_addresses_v6=50,
                  registry_addresses_v6=100)
msg = raises(lambda: bgp.check_limits(both))
ok(msg and "IPv4" in msg and "IPv6" in msg,
   "each family's breach is reported")
eq(raises(lambda: bgp.check_limits(made(15, 5, 100))), None,
   "an Adjustment built without IPv6 counts has no IPv6 limits to break")
adj = bgp.adjust(nets("10.0.0.0/16", "2001:db8::/48"), bgp.routes_from([
    "100 2001:db9::/32"]), IR)
ok(raises(lambda: bgp.check_limits(adj)),
   "a real IPv6 leak by an IR ASN trips the limit")

done()
