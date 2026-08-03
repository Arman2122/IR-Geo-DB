#!/usr/bin/env python3
"""
test_units.py — offline tests for the logic that decides what ships.

    python3 build/test_units.py

No network, no binaries. These cover the transformations where a quiet bug
would produce output that still loads but routes traffic wrongly: registry
parsing, prefix exclusion, subdomain pruning, TLD collapsing, and the
blocklist parsers that decide whether a line means "block this whole domain".
"""

from __future__ import annotations

import ipaddress
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import geodat  # noqa: E402
import sources  # noqa: E402
from build import exclude_networks  # noqa: E402
from model import (clean_domain, from_singbox_rules, make_domainset,  # noqa: E402
                   parse_networks, prune_covered, range_to_cidrs)

passed = failed = 0


def eq(got, want, label: str) -> None:
    global passed, failed
    if got == want:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL {label}\n       got:  {got!r}\n       want: {want!r}")


def ok(cond, label: str) -> None:
    eq(bool(cond), True, label)


def nets(*strs):
    return [ipaddress.ip_network(s) for s in strs]


# ------------------------------------------------------------ RIR parsing

# An IPv4 record carries a host count, not a prefix length, and the count is
# not always one aligned block. Getting this wrong silently shifts range
# boundaries, so it is checked against hand-computed answers.
RIR_SAMPLE = b"""\
2|ripencc|20260803|12345|19830705|20260802|+0000
ripencc|IR|ipv4|2.144.0.0|262144|20101022|allocated|abc
ripencc|IR|ipv4|5.1.43.0|256|20210728|allocated|def
ripencc|IR|ipv4|91.0.0.0|1536|20200101|allocated|ghi
ripencc|IR|ipv6|2001:790::|32|20050614|allocated|jkl
ripencc|DE|ipv4|1.2.3.0|256|20200101|allocated|mno
ripencc|IR|ipv4|9.9.9.0|256|20200101|reserved|pqr
ripencc|IR|ipv4|8.8.8.0|256|20200101|available|stu
"""

got = sources.parse_rir(RIR_SAMPLE)
# 1536 addresses is 1024 + 512, so it summarises to a /22 followed by a /23 —
# not two equal blocks. This is exactly the case a prefix-length assumption
# would get wrong.
eq(sorted(got),
   sorted(["2.144.0.0/14", "5.1.43.0/24", "91.0.0.0/22", "91.0.4.0/23",
           "2001:790::/32"]),
   "RIR: host counts become CIDRs, 1536 splits into a /22 plus a /23")
ok("1.2.3.0/24" not in got, "RIR: other countries are excluded")
ok(not any(n.startswith("9.9.9") for n in got), "RIR: 'reserved' is not delegated")
ok(not any(n.startswith("8.8.8") for n in got), "RIR: 'available' is not delegated")
eq(sources.parse_rir(RIR_SAMPLE, country="DE"), ["1.2.3.0/24"],
   "RIR: country filter is honoured")

eq([str(n) for n in range_to_cidrs("10.0.0.0", 1536)],
   ["10.0.0.0/22", "10.0.4.0/23"], "range_to_cidrs splits unaligned counts")
eq([str(n) for n in range_to_cidrs("10.0.0.0", 256)], ["10.0.0.0/24"],
   "range_to_cidrs handles an exactly-aligned block")


# ------------------------------------------------------- prefix arithmetic

v4, v6, bad = parse_networks(["5.160.0.0/17", "5.160.128.0/17", "2001:db8::/32",
                              "not-an-ip", "10.0.0.0/8"])
eq([str(n) for n in v4], ["5.160.0.0/16", "10.0.0.0/8"],
   "adjacent halves collapse into the supernet")
eq(bad, 1, "malformed entries are counted, not passed through")
eq([str(n) for n in v6], ["2001:db8::/32"], "v4 and v6 are kept apart")

kept, removed = exclude_networks(nets("10.0.0.0/8"), nets("10.1.0.0/16"))
eq(sum(n.num_addresses for n in kept), 2 ** 24 - 2 ** 16,
   "excluding a /16 from a /8 removes exactly that many addresses")
eq(removed, 2 ** 16, "exclusion reports addresses removed")
ok(all(not n.overlaps(ipaddress.ip_network("10.1.0.0/16")) for n in kept),
   "no remaining piece overlaps the excluded range")

kept, removed = exclude_networks(nets("10.1.0.0/16"), nets("10.0.0.0/8"))
eq(kept, [], "a network wholly inside an excluded range disappears")
eq(removed, 2 ** 16, "and its addresses are counted")

kept, removed = exclude_networks(nets("10.0.0.0/8"), nets("192.168.0.0/16"))
eq([str(n) for n in kept], ["10.0.0.0/8"], "disjoint ranges are left alone")
eq(removed, 0, "and nothing is reported removed")

kept, _ = exclude_networks(nets("10.0.0.0/8"), [])
eq([str(n) for n in kept], ["10.0.0.0/8"], "an empty exclusion list is a no-op")


# --------------------------------------------------------- domain cleaning

eq(clean_domain("  EXAMPLE.COM. "), "example.com", "domains are normalised")
eq(clean_domain("*.example.com"), "example.com", "a leading wildcard is a suffix")
eq(clean_domain(".example.com"), "example.com", "a leading dot is a suffix")
eq(clean_domain("ads-*.example.com"), None, "mid-label wildcards are rejected")
eq(clean_domain("not a domain"), None, "spaces are rejected")
eq(clean_domain(""), None, "empty is rejected")
eq(clean_domain("a" * 300), None, "over-long names are rejected")
eq(clean_domain("under_score.example.com"), "under_score.example.com",
   "underscores are kept — invalid per RFC, common in real lists")

kept, dropped = prune_covered({"example.com", "ads.example.com",
                               "a.b.example.com", "other.net"})
eq(sorted(kept), ["example.com", "other.net"], "children of a listed parent go")
eq(dropped, 2, "and the drop count is reported")

kept, dropped = prune_covered({"co.uk", "bbc.co.uk"})
eq(sorted(kept), ["co.uk"], "pruning walks every parent level")


# ---------------------------------------------------------- TLD collapsing

ds = make_domainset("ir", "t", suffix=["a.ir", "b.ir", "deep.sub.ir",
                                       "digikala.com", "aparat.com"],
                    sources=[], collapse_tld="ir")
eq(ds.suffix, {"ir", "digikala.com", "aparat.com"},
   "every *.ir entry collapses into the single 'ir' rule")
ok("a.ir" not in ds.suffix, "and the individual .ir names are gone")

ds2 = make_domainset("x", "t", suffix=["a.ir", "b.com"], sources=[])
eq(ds2.suffix, {"a.ir", "b.com"}, "without collapse_tld nothing is collapsed")

# an exact-match entry already covered by a suffix rule is redundant
ds3 = make_domainset("x", "t", suffix=["example.com"],
                     full=["www.example.com", "other.net"], sources=[])
eq(ds3.suffix, {"example.com"}, "suffix survives")
eq(ds3.full, {"other.net"}, "the covered exact entry is dropped")


# ------------------------------------------------------- blocklist parsers

ADBLOCK = b"""\
! comment
||ads.example.com^
||tracker.net^$third-party
@@||allowed.example.com^
||bad.example.com^
||example.org/path^
[Adblock Plus 2.0]
"""
eq(sources.parse_adblock(ADBLOCK), ["ads.example.com", "bad.example.com"],
   "adblock: only unqualified whole-domain rules are taken")

HOSTS = b"""\
# comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net
0.0.0.0 trailing.example.org # inline comment
1.2.3.4 not-a-sinkhole.example.com
"""
eq(sources.parse_hosts(HOSTS),
   ["ads.example.com", "tracker.example.net", "trailing.example.org"],
   "hosts: only sinkhole addresses count as blocks")

DOMAINS = b"""\
# comment
example.com

0.0.0.0 mixed.example.net
another.example.org
"""
eq(sources.parse_domains(DOMAINS),
   ["example.com", "mixed.example.net", "another.example.org"],
   "domains: tolerates a hosts-style line inside a domain list")

eq(sources.parse_cidr(b"1.2.3.0/24 # note\n\n; semi\n2001:db8::/32\n"),
   ["1.2.3.0/24", "2001:db8::/32"], "cidr: comments and blanks are stripped")

eq(sources.parse_fastly_json(b'{"addresses":["1.2.3.0/24"],'
                             b'"ipv6_addresses":["2001:db8::/32"]}'),
   ["1.2.3.0/24", "2001:db8::/32"], "fastly json: both families")

eq(sources.parse_google_json(
    b'{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},{"ipv6Prefix":"2001:db8::/32"}]}'),
   ["1.2.3.0/24", "2001:db8::/32"], "google json: both families")


# ------------------------------------------------- sing-box rule ingestion

flat = from_singbox_rules([
    {"domain": ["exact.com"], "domain_suffix": ["suffix.com"]},
    {"domain_keyword": ["kw"], "domain_regex": ["^re$"]},
    {"type": "logical", "rules": [{"ip_cidr": ["1.2.3.0/24"]}]},
    "not a dict",
])
eq(flat["domain"], {"exact.com"}, "exact matches are collected")
eq(flat["domain_suffix"], {"suffix.com"}, "suffix matches are collected")
eq(flat["domain_keyword"], {"kw"}, "keywords are collected")
eq(flat["ip_cidr"], {"1.2.3.0/24"}, "nested logical rules are walked")


# --------------------------------------------------------------- geodat

blob = geodat.encode_geosite({"ir": [(geodat.ROOT_DOMAIN, "ir"),
                                     (geodat.FULL, "a.com"),
                                     (geodat.PLAIN, "kw"),
                                     (geodat.REGEX, r"^x$")]})
back = geodat.decode_geosite(blob)
eq(back[0].code, "IR", "geosite category codes are upper-cased")
eq(back[0].domains,
   [(geodat.ROOT_DOMAIN, "ir"), (geodat.FULL, "a.com"),
    (geodat.PLAIN, "kw"), (geodat.REGEX, r"^x$")],
   "all four domain match types survive a round trip")

blob = geodat.encode_geoip({"ir": nets("2.144.0.0/14", "2001:790::/32")})
back = geodat.decode_geoip(blob)
eq([str(n) for n in back[0].networks], ["2.144.0.0/14", "2001:790::/32"],
   "geoip round-trips both address families")


print(f"{passed}/{passed + failed} unit checks passed")
sys.exit(1 if failed else 0)
