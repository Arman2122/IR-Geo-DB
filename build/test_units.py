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

import gzip
import ipaddress
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emitters  # noqa: E402
import geodat  # noqa: E402
import sources  # noqa: E402
from build import exclude_networks  # noqa: E402
from model import (IPSet, clean_domain, from_singbox_rules,  # noqa: E402
                   make_domainset, parse_networks, prune_covered,
                   psl_filter, public_suffixes, range_to_cidrs,
                   subtract_allowlist)

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

got = sources.parse_rir(RIR_SAMPLE).values
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
eq(sources.parse_rir(RIR_SAMPLE, country="DE").values, ["1.2.3.0/24"],
   "RIR: country filter is honoured")

# An asn record's value is a count of consecutive ASNs from `start`, not an
# end number, and only delegated statuses count — same rule as address space.
rir = sources.parse_rir(RIR_SAMPLE + b"ripencc|IR|asn|12880|1|20000101|allocated|x\n"
                                     b"ripencc|IR|asn|60000|3|20000101|assigned|y\n"
                                     b"ripencc|IR|asn|70000|2|20000101|reserved|z\n"
                                     b"ripencc|DE|asn|3320|1|20000101|allocated|w\n")
eq(sorted(v for v in rir.values if v.startswith("AS")),
   ["AS12880", "AS60000", "AS60001", "AS60002"],
   "rir: ASN runs, delegated IR records only")
eq(rir.invalid, 0, "rir: skipped countries and statuses are not invalid")
eq(sources.parse_rir(RIR_SAMPLE + b"ripencc|IR|asn|2|4294967295|20000101|allocated|x\n"
                                  b"ripencc|IR|ipv4|not-an-ip|256|20200101|allocated|y\n"
                     ).invalid,
   2, "rir: an ASN run past 2^32-1 and a bad address are counted, not emitted")

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
eq(sources.parse_adblock(ADBLOCK).values, ["ads.example.com", "bad.example.com"],
   "adblock: only unqualified whole-domain rules are taken")

HOSTS = b"""\
# comment
0.0.0.0 ads.example.com
127.0.0.1 tracker.example.net
0.0.0.0 trailing.example.org # inline comment
1.2.3.4 not-a-sinkhole.example.com
"""
eq(sources.parse_hosts(HOSTS).values,
   ["ads.example.com", "tracker.example.net", "trailing.example.org"],
   "hosts: only sinkhole addresses count as blocks")

DOMAINS = b"""\
# comment
example.com

0.0.0.0 mixed.example.net
another.example.org
"""
eq(sources.parse_domains(DOMAINS).values,
   ["example.com", "mixed.example.net", "another.example.org"],
   "domains: tolerates a hosts-style line inside a domain list")

eq(sources.parse_cidr(b"1.2.3.0/24 # note\n\n; semi\n2001:db8::/32\n").values,
   ["1.2.3.0/24", "2001:db8::/32"], "cidr: comments and blanks are stripped")
eq(sources.parse_cidr(b"\xef\xbb\xbf5.145.115.0/24\r\n147.160.138.19 \r\nnot-ip\n2001:db8::1\n").values,
   ["5.145.115.0/24", "147.160.138.19/32", "2001:db8::1/128"], "cidr: BOM, CRLF, bare IPs")
eq(sources.parse_cidr(b"1.2.3.0/24\ngarbage\n").invalid, 1, "cidr: invalid lines counted")
eq(sources.parse_cidr(b"# note\n\n; semi\n").invalid, 0,
   "cidr: comments and blanks are not invalid")

eq(sources.parse_fastly_json(b'{"addresses":["1.2.3.0/24"],'
                             b'"ipv6_addresses":["2001:db8::/32"]}').values,
   ["1.2.3.0/24", "2001:db8::/32"], "fastly json: both families")

eq(sources.parse_google_json(
    b'{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},{"ipv6Prefix":"2001:db8::/32"}]}').values,
   ["1.2.3.0/24", "2001:db8::/32"], "google json: both families")
eq(sources.parse_google_json(b'{"prefixes":[{"ipv4Prefix":"1.2.3.0/24"},'
                             b'{"ipv4Prefix":"junk"}]}').invalid,
   1, "google json: a malformed prefix is counted, not passed through")
eq(sources.parse_aws_json(b'{"prefixes":[{"ip_prefix":"1.2.3.0/24"}],'
                          b'"ipv6_prefixes":[{"ipv6_prefix":"2001:db8::/32"}]}').values,
   ["1.2.3.0/24", "2001:db8::/32"], "aws json: both families")
eq(sources.parse_gcore_json(b'{"addresses":["1.2.3.0/24"],'
                            b'"addresses_v6":["2001:db8::/32"]}').values,
   ["1.2.3.0/24", "2001:db8::/32"], "gcore json: both families")

# Every domain parser runs clean_domain. A line that has the shape of an entry
# but is rejected is counted, so a feed that turns to garbage shows up in
# `invalid`; a line skipped on purpose (an option rule, a non-sinkhole address)
# is not.
for parser, text, names, rejected, why in (
        (sources.parse_domains,
         b"Example.COM.\n*.wild.example.com\nbad_.-x.com\nads-*.example.net\n",
         ["example.com", "wild.example.com"], 2, "domains"),
        (sources.parse_hosts,
         b"0.0.0.0 EXAMPLE.com\n0.0.0.0 ads-*.example.net\n"
         b"1.2.3.4 not-a-sinkhole.example.com\n",
         ["example.com"], 1, "hosts"),
        (sources.parse_adblock,
         b"||EXAMPLE.com^\n||-bad.example.net^\n||x.example.org^$third-party\n",
         ["example.com"], 1, "adblock"),
        (sources.parse_adguard_allow,
         b"||A.Example.com^\n||-bad.example.net^\n@@||x.com^$important\n",
         ["a.example.com"], 1, "adguard allow")):
    res = parser(text)
    eq(res.values, names, f"{why}: names are cleaned")
    eq(res.invalid, rejected, f"{why}: rejected names are counted, skipped rules are not")


# ----------------------------------------------- feeds for the BGP and filters

# RIS whois dump rows are origin<TAB>prefix<TAB>peers. Only well-seen routes of
# a sane size are kept: too few peers, or a prefix shorter than /8, is dropped.
RIS = (b"% comment\n\n42337\t5.160.0.0/16\t300\n174\t0.0.0.0/0\t4\n"
       b"{1,2}\t9.9.9.0/24\t300\n1299\t8.0.0.0/7\t50\n64512\t1.2.3.0/24\t9\n")
eq(sources.parse_ris(RIS).values, ["42337 5.160.0.0/16"],
   "ris: peers >= 10, v4 length >= /8, AS-sets skipped")
eq(sources.parse_ris(gzip.compress(RIS)).values, ["42337 5.160.0.0/16"], "ris: .gz input")
eq(sources.parse_ris(RIS).invalid, 0,
   "ris: filtered and AS-set rows are skipped by design, not invalid")
eq(sources.parse_ris(b"3333\t2001:db8::/32\t160\n3333\t2000::/15\t160\n"
                     b"3333\t2001:db8::/48\t9\n").values,
   ["3333 2001:db8::/32"], "ris: v6 length >= /16, peers >= 10")
eq(sources.parse_ris(b"3333\t193.0.0.0/21\t160\nshort row\nx\t1.2.3.0/24\t99\n"
                     b"5\t1.2.3.0/99\t99\n5\t1.2.3.0/24\tmany\n").invalid,
   4, "ris: short rows, bad origins, prefixes and peer counts are counted")
try:
    sources.parse_ris(gzip.compress(RIS)[:-12])
    truncated = False
except EOFError:
    truncated = True
ok(truncated, "ris: a truncated download raises instead of parsing as a shorter list")

ORG_JSON = (b'{"objects":{"object":[{"attributes":{"attribute":'
            b'[{"name":"aut-num","value":"AS202319"},{"name":"as-name","value":"Sotoon-CDN"}]}}]}}')
eq(sources.parse_ripe_org_asns(ORG_JSON).values, ["AS202319"], "ripe org: aut-nums")
eq(sources.parse_ripe_org_asns(ORG_JSON.replace(b"AS202319", b"ASxyz")).invalid, 1,
   "ripe org: a malformed aut-num is counted")

DLC = geodat.encode_geosite({"category-ir": [(geodat.ROOT_DOMAIN, "aparat.com"),
                                             (geodat.FULL, "x.digikala.com"),
                                             (geodat.PLAIN, "kw")],
                             "google": [(geodat.ROOT_DOMAIN, "google.com")]})
eq(sources.parse_v2fly_dlc(DLC).values, ["aparat.com", "full:x.digikala.com"],
   "dlc: CATEGORY-IR domain + full only")
eq(sources.parse_v2fly_dlc(geodat.encode_geosite(
    {"category-ir": [(geodat.ROOT_DOMAIN, "ads-*.x.ir"), (geodat.REGEX, r"^x$")]})).invalid,
   1, "dlc: a rejected name is counted, a regexp entry is not")

PSL = (b"// ===BEGIN ICANN DOMAINS===\nir\nco.ir\n// ===END ICANN DOMAINS===\n"
       b"// ===BEGIN PRIVATE DOMAINS===\ndyndns.org\n*.compute.example\n"
       b"!www.compute.example\n// ===END PRIVATE DOMAINS===\n")
eq(sources.parse_psl(PSL).values,
   ["ir", "co.ir", "private:dyndns.org", "private:*.compute.example",
    "private:!www.compute.example"], "psl")
# Rules are not hostnames, so they must not go through clean_domain: that would
# strip the wildcard, reject '!' and reject IDN rules.
IDN = b"\xd8\xa7\xdb\x8c\xd8\xb1\xd8\xa7\xd9\x86"       # the Persian word for Iran
eq(sources.parse_psl(b"// c\n\nCO.IR  trailing comment\n" + IDN + b"\n").values,
   ["co.ir", IDN.decode()], "psl: first token, lower-cased, IDN kept")
eq(sources.parse_psl(b"ok\na..b\nx.*.y\n").invalid, 2,
   "psl: empty labels and misplaced wildcards are counted")

eq(sorted(sources.parse_adguard_allow(
    b"! c\n||a.example.com^\n@@||b.example.org^|\n@@||x.com^$important\n/re/\n").values),
   ["a.example.com", "b.example.org"], "adguard allow: plain rules only")

ok("html_cidr" not in sources.PARSERS, "the unused html_cidr parser is gone")
for name in ("ris", "ripe_org_asns", "v2fly_dlc", "psl", "adguard_allow"):
    ok(name in sources.PARSERS, f"parser '{name}' is registered")
ok(all(s.parser in sources.PARSERS for s in sources.SOURCES),
   "every registered source names a parser that exists")


# ------------------------------------------------------------ source registry

keys = [s.key for s in sources.SOURCES]
eq(len(keys), len(set(keys)), "source keys unique")
ok(all(s.parser in sources.PARSERS for s in sources.SOURCES), "every parser exists")
ok(all(u.startswith("https://") for s in sources.SOURCES for u in (s.url, *s.mirrors)),
   "https only")
ok(all(s.license and s.homepage for s in sources.SOURCES),
   "license + homepage on every source")
eq({s.key for s in sources.SOURCES if not s.optional}, {"rir-ripencc", "ir-domains"},
   "only two required")
ok(all(f"ripe-org-{o.lower()}" in keys for p in sources.PROVIDERS.values() for o in p["orgs"]),
   "org sources exist")
ok(all(k in keys for p in sources.PROVIDERS.values() for k in p["lists"]),
   "provider lists exist")
ok(sources.BY_KEY["threat-ip-hagezi"].max_stale_days == 7
   and sources.BY_KEY["arvancloud"].max_stale_days == 90, "stale windows")
ok(not any(k in keys for k in ("ads-adguard", "malware-urlhaus", "phishing-db",
                               "threat-ip-phishing", "ads-persian")),
   "removed sources gone")

eq(sources.PROVIDERS, {
    "ArvanCloud": {"orgs": ["ORG-NAAP1-RIPE", "ORG-NAAC1-RIPE", "ORG-AGTL2-RIPE"],
                   "lists": ["arvancloud"]},
    "Sotoon": {"orgs": ["ORG-HUCC1-RIPE", "ORG-IB117-RIPE"], "lists": []},
    "Derak": {"orgs": ["ORG-ENDC1-RIPE"], "lists": ["derak-v4", "derak-v6"]},
    "IranServer": {"orgs": ["ORG-GWSN7-RIPE"], "lists": ["iranserver"]},
    "MizbanCloud": {"orgs": ["ORG-SAML1-RIPE"], "lists": ["mizbancloud"]},
    "ParsPack": {"orgs": [], "lists": ["parspack"]},
}, "providers: exactly the spec 1.1 registry")
org_keys = [k for k in keys if k.startswith("ripe-org-")]
eq(sorted(org_keys),
   sorted(f"ripe-org-{o.lower()}" for p in sources.PROVIDERS.values()
          for o in p["orgs"]),
   "one RIPE org source per provider organisation, and no others")
ok(all(sources.BY_KEY[k].parser == "ripe_org_asns"
       and sources.BY_KEY[k].max_stale_days == 90
       and sources.BY_KEY[k].min_bytes == 50
       and sources.BY_KEY[k].license == "RIPE Database (public)"
       and sources.BY_KEY[k].kind == "ip" for k in org_keys),
   "RIPE org sources: parser, 90-day window, 50-byte floor, licence")
eq(sources.BY_KEY["ripe-org-org-hucc1-ripe"].url,
   "https://rest.db.ripe.net/search.json?query-string=ORG-HUCC1-RIPE"
   "&inverse-attribute=org&type-filter=aut-num&flags=no-referenced",
   "RIPE org source: the REST inverse query from the spec")

eq([(s.key, s.attribution) for s in sources.SOURCES if s.attribution],
   [("ris-v4", "Contains RIPE NCC RIS data © RIPE NCC"),
    ("ris-v6", "Contains RIPE NCC RIS data © RIPE NCC")],
   "only the RIS sources carry an attribution, and it is the RIPE NCC text")
eq((sources.BY_KEY["ris-v4"].url, sources.BY_KEY["ris-v6"].url),
   ("https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz",
    "https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz"), "RIS dump URLs")

# stale window per kind of data (spec 2, rulings R10)
STALE = (("rir-", 14), ("ris-", 14), ("xc-", 14), ("cloud-", 30),
         ("ripe-org-", 90), ("threat-ip-", 7), ("malware-", 7),
         ("phishing-", 7), ("crypto-", 7), ("ads-", 30), ("nsfw-", 30),
         ("allow-", 30), ("ir-", 30), ("psl", 30),
         ("arvancloud", 90), ("parspack", 90), ("derak-", 90),
         ("iranserver", 90), ("mizbancloud", 90))
got = {s.key: s.max_stale_days for s in sources.SOURCES}
want = {k: next(d for p, d in STALE if k.startswith(p)) for k in got}
eq(got, want, "max_stale_days follows the kind of data")

# a Last-Modified older than this is a stalled generator (ruling R22): RIS
# dumps are made several times a day, RIR files daily. Nothing else has one;
# threat feeds legitimately go quiet.
got = {s.key: s.max_age_days for s in sources.SOURCES}
want = {k: 3 if k.startswith("ris-") else 7 if k.startswith("rir-") else None
        for k in got}
eq(got, want, "max_age_days: 3 for ris-*, 7 for rir-*, unset elsewhere")

# the three HaGeZi lists carry the same three official mirrors
for key, path in (("ads-hagezi", "wildcard/light-onlydomains.txt"),
                  ("malware-hagezi-tif", "wildcard/tif.mini-onlydomains.txt"),
                  ("threat-ip-hagezi", "ips/tif.txt")):
    eq(sources.BY_KEY[key].url,
       f"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/{path}",
       f"{key}: primary URL")
    eq(sources.BY_KEY[key].mirrors,
       (f"https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/{path}",
        f"https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/{path}",
        f"https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/{path}"),
       f"{key}: gitlab, codeberg and jsDelivr mirrors")

# every GitHub-raw list can fall back to jsDelivr, which serves the same file
GH_RAW = re.compile(r"^https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$")
for s in sources.SOURCES:
    m = GH_RAW.match(s.url)
    if m and "hagezi" not in s.key and not s.key.startswith("xc-"):
        owner, repo, branch, path = m.groups()
        ok(f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}" in s.mirrors,
           f"{s.key}: has the jsDelivr mirror of its GitHub-raw URL")
ok(all(len(set((s.url, *s.mirrors))) == 1 + len(s.mirrors) for s in sources.SOURCES),
   "no URL repeated within a source")
eq(sources.BY_KEY["ir-domains"].mirrors,
   ("https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/domains.txt",
    "https://cdn.jsdelivr.net/gh/bootmortis/iran-hosted-domains@release/domains.txt"),
   "ir-domains: the spec 1.2 mirrors")
eq(sources.BY_KEY["psl"].mirrors,
   ("https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",),
   "psl: the GitHub mirror")
ok(not any("MasterKia" in u for s in sources.SOURCES for u in (s.url, *s.mirrors, s.homepage)),
   "the MasterKia PersianBlocker URL is gone")

# floors: a source may skip min_entries only if it can legitimately be empty,
# and then min_bytes is what guards it. A RIPE org that has ASNs is not one of
# those: an empty answer for it means the lookup broke.
EMPTY_OK = {"threat-ip-malware", "rir-apnic", "rir-arin", "rir-lacnic",
            "rir-afrinic"}
ok(all(s.min_bytes > 0 for s in sources.SOURCES), "every source has a size floor")
ok(all(s.min_entries > 0 for s in sources.SOURCES if s.key not in EMPTY_OK),
   "every source that is never empty has an entry floor")
ok(all(s.min_entries == 0 for s in sources.SOURCES if s.key in EMPTY_OK),
   "sources that can be empty rely on min_bytes alone")
# a header-only Feodo file is valid and must get past the byte floor
FEODO_EMPTY = "\n".join([
    "#" * 64,
    "# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #",
    "# Last updated: 2026-03-04 14:28:39 UTC                        #",
    "#                                                              #",
    "# Terms Of Use: https://feodotracker.abuse.ch/blocklist/       #",
    "# For questions please contact feodotracker [at] abuse.ch      #",
    "#" * 64, "#", "# DstIP", "# END 0 entries"]).encode()
eq(sources.parse_cidr(FEODO_EMPTY).values, [], "Feodo: a header-only file has no entries")
ok(len(FEODO_EMPTY) > sources.BY_KEY["threat-ip-malware"].min_bytes,
   "Feodo: min_bytes is below an empty but valid file")
eq({s.key for s in sources.SOURCES if s.max_shrink != 0.5}, {"threat-ip-malware"},
   "only Feodo overrides the shrink guard")
eq(sources.BY_KEY["threat-ip-malware"].max_shrink, 1.0,
   "Feodo may legitimately fall to near zero")

# licences stated in the rulings (R11)
for prefix, lic in (("rir-", "Registry public data"),
                    ("ris-", "RIPE NCC RIS data (attribution required)"),
                    ("ripe-org-", "RIPE Database (public)")):
    ok(all(s.license == lic for s in sources.SOURCES if s.key.startswith(prefix)),
       f"{prefix}*: licence is '{lic}'")
ok(all(s.license in ("Provider-published", "All rights reserved")
       for s in sources.SOURCES if s.key.startswith("cloud-")
       or s.key in ("arvancloud", "parspack", "derak-v4", "derak-v6",
                    "iranserver", "mizbancloud")),
   "cloud and Iranian provider lists: Provider-published or All rights reserved")
eq({k: sources.BY_KEY[k].parser for k in ("ads-persian-hosts", "ads-persian-ads",
                                         "ads-persian-trackers", "ir-v2fly", "psl",
                                         "allow-adguard-exclusions",
                                         "allow-adguard-exceptions",
                                         "nsfw-stevenblack-gambling",
                                         "threat-ip-hagezi", "iranserver")},
   {"ads-persian-hosts": "domains", "ads-persian-ads": "domains",
    "ads-persian-trackers": "domains", "ir-v2fly": "v2fly_dlc", "psl": "psl",
    "allow-adguard-exclusions": "adguard_allow",
    "allow-adguard-exceptions": "adguard_allow",
    "nsfw-stevenblack-gambling": "hosts", "threat-ip-hagezi": "cidr",
    "iranserver": "cidr"},
   "new sources use the parsers the brief names")


# ------------------------------------------------------------ domain filters

# Rules come from sources.parse_psl: ICANN rules are plain, private-section
# rules carry a "private:" prefix. Only the private section is filtered on.
R = sources.parse_psl(PSL).values
kept, n = psl_filter({"dyndns.org", "foo.dyndns.org", "a.compute.example",
                      "www.compute.example", "digikala.com"}, R)
eq(kept, {"foo.dyndns.org", "www.compute.example", "digikala.com"}, "psl filter")
eq(n, 2, "psl count")
eq(psl_filter({"dyndns.org"}, R, keep=frozenset({"dyndns.org"}))[0], {"dyndns.org"},
   "psl keep")

# A '*.' rule removes direct children only: the suffix itself and anything
# deeper are specific hosts. No exception rule here, so every child goes.
kept, n = psl_filter({"a.pages.example", "b.pages.example", "pages.example",
                      "x.a.pages.example"}, ["private:*.pages.example"])
eq(kept, {"pages.example", "x.a.pages.example"}, "psl wildcard: direct children only")
eq(n, 2, "psl wildcard count")
# ICANN rules are never filtered, even when the name equals one.
eq(psl_filter({"co.ir", "ir"}, R)[0], {"co.ir", "ir"}, "psl: icann rules are ignored")
# keep beats the wildcard rule too, and an empty rule list changes nothing.
eq(psl_filter({"a.compute.example"}, R, keep=frozenset({"a.compute.example"}))[0],
   {"a.compute.example"}, "psl keep beats a wildcard rule")
eq(psl_filter({"dyndns.org"}, []), ({"dyndns.org"}, 0), "psl: no rules, no removals")

eq(public_suffixes(R), {"ir", "co.ir", "dyndns.org", "compute.example",
                        "www.compute.example"},
   "public_suffixes: both sections, prefixes stripped")

kept, n = subtract_allowlist({"ads.x.com", "x.com", "y.com", "co.ir"},
                             {"x.com", "com", "co.ir"}, public_suffixes(R))
eq(kept, {"y.com", "co.ir"},
   "allowlist: entry + children; single label and public suffix ignored")
eq(n, 2, "allowlist count")
# The match is on a dot boundary: notx.com is not under x.com.
eq(subtract_allowlist({"notx.com", "a.b.x.com"}, {"x.com"}, set())[0], {"notx.com"},
   "allowlist: dot-boundary match, any depth")

ds = make_domainset("ir", "t", suffix=["a.ir", "xn--mgba3a4f16a", "b.xn--mgba3a4f16a",
                                       "c.com"],
                    sources=[], collapse_tld=("ir", "xn--mgba3a4f16a"))
eq(ds.suffix, {"ir", "xn--mgba3a4f16a", "c.com"}, "multi-TLD collapse")
ds = make_domainset("ir", "t", suffix=["a.ir"], full=["x.xn--mgba3a4f16a", "host.org"],
                    sources=[], collapse_tld=("ir", "xn--mgba3a4f16a"))
eq((ds.suffix, ds.full), ({"ir", "xn--mgba3a4f16a"}, {"host.org"}),
   "multi-TLD collapse also clears exact names")
# The plain string form still collapses only that one TLD.
ds = make_domainset("ir", "t", suffix=["a.ir", "b.xn--mgba3a4f16a", "c.com"],
                    sources=[], collapse_tld="ir")
eq(ds.suffix, {"ir", "b.xn--mgba3a4f16a", "c.com"}, "collapse_tld str: only that TLD")


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


# ------------------------------------------------------------- nftables

# Users re-run `nft -f` to update. If a set is only added to, a prefix that
# leaves the upstream list stays in the live set for good — so each set has
# to be flushed before its elements, inside the same file (one transaction).


def emit_nft(s: IPSet) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        emitters.ip_nftables(emitters.BuildContext(tmp, "t", "v"), s)
        with open(os.path.join(tmp, "nftables", f"{s.slug}.nft"),
                  encoding="utf-8") as fh:
            return fh.read().splitlines()


v4s = nets(*[f"10.{i}.0.0/16" for i in range(9)])  # 9 wraps past one line
v6s = nets("2001:db8::/32", "2001:db9::/32")
nft = [ln for ln in emit_nft(IPSet("ir-x", "t", v4=v4s, v6=v6s))
       if not ln.startswith("#")]
eq(nft[0], "add table inet geo", "nftables: the table is declared first")
block = nft.index("table inet geo {")
for setname, typ, want in (("ir_x_v4", "ipv4_addr", v4s),
                           ("ir_x_v6", "ipv6_addr", v6s)):
    # the exact line also proves the declaration carries no elements
    decl = nft.index(f"add set inet geo {setname} "
                     f"{{ type {typ}; flags interval; auto-merge; }}")
    flush = nft.index(f"flush set inet geo {setname}")
    fill = nft.index(f"  set {setname} {{")
    ok(decl < flush < block < fill,
       f"nftables: {setname} is declared, flushed, then filled")
    eq(nft[fill + 1:fill + 5],
       [f"    type {typ}", "    flags interval", "    auto-merge",
        "    elements = {"],
       f"nftables: {setname} is filled as an auto-merging interval set")
    body = nft[fill + 5:nft.index("    }", fill)]
    eq([e.strip() for ln in body for e in ln.split(",") if e.strip()],
       [str(n) for n in want], f"nftables: {setname} gets exactly the input")
eq(nft[nft.index("  set ir_x_v4 {") + 5].count(","), 8,
   "nftables: elements are written eight to a line")
ok(not any("delete" in ln for ln in nft),
   "nftables: never deletes — user rules may reference these sets")
ok(not any("_v6" in ln for ln in emit_nft(IPSet("y", "t", v4=v4s))),
   "nftables: an empty family gets no set, flush or add")


print(f"{passed}/{passed + failed} unit checks passed")
sys.exit(1 if failed else 0)
