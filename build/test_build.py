#!/usr/bin/env python3
"""Offline tests for build.py: how the harvested sources become the sets.

    python3 build/test_build.py

A Harvest is built by hand from small synthetic values for every source key,
so no network is touched. The registry block is 10.0.0.0/16, large enough
that the synthetic BGP changes stay well inside the anomaly limits.
"""

from __future__ import annotations

import contextlib
import copy
import io
import ipaddress
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from testkit import done, eq, ok  # noqa: E402

import bgp  # noqa: E402
import build  # noqa: E402
import fetch  # noqa: E402
import release_notes  # noqa: E402
import sources  # noqa: E402
import verify  # noqa: E402
from emitters import BuildContext, ip_ipset  # noqa: E402
from model import IPSet  # noqa: E402


def net(s: str):
    return ipaddress.ip_network(s)


def strs(networks) -> list[str]:
    return [str(n) for n in networks]


def overlaps(networks, cidr: str) -> bool:
    target = net(cidr)
    return any(n.version == target.version and n.overlaps(target)
               for n in networks)


VALUES = {
    # Registry: one IPv4 and one IPv6 block, plus the ASN tokens the RIR
    # parser emits beside them. The tokens must never reach parse_networks.
    "rir-ripencc": ["10.0.0.0/16", "2001:db8::/32", "AS58224", "AS44244"],
    "rir-apnic": [],
    "ris-v4": [
        "58224 10.0.0.0/16",        # the registry block, announced from Iran
        "64500 10.0.2.0/24",        # foreign more-specific inside it: removed
        "58224 20.0.0.0/24",        # Iranian origin outside the registry: added
        # added by BGP, but inside Cloudflare's published ranges. Cloudflare's
        # own covering route is left out on purpose: under it, the /24 would
        # be hijack-shaped and never added, and the cloud guard untested
        "44244 104.16.5.0/24",
        "202468 185.166.104.0/24",  # ArvanCloud (ORG-NAAP1-RIPE)
        "202468 185.143.232.0/24",  # ArvanCloud, inside its published list
        "202319 5.34.192.0/22",     # Sotoon (ORG-HUCC1-RIPE)
        "60423 185.204.168.0/24",   # Derak, inside its published list
        "60423 10.200.0.0/24",      # Derak announcing a bogon
    ],
    "ris-v6": ["58224 2001:db8::/32", "202468 2a0e:97c0::/32"],
    "ripe-org-org-naap1-ripe": ["AS202468"],
    "ripe-org-org-naac1-ripe": ["AS205585"],
    "ripe-org-org-hucc1-ripe": ["AS202319"],
    "ripe-org-org-endc1-ripe": ["AS60423"],
    "ripe-org-org-gwsn7-ripe": ["AS61173"],
    "arvancloud": ["185.143.232.0/22"],
    "parspack": ["104.16.8.0/24"],               # a Cloudflare edge, kept
    "derak-v4": ["192.168.204.48/28", "185.204.168.0/22"],  # one bogon
    "derak-v6": ["2a0e:1d80::/32"],
    "iranserver": ["185.4.28.10/32"],
    "mizbancloud": ["2.57.36.0/24"],
    "xc-ipverse-v4": ["10.0.0.0/16"],
    "xc-ipverse-v6": ["2001:db8::/32"],
    "xc-ipdeny-v4": ["10.0.0.0/16"],
    "cloud-cloudflare-v4": ["104.16.0.0/13"],
    "cloud-cloudflare-v6": ["2606:4700::/32"],
    "cloud-aws": ["52.94.4.0/22"],
    "threat-ip-malware": ["45.9.9.9/32", "10.1.1.1/32"],
    "threat-ip-hagezi": ["104.16.1.1/32", "185.166.104.5/32", "46.1.2.3/32",
                         "52.94.0.0/21",   # its upper half is AWS
                         "2606:4700::1111/128", "fd00::1/128",
                         "2a01:4f8::1/128"],
    "ir-domains": ["digikala.com", "dyndns.org", "foo.dyndns.org", "co.com",
                   "liara.run", "shop.ir", "news.xn--mgba3a4f16a",
                   "vistablog.ir"],
    "ir-v2fly": ["aparat.com", "ir", "full:exact.example.com",
                 "full:dyndns.org"],
    "psl": ["com", "org", "ir", "run", "io", "private:dyndns.org",
            "private:co.com", "private:liara.run", "private:github.io",
            "private:vistablog.ir"],
    "ads-persian-hosts": ["persian-ads.example", "allowed.example"],
    "ads-persian-ads": ["ads.persian.example"],
    "ads-persian-trackers": ["tracker.persian.example"],
    "ads-hagezi": ["hagezi-ads.example", "sub.allowed.example",
                   "cdn.excepted.example", "x.github.io",
                   "persian-ads.example"],
    "allow-adguard-exclusions": ["allowed.example", "github.io", "com"],
    "allow-adguard-exceptions": ["excepted.example"],
    "malware-hagezi-tif": ["bad.example"],
    "phishing-certpl": ["phish.example"],
    "crypto-nocoin": ["miner.example"],
    "nsfw-stevenblack": ["porn.example"],
    "nsfw-stevenblack-gambling": ["casino.example"],
}


def harvest(outcomes=None, **changes) -> fetch.Harvest:
    """The synthetic harvest; a key set to None is left out entirely."""
    values = {k: list(v) for k, v in VALUES.items()}
    for key, val in changes.items():
        key = key.replace("_", "-")
        if val is None:
            values.pop(key, None)
        else:
            values[key] = val
    return fetch.Harvest(values=values, outcomes=outcomes or {})


def raises(fn, exc):
    try:
        fn()
    except exc as e:
        return str(e) or "<raised>"
    return None


# ---------------------------------------------------------------- IP sets

h = harvest()
ips, audit = build.build_ip_sets(h, True)
ir = ips["ir"]

# the brief's assertions
ok(ipaddress.ip_network("20.0.0.0/24") in ips["ir"].v4, "BGP addition reaches ir")
ok(not any(n.overlaps(ipaddress.ip_network("10.0.2.0/24")) for n in ips["ir"].v4),
   "BGP removal reaches ir")
ok(any(n.overlaps(ipaddress.ip_network("185.166.104.0/24")) for n in ips["ir-cdn"].v4),
   "provider ASN prefix in ir-cdn")
ok(not any(n.overlaps(ipaddress.ip_network("192.168.204.48/28")) for n in ips["ir-cdn"].v4),
   "bogon dropped from ir-cdn")
ok(not any(n.overlaps(ipaddress.ip_network("104.16.0.0/13")) for n in ips["malware"].v4),
   "cloud range removed from threat IPs")

eq(ir.malformed, 0, "ASN tokens never reach parse_networks")
eq(strs(ir.v4), ["10.0.0.0/23", "10.0.3.0/24", "10.0.4.0/22", "10.0.8.0/21",
                 "10.0.16.0/20", "10.0.32.0/19", "10.0.64.0/18",
                 "10.0.128.0/17", "20.0.0.0/24"],
   "ir = registry - foreign more-specific + Iranian announcement")
eq(strs(ir.v6), ["2001:db8::/32"], "IPv6 registry block kept")
ok(not overlaps(ir.v4, "104.16.5.0/24"),
   "cloud guard runs after BGP: an addition inside Cloudflare is removed")
eq(audit["foreign_cloud_overlap_addresses"], 256,
   "cloud guard counts the BGP addition it removed")
eq(audit["bgp"], {"applied": True, "ir_asns": 2, "ris_generated": "",
                  "registry_addresses": 65536, "added_prefixes": 2,
                  "added_addresses": 512, "removed_prefixes": 1,
                  "removed_addresses": 256, "excluded_prefixes": 0,
                  "excluded_addresses": 0, "registry_addresses_v6": 2 ** 96,
                  "added_addresses_v6": 0, "removed_addresses_v6": 0},
   "audit.bgp shape: IPv4 counts, excluded additions and IPv6 addresses")
eq(audit["ir_ipv4_addresses"], 65536, "ir_ipv4_addresses is after adjustment")
eq(ir.sources, ["RIR delegated statistics (RIPE NCC, APNIC, ARIN, LACNIC, "
                "AFRINIC)", "RIPE NCC RIS routing data"], "ir credits")

# providers
eq(set(audit["providers"]), set(sources.PROVIDERS), "one audit entry per provider")
eq(audit["providers"]["ArvanCloud"],
   {"asns": [202468, 205585], "network_addresses": 512,
    "list_addresses": 1024, "addresses": 1280},
   "audit.providers shape: networks, list and their union")
eq(audit["providers"]["Derak"],
   {"asns": [60423], "network_addresses": 256, "list_addresses": 1024,
    "addresses": 1024},
   "every provider count is after bogon removal, announced and listed alike")
eq(audit["providers"]["Sotoon"]["addresses"], 1024,
   "a provider with no list gets its announced networks")
eq(audit["providers"]["ParsPack"]["asns"], [], "a provider with no org has no ASNs")
cdn = ips["ir-cdn"]
ok(overlaps(cdn.v4, "5.34.192.0/22"), "Sotoon's announced prefix in ir-cdn")
ok(overlaps(cdn.v4, "104.16.8.0/24"), "no cloud subtraction from ir-cdn")
ok(overlaps(cdn.v6, "2a0e:97c0::/32"), "IPv6 provider announcement in ir-cdn")
ok(overlaps(cdn.v6, "2a0e:1d80::/32"), "IPv6 provider list in ir-cdn")
ok(not overlaps(cdn.v4, "20.0.0.0/24"), "an Iranian ASN is not a provider ASN")
eq(len(cdn.v4), len(set(cdn.v4)), "ir-cdn collapsed")
eq(cdn.sources, ["ArvanCloud", "Sotoon", "Derak", "IranServer", "MizbanCloud",
                 "ParsPack", "RIPE NCC RIS routing data"], "ir-cdn credits")
eq(ips["ir-full"].sources, ir.sources + cdn.sources[:-1],
   "ir-full credits each source once")

# threat IPs
mal = ips["malware"]
eq(strs(mal.v4), ["45.9.9.9/32", "46.1.2.3/32", "52.94.0.0/22"],
   "malware IPs: bogon, cloud and ir-cdn addresses subtracted; a range "
   "partly in a cloud keeps the rest")
eq(strs(mal.v6), ["2a01:4f8::1/128"], "IPv6 bogon and cloud subtracted too")
eq(audit["threat_ip_removed"], 3 + 1024,
   "threat_ip_removed counts IPv4 addresses")
eq(mal.sources, ["Feodo Tracker / abuse.ch (CC0)",
                 "HaGeZi Threat Intelligence Feeds (GPL-3.0)"], "malware credits")
eq((ips["phishing"].total, ips["phishing"].sources), (0, []),
   "phishing IP set stays empty")
eq(set(ips), {"ir", "ir-cdn", "ir-full", "private", "malware", "phishing"},
   "same IP set keys as before")
ok("crosscheck_ipverse" in audit and "crosscheck_ipdeny" in audit,
   "cross-checks still run")

# RIS timestamp (Ruling R6)
when = "Fri, 23 Oct 2026 06:00:00 GMT"
_, a = build.build_ip_sets(harvest(outcomes={"ris-v4": fetch.Outcome(
    key="ris-v4", status="fresh", last_modified=when,
    fetched_at="2026-10-23T09:00:00Z")}), True)
eq(a["bgp"]["ris_generated"], when, "ris_generated is the dump's Last-Modified")
_, a = build.build_ip_sets(harvest(outcomes={"ris-v4": fetch.Outcome(
    key="ris-v4", status="stale", fetched_at="2026-10-23T09:00:00Z")}), True)
eq(a["bgp"]["ris_generated"], "2026-10-23T09:00:00Z",
   "ris_generated falls back to fetched_at")

# BGP unavailable: registry-only, never a failure
NOT_APPLIED = {"applied": False, "ir_asns": 0, "ris_generated": "",
               "registry_addresses": 0, "added_prefixes": 0,
               "added_addresses": 0, "removed_prefixes": 0,
               "removed_addresses": 0, "excluded_prefixes": 0,
               "excluded_addresses": 0, "registry_addresses_v6": 0,
               "added_addresses_v6": 0, "removed_addresses_v6": 0}
ips2, a2 = build.build_ip_sets(harvest(ris_v4=None, ris_v6=None), True)
eq(a2["bgp"], NOT_APPLIED, "no RIS data: BGP not applied, counts 0")
eq(strs(ips2["ir"].v4), ["10.0.0.0/16"], "no RIS data: ir is registry-only")
ok(not overlaps(ips2["ir-cdn"].v4, "185.166.104.0/24"),
   "no RIS data: ir-cdn is the published lists only")
ok(overlaps(ips2["ir-cdn"].v4, "185.143.232.0/22"),
   "no RIS data: published lists still in ir-cdn")
eq(a2["providers"]["ArvanCloud"]["network_addresses"], 0,
   "no RIS data: no provider network addresses")
eq(ips2["ir"].sources, ir.sources,
   "credits do not change with what was harvested (the shrink guard needs that)")

ips3, a3 = build.build_ip_sets(harvest(ris_v4=["garbage"]), True)
eq(a3["bgp"], NOT_APPLIED, "routes_from raising: BGP not applied")
eq(strs(ips3["ir"].v4), ["10.0.0.0/16"], "routes_from raising: registry-only ir")

msg = raises(lambda: build.build_ip_sets(
    harvest(ris_v4=["58224 30.0.0.0/8"], ris_v6=[]), True), bgp.BGPAnomaly)
ok(msg and "add" in msg, f"an over-limit addition raises BGPAnomaly ({msg})")

ips4, a4 = build.build_ip_sets(harvest(), False)
ok(overlaps(ips4["ir"].v4, "104.16.5.0/24"),
   "--no-strict-exclude reports the cloud overlap without removing it")
eq(a4["foreign_cloud_excluded"], False, "audit records the cloud guard was off")

# Provider ASNs registered abroad are neutral (review I2): AS41227 stands for
# Sotoon's ORG-IB117-RIPE network in the Netherlands. The build passes every
# ASN found under the ripe-org-* keys, the same set ir-cdn is built from.
SOTOON_NL = VALUES["ris-v4"] + ["41227 10.0.9.0/24", "41227 193.29.17.0/24"]
ips5, a5 = build.build_ip_sets(harvest(ris_v4=SOTOON_NL), True)
eq(a5["bgp"]["removed_addresses"], 512,
   "control: with no org lookup, the abroad ASN's /24 is removed as foreign")
ips5, a5 = build.build_ip_sets(harvest(ris_v4=SOTOON_NL,
                                       ripe_org_org_ib117_ripe=["AS41227"]),
                               True)
ok(any(net("10.0.9.0/24").subnet_of(n) for n in ips5["ir"].v4),
   "provider ASN abroad: its route inside registry space stays in ir")
eq((a5["bgp"]["removed_addresses"], a5["bgp"]["added_addresses"]), (256, 512),
   "provider ASN abroad: nothing more removed, nothing added")
ok(not overlaps(ips5["ir"].v4, "193.29.17.0/24"),
   "provider ASN abroad: its route outside the registry is not added to ir")
ok(overlaps(ips5["ir-cdn"].v4, "193.29.17.0/24"),
   "provider ASN abroad: ...it is in ir-cdn")
eq(a5["providers"]["Sotoon"]["asns"], [41227, 202319],
   "provider ASN abroad: the same ASNs feed ir-cdn")

# Hijack-shaped additions are left out and counted (review M2)
ips6, a6 = build.build_ip_sets(harvest(ris_v4=VALUES["ris-v4"] + [
    "58224 30.0.1.0/24", "64501 30.0.0.0/16"]), True)
ok(not overlaps(ips6["ir"].v4, "30.0.1.0/24"),
   "an Iranian /24 under a foreign /16 is not added to ir")
eq((a6["bgp"]["excluded_prefixes"], a6["bgp"]["excluded_addresses"],
    a6["bgp"]["added_addresses"]), (1, 256, 512),
   "audit.bgp counts the excluded prefix and its addresses")

# Mixed-family subtraction (review I4): one provider's v4 and v6 entries that
# each strictly contain a bogon crashed exclude_networks' collapse
private_nets = [net(p) for p in build.PRIVATE_RANGES]
got = raises(lambda: build._subtract([net("10.0.0.0/7"), net("fc00::/6")],
                                     private_nets), TypeError)
eq(got, None, "mixed-family _subtract does not raise")
eq(strs(build._subtract([net("10.0.0.0/7"), net("fc00::/6")],
                        private_nets)[0]),
   ["11.0.0.0/8", "fe00::/9", "fec0::/10"],
   "mixed-family _subtract: each family keeps its own remainder, v4 first")
ips7, a7 = build.build_ip_sets(harvest(derak_v4=["10.0.0.0/7"],
                                       derak_v6=["fc00::/6"]), True)
eq(a7["providers"]["Derak"]["list_addresses"], 2 ** 24,
   "a provider list with a v4 and a v6 bogon-containing range builds")

# ------------------------------------------------------------- domain sets

doms, daudit = build.build_domain_sets(h)
# the brief's assertions
ok("dyndns.org" not in doms["ir"].suffix and "xn--mgba3a4f16a" in doms["ir"].suffix,
   "ir domain filters")
ok("aparat.com" in doms["ir"].suffix, "v2fly CATEGORY-IR merged")
ok("allowed.example" not in doms["ads"].suffix, "AdGuard allowlist applied")
ok("casino.example" in doms["nsfw"].suffix, "gambling merged into nsfw")

d = doms["ir"]
eq(sorted(d.suffix), ["aparat.com", "digikala.com", "foo.dyndns.org", "ir",
                      "liara.run", "xn--mgba3a4f16a"],
   "ir suffixes: both ccTLDs collapsed, PSL suffixes gone, hosts under them kept")
ok("foo.dyndns.org" in d.suffix,
   "a host under a removed PSL suffix is kept (filter runs before pruning)")
ok("liara.run" in d.suffix and "liara.run" in build.IR_PLATFORM_SUFFIXES,
   "an Iranian platform suffix survives the PSL filter")
eq(sorted(d.full), ["dyndns.org", "exact.example.com"],
   "full: v2fly values land in full; the PSL filter leaves exact names alone")
ok("vistablog.ir" not in d.suffix,
   "a PSL suffix under .ir is covered by the ir rule, not filtered")
eq(daudit, {"psl_removed": 2, "allowlist_removed": {"ads": 3, "ads-ir": 1}},
   "domain audit counts")
eq(d.sources, ["Iran Hosted Domains (MIT)",
               "v2fly domain-list-community (MIT)"], "ir domain credits")

eq(sorted(doms["ads-ir"].suffix),
   ["ads.persian.example", "persian-ads.example", "tracker.persian.example"],
   "ads-ir: the three PersianBlocker lists, allowlist applied")
eq(sorted(doms["ads"].suffix),
   ["ads.persian.example", "hagezi-ads.example", "persian-ads.example",
    "tracker.persian.example", "x.github.io"],
   "ads: PersianBlocker + HaGeZi; a public-suffix allow entry is ignored")
eq(doms["ads"].sources, ["PersianBlocker (AGPL-3.0)",
                         "HaGeZi Multi LIGHT (GPL-3.0)"], "ads credits")
eq(sorted(doms["nsfw"].suffix), ["casino.example", "porn.example"],
   "nsfw: porn + gambling")
ok("allowed.example" not in doms["block-all"].suffix
   and "bad.example" in doms["block-all"].suffix,
   "block-all is built from the filtered sets")
eq((sorted(doms["malware"].suffix), sorted(doms["phishing"].suffix),
    sorted(doms["cryptominers"].suffix)),
   (["bad.example"], ["phish.example"], ["miner.example"]),
   "security sets keep their keys")

doms2, daudit2 = build.build_domain_sets(harvest(psl=None))
eq(daudit2["psl_removed"], None, "no PSL: psl_removed is None")
ok("dyndns.org" in doms2["ir"].suffix, "no PSL: the filter is skipped")

# ---------------------------------------------------------------- metadata

outcomes = {
    "psl": fetch.Outcome(key="psl", status="fresh", served_by="primary",
                         values=["com"], sha256="ab"),
    "ris-v4": fetch.Outcome(key="ris-v4", status="stale", served_by="state",
                            values=["1 1.0.0.0/24"], stale_days=2.0,
                            error="primary: HTTP 503"),
    "rir-ripencc": fetch.Outcome(key="rir-ripencc", status="fresh",
                                 served_by="primary", values=["10.0.0.0/16"]),
}
hm = harvest(outcomes=outcomes)
with tempfile.TemporaryDirectory() as tmp:
    ctx = BuildContext(outdir=tmp, timestamp="2026-10-23 00:00:00 UTC",
                       version="v2026.10.23")
    stats = build.write_metadata(ctx, ips, doms, hm, audit)
    with open(os.path.join(tmp, "stats.json"), encoding="utf-8") as fh:
        on_disk = json.load(fh)
src = stats["sources"]
eq(list(src), ["rir-ripencc", "ris-v4", "psl"], "sources in registry order")
eq((src["psl"]["license"], src["psl"]["homepage"]),
   ("MPL-2.0", "https://publicsuffix.org"),
   "license and homepage from the registry")
eq(src["ris-v4"]["attribution"], "Contains RIPE NCC RIS data © RIPE NCC",
   "RIPE attribution carried")
eq((src["ris-v4"]["status"], src["ris-v4"]["served_by"],
    src["ris-v4"]["stale_days"], src["ris-v4"]["entries"]),
   ("stale", "state", 2.0, 1), "outcome report fields carried")
ok("values" not in src["psl"], "no values in stats.json")
eq(stats["sources_failed"], {"ris-v4": "primary: HTTP 503"}, "sources_failed stays")
ok("psl" in stats["sources_ok"], "sources_ok stays")
eq(on_disk["sources"], src, "stats.json on disk carries the sources block")

# ------------------------------------------- verify's provider checks (I1)


def checks_for(applied, ris_v4_status, arvan=100, sotoon=0) -> dict:
    """{provider: passed} from verify.provider_checks for a stats dict."""
    st = {"audit": {"bgp": {"applied": applied},
                    "providers": {"ArvanCloud": {"addresses": arvan},
                                  "Sotoon": {"addresses": sotoon}}},
          "sources": ({} if ris_v4_status is None
                      else {"ris-v4": {"status": ris_v4_status}})}
    return {label.split()[1]: passed
            for label, passed in verify.provider_checks(st)}


eq(checks_for(False, "dropped"), {"ArvanCloud": True, "Sotoon": None},
   "verify: RIS dropped, so the Sotoon check is skipped, ArvanCloud kept")
eq(checks_for(True, "dropped"), {"ArvanCloud": True, "Sotoon": None},
   "verify: ris-v4 dropped with only ris-v6 applied: Sotoon skipped")
eq(checks_for(False, "stale"), {"ArvanCloud": True, "Sotoon": None},
   "verify: unreadable RIS (BGP not applied): Sotoon skipped")
eq(checks_for(True, None), {"ArvanCloud": True, "Sotoon": None},
   "verify: no ris-v4 record at all: Sotoon skipped")
eq(checks_for(True, "fresh"), {"ArvanCloud": True, "Sotoon": False},
   "verify: with routing data, a Sotoon of 0 fails")
eq(checks_for(True, "stale", sotoon=5), {"ArvanCloud": True, "Sotoon": True},
   "verify: a stale RIS copy is still routing data, so Sotoon is checked")
eq(checks_for(False, "dropped", arvan=0), {"ArvanCloud": False, "Sotoon": None},
   "verify: ArvanCloud is checked without RIS, since it publishes a list")
ok(all(passed is None or isinstance(passed, bool)
       for _, passed in verify.provider_checks({})),
   "verify: an empty stats dict gives checks, not a crash")
eq([p for _, p in verify.provider_checks(stats)], [True, True],
   "verify: the real stats above pass both provider checks")

# ------------------------------------------------------ day-over-day guard

BLOCKLISTS = ("ads", "ads-ir", "malware", "phishing", "cryptominers", "nsfw",
              "block-all")
eq(build.BLOCKLIST_SETS, BLOCKLISTS, "the blocklist sets the 60% limit covers")

base = {"audit": {"ir_ipv4_addresses": 1000},
        "ip_sets": {"ir": {"sources": ["A"]}},
        "domain_sets": {"ir": {"suffix": 100, "full": 0, "sources": ["B"]},
                        "ads": {"suffix": 1000, "full": 0, "sources": ["C"]}}}


def mk(addr, ird, ads, src="C"):
    s = copy.deepcopy(base)
    s["audit"]["ir_ipv4_addresses"] = addr
    s["domain_sets"]["ir"]["suffix"] = ird
    s["domain_sets"]["ads"]["suffix"] = ads
    s["domain_sets"]["ads"]["sources"] = [src]
    return s


def quiet(fn, *args):
    """fn(*args) with the log captured: (result, log text)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        return fn(*args), buf.getvalue()


# the brief's assertions
eq(build.shrink_problems(mk(940, 100, 1000), base) != [], True, "ir -6% trips")
eq(build.shrink_problems(mk(960, 100, 1000), base), [], "ir -4% passes")
eq(len(build.shrink_problems(mk(1000, 89, 1000), base)), 1, "ir domains -11% trips")
eq(len(build.shrink_problems(mk(1000, 100, 390), base)), 1, "ads -61% trips")
eq(quiet(build.shrink_problems, mk(1000, 100, 100, src="D"), base)[0], [],
   "changed sources skip the set")
eq(build.shrink_problems(mk(1, 1, 1), None), [], "no previous stats -> no problems")
eq(build.shrink_problems(mk(1, 1, 1), {"ip_sets": {}, "domain_sets": {}}), [],
   "old schema -> skipped, no crash")

# the limits are inclusive: a drop of exactly the limit passes
eq(build.shrink_problems(mk(950, 90, 400), base), [],
   "a drop of exactly 5% / 10% / 60% passes")
eq(len(build.shrink_problems(mk(949, 100, 1000), base)), 1, "ir 5.1% trips")
eq(len(build.shrink_problems(mk(1000, 89, 1000), base)), 1, "ir domains 11% trips")
eq(len(build.shrink_problems(mk(1000, 100, 399), base)), 1, "ads 60.1% trips")
# growth never fails
eq(build.shrink_problems(mk(2000, 500, 5000), base), [], "growth passes")
eq(build.shrink_problems(copy.deepcopy(base), base), [], "no change passes")
# every check reports, one message each
eq(len(build.shrink_problems(mk(500, 50, 100), base)), 3,
   "three breaches give three problems")

# a previous value of 0 gives nothing to compare against
zero = copy.deepcopy(base)
zero["audit"]["ir_ipv4_addresses"] = 0
zero["domain_sets"]["ir"].update(suffix=0, full=0)
zero["domain_sets"]["ads"].update(suffix=0, full=0)
eq(build.shrink_problems(mk(0, 0, 0), zero), [], "previous value 0 is skipped")
eq(build.shrink_problems(mk(5, 5, 5), zero), [], "previous 0, any new value passes")

# every blocklist domain set is held to 60%
for slug in BLOCKLISTS:
    prev_b = copy.deepcopy(base)
    prev_b["domain_sets"][slug] = {"suffix": 600, "full": 400, "sources": ["X"]}
    now_b = copy.deepcopy(prev_b)
    now_b["domain_sets"][slug].update(suffix=234, full=156)         # -61%
    got = build.shrink_problems(now_b, prev_b)
    eq(len(got), 1, f"{slug} trips at -61%")
    ok(got and got[0].startswith(f"{slug}: "), f"{slug}: message names the set")
    now_b["domain_sets"][slug].update(suffix=240, full=160)         # -60%
    eq(build.shrink_problems(now_b, prev_b), [], f"{slug} passes at exactly -60%")
# ... and no other set
other = copy.deepcopy(base)
other["domain_sets"]["misc"] = {"suffix": 1000, "full": 0, "sources": ["X"]}
now_o = copy.deepcopy(other)
now_o["domain_sets"]["misc"]["suffix"] = 1
eq(build.shrink_problems(now_o, other), [], "a set outside the lists is not checked")

# ir domains are suffix + full; keyword and regex are not counted
prev_d = copy.deepcopy(base)
prev_d["domain_sets"]["ir"].update(suffix=60, full=40, keyword=500, regex=500)
now_d = copy.deepcopy(prev_d)
now_d["domain_sets"]["ir"].update(suffix=45, full=45, keyword=0, regex=0)   # 100 -> 90
eq(build.shrink_problems(now_d, prev_d), [], "ir domains: suffix + full, -10% passes")
now_d["domain_sets"]["ir"].update(suffix=44, full=45)                       # 100 -> 89
eq(len(build.shrink_problems(now_d, prev_d)), 1,
   "ir domains: suffix + full, -11% trips")

# messages: the set, old and new values, the drop and the limit
eq(build.shrink_problems(mk(940, 100, 1000), base),
   ["ir IPv4 addresses: 1,000 → 940 (−6.0%, limit −5%)"],
   "ir IPv4 message")
eq(build.shrink_problems(mk(1000, 89, 1000), base),
   ["ir domains: 100 → 89 (−11.0%, limit −10%)"],
   "ir domains message")
big = copy.deepcopy(base)
big["domain_sets"]["ads"]["suffix"] = 229593
eq(build.shrink_problems(mk(1000, 100, 70047), big),
   ["ads: 229,593 → 70,047 (−69.5%, limit −60%)"], "ads message")

# a set is skipped, and the skip logged, when its sources changed
got, text = quiet(build.shrink_problems, mk(1000, 100, 100, src="D"), base)
eq(got, [], "ads sources changed: no problem")
eq(text, "  skip ads: sources changed\n", "ads skip is logged")
chg = mk(500, 100, 1000)
chg["ip_sets"]["ir"]["sources"] = ["A", "A2"]
got, text = quiet(build.shrink_problems, chg, base)
eq(got, [], "ir IPv4 uses ip_sets.ir.sources")
eq(text, "  skip ir IPv4 addresses: sources changed\n", "ir IPv4 skip is logged")
chg = mk(1000, 10, 1000)
chg["domain_sets"]["ir"]["sources"] = ["B2"]
got, text = quiet(build.shrink_problems, chg, base)
eq(got, [], "ir domains use domain_sets.ir.sources")
eq(text, "  skip ir domains: sources changed\n", "ir domains skip is logged")
chg = mk(500, 50, 100)
chg["domain_sets"]["ir"]["sources"] = ["B2"]
got, _ = quiet(build.shrink_problems, chg, base)
eq(len(got), 2, "a skipped set does not hide the others")
# the order a list is written in is not a change of sources
chg = mk(1000, 100, 100)
chg["domain_sets"]["ads"]["sources"] = ["C", "C2"]
prev_s = copy.deepcopy(base)
prev_s["domain_sets"]["ads"]["sources"] = ["C2", "C"]
eq(len(build.shrink_problems(chg, prev_s)), 1, "reordered sources are still compared")

# old releases lack fields; a missing field skips that one comparison. Against
# the full base, mk(1, 1, 1) breaches all three checks.
eq(len(quiet(build.shrink_problems, mk(1, 1, 1), base)[0]), 3,
   "control: all three checks fire against a complete previous release")
for label, strip, left in (
        ("audit.ir_ipv4_addresses",
         lambda p: p["audit"].pop("ir_ipv4_addresses"), 2),
        ("audit", lambda p: p.pop("audit"), 2),
        ("ip_sets.ir.sources", lambda p: p["ip_sets"]["ir"].pop("sources"), 2),
        ("domain_sets.ads.sources",
         lambda p: p["domain_sets"]["ads"].pop("sources"), 2),
        ("domain_sets.ads.full", lambda p: p["domain_sets"]["ads"].pop("full"), 2),
        ("domain_sets", lambda p: p.pop("domain_sets"), 1)):
    old = copy.deepcopy(base)
    strip(old)
    eq(len(quiet(build.shrink_problems, mk(1, 1, 1), old)[0]), left,
       f"previous release without {label}: that comparison is skipped")
eq(quiet(build.shrink_problems, mk(1, 1, 1), {})[0], [],
   "an empty previous release is skipped, no crash")
eq(quiet(build.shrink_problems, mk(1, 1, 1),
         {"audit": {"ir_ipv4_addresses": "x"}, "ip_sets": {"ir": []},
          "domain_sets": {"ads": {"suffix": None}, "ir": 7}})[0], [],
   "malformed previous values are skipped, no crash")
eq(quiet(build.shrink_problems, {"audit": {}, "ip_sets": {}, "domain_sets": {}},
         base)[0], [], "a missing current value is skipped too")

# previous_stats: any failure is None, never an exception
eq(build.PREVIOUS_STATS_URL,
   "https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/stats.json",
   "previous release URL")
real_get = fetch.http_get
calls = []
slept: list = []


def fake_get(*results):
    """An http_get answering each call with the next result (the last one
    repeats); an exception is raised."""
    answers = list(results)

    def get(url, headers, timeout=fetch.TIMEOUT):
        calls.append((url, headers, timeout))
        result = answers.pop(0) if len(answers) > 1 else answers[0]
        if isinstance(result, BaseException):
            raise result
        return result
    return get


def prev(url=build.PREVIOUS_STATS_URL):
    """previous_stats with sleeps recorded: (result, calls made, log)."""
    calls.clear()
    slept.clear()
    got, text = quiet(build.previous_stats, url, slept.append)
    return got, len(calls), text


OK_BODY = fetch.Response(200, {}, json.dumps({"version": "v1",
                                               "audit": {}}).encode())
try:
    fetch.http_get = fake_get(fetch.FetchError(0, "no route"))
    got, n, text = prev("https://invalid.example/stats.json")
    eq(got, None, "previous_stats: a failing URL gives None")
    eq(calls[-1], ("https://invalid.example/stats.json",
                   {"User-Agent": fetch.USER_AGENT}, 60),
       "previous_stats: URL, User-Agent and 60 s timeout")
    eq((n, slept), (2, [2]),
       "previous_stats: a network error is retried once, like a source")
    eq(text, "  previous release stats.json: no route\n",
       "previous_stats: the reason for the skip is logged")
    fetch.http_get = fake_get(fetch.FetchError(503, "Service Unavailable"))
    got, n, text = prev()
    eq((got, n, slept), (None, 4, [2, 4, 8]),
       "previous_stats: a 5xx is retried with the sources' backoff")
    ok("HTTP 503" in text, "previous_stats: the 5xx is logged")
    # one blip must not switch the guard off (review M3)
    fetch.http_get = fake_get(fetch.FetchError(0, "timed out"), OK_BODY)
    got, n, text = prev()
    eq((got, n), ({"version": "v1", "audit": {}}, 2),
       "previous_stats: a timeout then a 200 still returns the stats")
    eq(text, "", "previous_stats: a recovered blip logs nothing")
    fetch.http_get = fake_get(fetch.FetchError(502, "Bad Gateway"), OK_BODY)
    eq(prev()[:2], ({"version": "v1", "audit": {}}, 2),
       "previous_stats: a 5xx then a 200 still returns the stats")
    fetch.http_get = fake_get(fetch.FetchError(404, "Not Found"))
    got, n, text = prev()
    eq((got, n, slept), (None, 1, []),
       "previous_stats: no release yet (404) is not retried")
    eq(text, "  previous release stats.json: no release yet (HTTP 404)\n",
       "previous_stats: the 404 skip is logged")
    fetch.http_get = fake_get(RuntimeError("anything"))
    got, n, text = prev()
    eq((got, n), (None, 1), "previous_stats: any exception gives None")
    ok("RuntimeError" in text, "previous_stats: the exception type is logged")
    eq(calls[-1][0], build.PREVIOUS_STATS_URL, "previous_stats: default URL")
    fetch.http_get = fake_get(fetch.Response(503, {}, b"{}"))
    got, _, text = prev()
    eq(got, None, "previous_stats: a non-200 response gives None")
    ok("HTTP 503" in text, "previous_stats: a non-200 status is logged")
    fetch.http_get = fake_get(fetch.Response(304, {}, b""))
    eq(prev()[0], None, "previous_stats: a 304 gives None")
    fetch.http_get = fake_get(fetch.Response(200, {}, b"<html>not json"))
    got, _, text = prev()
    eq(got, None, "previous_stats: a non-JSON body gives None")
    ok("not JSON" in text, "previous_stats: a non-JSON body is logged")
    fetch.http_get = fake_get(fetch.Response(200, {}, b"[1, 2]"))
    eq(prev()[0], None, "previous_stats: JSON that is not an object")
    fetch.http_get = fake_get(OK_BODY)
    eq(prev()[:2], ({"version": "v1", "audit": {}}, 1),
       "previous_stats: a 200 with JSON returns the dict")
finally:
    fetch.http_get = real_get

# the guard as main runs it: a stats-shaped dict built from the same methods
# as stats.json (`stats` is the one write_metadata returned above)
_, text = quiet(build.enforce_shrink_limits, ips, doms, audit, stats, False)
ok("FAIL" not in text and "warn" not in text, "an identical build passes the guard")
_, text = quiet(build.enforce_shrink_limits, ips, doms, audit, None, False)
eq(text, "  previous release unavailable — guard skipped\n",
   "no previous release: logged and skipped")
bigger = copy.deepcopy(stats)
bigger["audit"]["ir_ipv4_addresses"] *= 2
bigger["domain_sets"]["ads"]["suffix"] += 100
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    msg = raises(lambda: build.enforce_shrink_limits(ips, doms, audit, bigger,
                                                     False), SystemExit)
eq(msg, "set shrank beyond its limit — refusing to publish",
   "a shrunk set exits with the refusal message")
fail_lines = [ln for ln in buf.getvalue().splitlines() if ln.startswith("  FAIL ")]
eq(len(fail_lines), 2, "each problem is logged as '  FAIL <message>'")
ok(fail_lines[0].startswith("  FAIL ir IPv4 addresses: 131,072 → 65,536 "),
   "the FAIL line carries the old and new values")
_, text = quiet(build.enforce_shrink_limits, ips, doms, audit, bigger, True)
eq(len([ln for ln in text.splitlines() if ln.startswith("  warn ")]), 2,
   "--allow-shrink logs each problem as '  warn' and continues")
ok("FAIL" not in text, "--allow-shrink logs no FAIL")

# ------------------------------------------------------------ release notes

FOOTER = "Contains RIPE NCC RIS data © RIPE NCC."
BGP = {"applied": True, "ir_asns": 130, "ris_generated": "2026-10-23",
       "registry_addresses": 11_000_000, "added_prefixes": 12,
       "added_addresses": 4096, "removed_prefixes": 3, "removed_addresses": 768}


def notes(**changes) -> str:
    """render() of a small current-schema stats dict, with fields replaced."""
    st = {"version": "v1", "generated": "2026-10-23 00:00:00 UTC",
          "ip_sets": {"ir": {"ipv4": 3, "ipv6": 2},
                      "ir-cdn": {"ipv4": 1, "ipv6": 1}},
          "domain_sets": {"ir": {"suffix": 5, "full": 1}},
          "sources": {"a": {"status": "fresh", "stale_days": 0.0},
                      "b": {"status": "not-modified", "stale_days": 0.0}},
          "audit": {}}
    st.update(changes)
    return release_notes.render(st, "v1")


def stale_x(**fields) -> dict:
    return {"x": {"status": "stale", "served_by": "state", "stale_days": 2.04,
                  "error": "primary: HTTP 503", **fields}}


text = notes(sources=stale_x())
ok("| `x` | stale |" in text, "a stale source gets a Source health row")
ok("\n## Source health\n" in text, "the heading is exactly '## Source health'")
ok("| Source | Status | Served by | Age (days) | Error |" in text,
   "the Source health columns")
ok("| `x` | stale | state | 2.0 | primary: HTTP 503 |" in text,
   "the row carries served_by, the age to 1 decimal and the error")
ok("Degraded sources" not in text, "the old Degraded sources section is gone")
ok("Source health" not in notes(), "all fresh or not-modified: no Source health")
ok("Source health" not in notes(sources={}), "no sources at all: no Source health")
text = notes(sources={"x": {"status": "dropped", "served_by": "",
                            "stale_days": 0.0, "error": "nothing stored"}})
ok("| `x` | dropped | — | — | nothing stored |" in text,
   "dropped with nothing stored: no served_by, no age")
text = notes(sources=stale_x(status="dropped", served_by="", stale_days=120.0))
ok("| `x` | dropped | — | 120.0 |" in text,
   "dropped with an over-age stored copy shows that age")
text = notes(sources=stale_x(error="a|b\nc\r\nd"))
row = next(ln for ln in text.splitlines() if ln.startswith("| `x`"))
ok(row.endswith("| a\\|b c d |"), "| is escaped and newlines become spaces")
eq(row.count("|") - row.count("\\|"), 6, "an escaped | adds no column")
text = notes(sources=stale_x(error="a|b\nc" + "z" * 200))
row = next(ln for ln in text.splitlines() if ln.startswith("| `x`"))
eq(row.split(" | ")[-1], "a\\|b c" + "z" * 115 + " |",
   "the error is cut at 120 characters, then escaped")
text = notes(sources={**stale_x(), "y": {"status": "stale", "stale_days": 9.96}})
ok("| `y` | stale | — | 10.0 |  |" in text,
   "a missing served_by is a dash and a missing error is blank")
text = notes(sources={"k": {"status": "fresh"}, **stale_x(),
                      "m": {"status": "not-modified"}})
ok("| `k`" not in text and "| `m`" not in text,
   "fresh and not-modified sources stay out of the table")

for size, warned in ((21_000_000, True), (20_000_000, True),
                     (19_999_999, False)):
    eq("> **Warning:** geosite.dat is" in
       notes(audit={"geosite_dat_bytes": size}), warned,
       f"geosite.dat of {size} bytes: warning is {warned}")
ok("> **Warning:** geosite.dat is 21.0 MB — over jsDelivr's 20 MB limit, "
   "so the CDN mirror will not serve it." in
   notes(audit={"geosite_dat_bytes": 21_000_000}), "the warning line")
ok("geosite.dat is 20.5 MB" in notes(audit={"geosite_dat_bytes": 20_460_000}),
   "MB is bytes / 1e6, to 1 decimal")

# provenance: registry + BGP
text = notes(audit={"bgp": BGP})
ok("added 4,096 addresses" in text and "removed 768 addresses" in text and
   "130 Iranian ASNs" in text,
   "an applied BGP adjustment quotes the added and removed addresses")
ok("registry-only" not in text, "applied: not described as registry-only")
ok("Registry, then routing" in text and "most specific route" in text,
   "provenance: described as registry, then routing (review M7)")
ok("Iranian only if a RIR delegated" not in text,
   "provenance: the registry-only sentence is gone")
text = notes(audit={"bgp": {**BGP, "applied": False}})
ok("routing data was unavailable" in text and "registry-only" in text,
   "no BGP: routing data unavailable, so registry-only")
ok("registry-only" in notes(), "no audit.bgp at all: registry-only")
ok("Cloudflare, AWS, Google, Fastly and G-Core ranges subtracted (7 addresses)"
   in notes(audit={"foreign_cloud_excluded": True,
                   "foreign_cloud_overlap_addresses": 7}),
   "the cloud exclusion line is kept")
text = notes(audit={"providers": {"ArvanCloud": {"addresses": 12_345},
                                  "Sotoon": {"addresses": 0}}})
ok("ArvanCloud 12,345" in text and "Sotoon 0" in text,
   "a provider line lists each provider and its addresses")
ok("ArvanCloud" not in notes(), "no providers audit: no provider line")

# attribution footer
eq(notes(audit={"bgp": BGP}).rstrip().splitlines()[-1], FOOTER,
   "BGP applied: the footer is the last line")
ok(FOOTER in notes(sources={"ris-v4": {"status": "stale", "stale_days": 1.0}}),
   "a stale RIS source brings the footer")
ok(FOOTER in notes(sources={"ris-v6": {"status": "not-modified"}}),
   "a not-modified RIS source brings the footer")
ok(FOOTER not in notes(sources={"ris-v4": {"status": "dropped"},
                                "ris-v6": {"status": "dropped"}},
                       audit={"bgp": {**BGP, "applied": False}}),
   "every RIS source dropped and no BGP: no footer")
ok(FOOTER not in notes(), "no RIS at all: no footer")
text = notes(sources=stale_x(), audit={"bgp": BGP})
section = text.split("\n## Source health\n")[1].split("\n## ")[0]
ok("| `x` |" in section and FOOTER not in section,
   "an extracted Source health section ends before the footer")

# an old-schema stats.json: no sources, bgp, providers or dat size
OLD = {"version": "v2026.08.03", "generated": "2026-08-03 00:00:00 UTC",
       "ip_sets": {"ir": {"ipv4": 3, "ipv6": 2}, "ir-cdn": {"ipv4": 1, "ipv6": 1},
                   "malware": {"ipv4": 9, "ipv6": 0}},
       "domain_sets": {"ir": {"suffix": 5, "full": 1},
                       "ads": {"suffix": 7, "full": 0}},
       "sources_ok": ["rir-ripencc"], "sources_failed": {"x": "boom"},
       "audit": {"crosscheck_ipverse": {"exact_prefix_matches": 1,
                                        "address_coverage_ratio": 1.0},
                 "foreign_cloud_excluded": True}}
text = release_notes.render(OLD, "v2026.08.03")
ok(all(h in text for h in ("## Stable URLs", "## Contents",
                           "## Iranian IP provenance", "## Quick start",
                           "## Verifying")),
   "an old-schema stats dict renders every static section")
ok("Source health" not in text and "Warning" not in text and FOOTER not in text,
   "...and none of the new ones")
ok("## Contents" in release_notes.render({"ip_sets": {}, "domain_sets": {}},
                                         "v1"),
   "a stats dict with no sets renders too")

# the real thing: the stats write_metadata produced above
text = release_notes.render(stats, "v2026.10.23")
ok("| `ris-v4` | stale | state | 2.0 | primary: HTTP 503 |" in text,
   "the stale RIS source of the real stats is in the table")
ok("ArvanCloud" in text and "Sotoon" in text, "the real providers audit is quoted")
ok(FOOTER in text, "real stats: RIS in use, so the footer is present")

# ------------------------------------------------------------ ipset sizing


def ipset_lines(v4=(), v6=()) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        c = BuildContext(outdir=tmp, timestamp="2026-10-23 00:00:00 UTC",
                         version="v1")
        ip_ipset(c, IPSet(slug="t", title="T", v4=list(v4), v6=list(v6)))
        with open(os.path.join(tmp, "ipset", "t.ipset"), encoding="utf-8") as fh:
            return fh.read().splitlines()


def create_line(lines, family):
    return next(ln for ln in lines if ln.startswith(f"create t-{family} "))


def v4_nets(count):
    return [ipaddress.IPv4Network((i << 8, 24)) for i in range(count)]


# maxelem is left to the kernel default (65536) up to 75 % of it, so a small
# set's create line is the one routers already have loaded; past that it is
# one fixed value, never proportional (create -exist fails if it changes)
DEFAULT_CREATE = "create t-v4 hash:net family inet -exist"
LARGE_CREATE = "create t-v4 hash:net family inet maxelem 1048576 -exist"
lines = ipset_lines(v4=v4_nets(40_000))
eq(create_line(lines, "v4"), DEFAULT_CREATE, "40,000 entries: no maxelem")
eq(len([ln for ln in lines if not ln.startswith("#")]), 2 + 40_000,
   "...with one create, one flush and the 40,000 adds")
eq(create_line(ipset_lines(v4=v4_nets(10)), "v4"), DEFAULT_CREATE,
   "10 entries: no maxelem")
eq(create_line(ipset_lines(v4=v4_nets(50_000)), "v4"), LARGE_CREATE,
   "50,000 entries: maxelem 1048576")
for count, want in ((1, DEFAULT_CREATE), (49_152, DEFAULT_CREATE),
                    (49_153, LARGE_CREATE), (65_536, LARGE_CREATE),
                    (200_000, LARGE_CREATE)):
    eq(create_line(ipset_lines(v4=v4_nets(count)), "v4"), want,
       f"{count} entries: " + ("maxelem 1048576" if want == LARGE_CREATE
                               else "no maxelem"))
v6 = [ipaddress.IPv6Network(((0x20010DB8 << 96) | (i << 64), 64))
      for i in range(10)]
lines = ipset_lines(v4=v4_nets(50_000), v6=v6)
eq(create_line(lines, "v4"), LARGE_CREATE,
   "each family is judged on its own entries: v4 over the limit")
eq(create_line(lines, "v6"), "create t-v6 hash:net family inet6 -exist",
   "each family is judged on its own entries: v6 under it")
big6 = [ipaddress.IPv6Network(((0x20010DB8 << 96) | (i << 64), 64))
        for i in range(50_000)]
eq(create_line(ipset_lines(v6=big6), "v6"),
   "create t-v6 hash:net family inet6 maxelem 1048576 -exist",
   "IPv6 over the limit: maxelem 1048576")
ok(not any(ln.startswith("create t-v6") for ln in ipset_lines(v4=v4_nets(1))),
   "an empty family gets no create line")

# ------------------------------------------- geosite.dat size for the report

with tempfile.TemporaryDirectory() as tmp:
    c = BuildContext(outdir=tmp, timestamp="2026-10-23 00:00:00 UTC",
                     version="v1")
    size, _ = quiet(build.build_dat_files, c, ips, doms)
    eq(size, os.path.getsize(os.path.join(tmp, "xray", "geosite.dat")),
       "build_dat_files returns the byte size of xray/geosite.dat")
    ok(size > 0, "...and it is not empty")

done()
