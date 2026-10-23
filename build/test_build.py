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
import sources  # noqa: E402
from emitters import BuildContext  # noqa: E402


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
        "44244 104.16.5.0/24",      # added by BGP, but inside Cloudflare
        "13335 104.16.0.0/13",      # Cloudflare's own announcement
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
                  "removed_addresses": 256},
   "audit.bgp shape and IPv4 counts")
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
               "removed_addresses": 0}
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


def fake_get(result):
    def get(url, headers, timeout=fetch.TIMEOUT):
        calls.append((url, headers, timeout))
        if isinstance(result, BaseException):
            raise result
        return result
    return get


try:
    fetch.http_get = fake_get(fetch.FetchError(0, "no route"))
    eq(build.previous_stats("https://invalid.example/stats.json"), None,
       "previous_stats: a failing URL gives None")
    eq(calls[-1], ("https://invalid.example/stats.json",
                   {"User-Agent": fetch.USER_AGENT}, 60),
       "previous_stats: URL, User-Agent and 60 s timeout")
    fetch.http_get = fake_get(fetch.FetchError(404, "Not Found"))
    eq(build.previous_stats(), None, "previous_stats: no release yet gives None")
    fetch.http_get = fake_get(RuntimeError("anything"))
    eq(build.previous_stats(), None, "previous_stats: any exception gives None")
    eq(calls[-1][0], build.PREVIOUS_STATS_URL, "previous_stats: default URL")
    fetch.http_get = fake_get(fetch.Response(503, {}, b"{}"))
    eq(build.previous_stats(), None, "previous_stats: a non-200 response gives None")
    fetch.http_get = fake_get(fetch.Response(304, {}, b""))
    eq(build.previous_stats(), None, "previous_stats: a 304 gives None")
    fetch.http_get = fake_get(fetch.Response(200, {}, b"<html>not json"))
    eq(build.previous_stats(), None, "previous_stats: a non-JSON body gives None")
    fetch.http_get = fake_get(fetch.Response(200, {}, b"[1, 2]"))
    eq(build.previous_stats(), None, "previous_stats: JSON that is not an object")
    fetch.http_get = fake_get(fetch.Response(
        200, {}, json.dumps({"version": "v1", "audit": {}}).encode()))
    eq(build.previous_stats(), {"version": "v1", "audit": {}},
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

done()
