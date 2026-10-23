#!/usr/bin/env python3
"""Fetch every source, normalise it, and emit every output format.

    python3 build/build.py --outdir dist --version v2026.08.03
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from bisect import bisect_right
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import bgp  # noqa: E402
import emitters  # noqa: E402
import fetch  # noqa: E402
import geodat  # noqa: E402
import sources  # noqa: E402
from emitters import BuildContext  # noqa: E402
from model import (DomainSet, IPSet, exclude_networks,  # noqa: E402
                   make_domainset, make_ipset, parse_networks, psl_filter,
                   public_suffixes, subtract_allowlist)

PRIVATE_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128",
]

IP_ROLES = {
    "ir": ("Iran — IP ranges delegated to Iranian organisations", "direct"),
    "ir-cdn": ("Iranian CDN and hosting provider ranges", "direct"),
    "ir-full": ("Iran — registry ranges plus Iranian CDN ranges", "direct"),
    "private": ("RFC-reserved and private address space", "plain"),
    # Same slugs as the domain sets: geoip: and geosite: are separate
    # namespaces in Xray, and no output filename collides.
    "malware": ("Botnet command-and-control IP addresses", "block"),
    "phishing": ("IP addresses hosting active phishing", "block"),
}

DOMAIN_ROLES = {
    "ir": ("Iranian domains", "direct"),
    "ads": ("Advertising and tracking domains", "block"),
    "ads-ir": ("Persian advertising and tracking domains", "block"),
    "malware": ("Active malware domains", "block"),
    "phishing": ("Phishing and scam domains", "block"),
    "cryptominers": ("Browser cryptomining domains", "block"),
    "nsfw": ("Adult and gambling domains", "block"),
    "block-all": ("Combined blocklist — ads, malware, phishing, miners", "block"),
}

# The two Iranian ccTLDs, .ir and .ایران, each published as one suffix rule.
IR_TLDS = ("ir", "xn--mgba3a4f16a")

# Private-section PSL suffixes run by an Iranian operator, kept in `ir`
# although the PSL filter drops every other shared-hosting suffix: a suffix
# rule for one routes all of its customers' sites, which is right only when
# the platform itself is Iranian. Seeded on 2026-10-23 from the `ir` names
# that are PSL private rules after the .ir/.ایران collapse. The other five
# are not Iranian: dyndns.org, selfip.com and sells-it.net (DynDNS.com),
# ddnsguru.com (Dynu) and co.com (co.com Registry, CentralNic). A suffix
# under .ir or .ایران, such as vistablog.ir, needs no entry: the TLD rule
# already covers it.
IR_PLATFORM_SUFFIXES = frozenset({
    # Liara, an Iranian PaaS that serves apps as <app>.liara.run. The PSL
    # entry reads "Liara : https://liara.ir", submitted from info@liara.ir.
    "liara.run",
})

# Credits on each set: plain names a reader can follow. They are fixed, not
# derived from what was harvested, because the day-over-day guard skips a set
# whose credits changed, and a dropped source must not switch the guard off.
RIR_CREDIT = ("RIR delegated statistics (RIPE NCC, APNIC, ARIN, LACNIC, "
              "AFRINIC)")
RIS_CREDIT = "RIPE NCC RIS routing data"

# The last published release's stats.json, what the day-over-day guard
# compares a build against. GitHub redirects it to the asset.
PREVIOUS_STATS_URL = ("https://github.com/Arman2122/IR-Geo-DB/releases/latest/"
                      "download/stats.json")

# The most a set may lose against the previous release, in whole percent. A
# drop of exactly the limit passes; only a larger one refuses the publish.
IR_IPV4_SHRINK_PCT = 5
IR_DOMAIN_SHRINK_PCT = 10
BLOCKLIST_SHRINK_PCT = 60
BLOCKLIST_SETS = ("ads", "ads-ir", "malware", "phishing", "cryptominers",
                  "nsfw", "block-all")


def log(msg: str = "") -> None:
    print(msg, flush=True)


def _collapse(nets) -> list:
    """Collapsed and sorted, IPv4 first; the families may be mixed."""
    nets = list(nets)
    return [n for v in (4, 6) for n in sorted(ipaddress.collapse_addresses(
        [x for x in nets if x.version == v]))]


def _addresses(nets) -> int:
    """IPv4 addresses in a collapsed list (IPv6 networks are ignored)."""
    return sum(n.num_addresses for n in nets if n.version == 4)


def _subtract(base: list, drop: list) -> tuple[list, int]:
    """exclude_networks, with the base networks that touch nothing set aside.

    exclude_networks tests every base network against every drop network:
    the ~32,000 threat IPs against ~2,500 cloud ranges took half a minute.
    A bisect over the collapsed drop list finds the few base networks that
    touch one, and only those go through it. Returns the collapsed remainder
    and the number of addresses removed.
    """
    drops = _collapse(drop)
    index = {v: ([int(n.network_address) for n in drops if n.version == v],
                 [int(n.broadcast_address) for n in drops if n.version == v])
             for v in (4, 6)}
    touching, clear = [], []
    for n in base:
        starts, ends = index[n.version]
        # drops are disjoint and sorted, so only the last one starting at or
        # before n's end can reach back into n
        i = bisect_right(starts, int(n.broadcast_address)) - 1
        if i >= 0 and ends[i] >= int(n.network_address):
            touching.append(n)
        else:
            clear.append(n)
    kept, removed = exclude_networks(touching, drops)
    return _collapse(clear + kept), removed


def _ris_routes(h: fetch.Harvest) -> list | None:
    """The RIS routes, parsed once for both `ir` and `ir-cdn`.

    None when there are none to use: then `ir` is registry-only and `ir-cdn`
    the published lists only, and the build carries on (spec §3).
    """
    v4, v6 = h.get("ris-v4"), h.get("ris-v6")
    if not v4 and not v6:
        log("  warn: no RIS data — ir is registry-only, ir-cdn is the "
            "published lists only")
        return None
    for key, values in (("ris-v4", v4), ("ris-v6", v6)):
        if not values:
            log(f"  warn: no {key} data — that family is not BGP-adjusted")
    try:
        return bgp.routes_from(v4 + v6)
    except ValueError as exc:
        # only a corrupted stored copy gets here: the parser validated it
        log(f"  warn: unreadable RIS data ({exc}) — ir is registry-only, "
            f"ir-cdn is the published lists only")
        return None


def _ris_generated(h: fetch.Harvest) -> str:
    """When the RIS dump was made: its Last-Modified, else when it was read."""
    out = h.outcomes.get("ris-v4")
    if out is None:
        return ""
    return out.last_modified or out.fetched_at


def _bgp_adjust(h: fetch.Harvest, reg_v4: list, reg_v6: list,
                ir_asns: set[int], routes: list | None,
                neutral_asns: set[int] = frozenset()
                ) -> tuple[list, list, dict]:
    """Registry IR → BGP add/remove → anomaly limits (spec §3).

    `neutral_asns` are the providers' own ASNs (bgp.adjust says how they
    count). Raises bgp.BGPAnomaly when the change is beyond the limits: a
    leak or a broken dump, which must fail the build rather than publish.
    """
    report = {"applied": False, "ir_asns": 0,
              "ris_generated": _ris_generated(h), "registry_addresses": 0,
              "added_prefixes": 0, "added_addresses": 0,
              "removed_prefixes": 0, "removed_addresses": 0,
              "excluded_prefixes": 0, "excluded_addresses": 0,
              "registry_addresses_v6": 0, "added_addresses_v6": 0,
              "removed_addresses_v6": 0}
    if routes is None:
        return reg_v4, reg_v6, report

    adj = bgp.adjust(reg_v4 + reg_v6, routes, ir_asns, neutral_asns)
    bgp.check_limits(adj)
    # IPv4 only, like the unsuffixed address counts, so each prefix count
    # pairs with its address count
    added4 = sum(1 for n in adj.added if n.version == 4)
    removed4 = sum(1 for n in adj.removed if n.version == 4)
    excluded4 = [n for n in adj.excluded if n.version == 4]
    report.update(applied=True, ir_asns=len(ir_asns),
                  registry_addresses=adj.registry_addresses,
                  added_prefixes=added4, added_addresses=adj.added_addresses,
                  removed_prefixes=removed4,
                  removed_addresses=adj.removed_addresses,
                  excluded_prefixes=len(excluded4),
                  excluded_addresses=adj.excluded_addresses,
                  registry_addresses_v6=adj.registry_addresses_v6,
                  added_addresses_v6=adj.added_addresses_v6,
                  removed_addresses_v6=adj.removed_addresses_v6)
    log(f"  BGP adjustment ({len(ir_asns)} IR ASNs, {len(routes)} RIS routes): "
        f"+{added4} IPv4 prefixes (+{adj.added_addresses} addresses), "
        f"-{removed4} (-{adj.removed_addresses} addresses) on "
        f"{adj.registry_addresses} registry IPv4 addresses; IPv6 "
        f"+{len(adj.added) - added4} / -{len(adj.removed) - removed4} prefixes")
    if adj.excluded:
        # few by design, and each one is worth a look
        log(f"  not added, under a foreign route: "
            f"{', '.join(map(str, adj.excluded))} "
            f"({adj.excluded_addresses} IPv4 addresses)")
    return ([n for n in adj.networks if n.version == 4],
            [n for n in adj.networks if n.version == 6], report)


def _provider_asns(h: fetch.Harvest) -> dict[str, set[int]]:
    """Each provider's ASNs: every one RIPE holds for its organisations."""
    out = {}
    for name, info in sources.PROVIDERS.items():
        out[name] = set()
        for org in info["orgs"]:
            out[name] |= bgp.asns_from(h.get(f"ripe-org-{org.lower()}"))
    return out


def _provider_networks(h: fetch.Harvest, routes: list | None,
                       private: list, provider_asns: dict[str, set[int]]
                       ) -> tuple[IPSet, dict]:
    """`ir-cdn`: every provider's published lists plus what its ASNs announce.

    The ASNs are the ones RIPE holds for each provider organisation. Bogons
    are removed (Derak publishes a 192.168.x range); foreign clouds are not,
    because ParsPack's real edges sit on Vultr (spec §4). Kept out of `ir`:
    the published lists include edge nodes that are not in Iran.
    """
    report, everything, bad = {}, [], 0
    for name, info in sources.PROVIDERS.items():
        asns = provider_asns[name]
        announced = bgp.announced_by(routes, asns) if routes and asns else []
        list4, list6, n_bad = parse_networks(
            [v for key in info["lists"] for v in h.get(key)])
        bad += n_bad
        # every count is after collapse and bogon removal (Ruling R2)
        networks, _ = _subtract(announced, private)
        listed, _ = _subtract(list4 + list6, private)
        own = _collapse(networks + listed)
        everything += own
        report[name] = {"asns": sorted(asns),
                        "network_addresses": _addresses(networks),
                        "list_addresses": _addresses(listed),
                        "addresses": _addresses(own)}
        log(f"  {name:<12} {len(asns)} ASNs: {_addresses(networks)} IPv4 "
            f"addresses announced, {_addresses(listed)} listed, "
            f"{_addresses(own)} in all")
    nets = _collapse(everything)
    cdn = IPSet(slug="ir-cdn", title=IP_ROLES["ir-cdn"][0],
                v4=[n for n in nets if n.version == 4],
                v6=[n for n in nets if n.version == 6],
                sources=list(sources.PROVIDERS) + [RIS_CREDIT], malformed=bad)
    return cdn, report


def build_ip_sets(h: fetch.Harvest, strict_exclude: bool) -> tuple[dict, dict]:
    audit: dict = {}

    # The RIR parser emits "AS<n>" tokens beside the prefixes: the ASNs feed
    # the BGP adjustment and must not reach parse_networks as malformed.
    registry_raw = h.any_of("rir-")
    prefixes = [v for v in registry_raw if not v.startswith("AS")]
    ir_asns = bgp.asns_from(registry_raw)
    reg_v4, reg_v6, reg_bad = parse_networks(prefixes)
    log(f"  registry IR: {len(reg_v4)} IPv4 + {len(reg_v6)} IPv6 prefixes, "
        f"{len(ir_asns)} ASNs ({len(prefixes)} raw prefix records, "
        f"{reg_bad} malformed)")

    routes = _ris_routes(h)
    # The providers' ASNs, the same ones `ir-cdn` is built from. Those
    # registered abroad would otherwise count as foreign and remove the
    # provider's own Iranian space from `ir` (bgp.adjust).
    provider_asns = _provider_asns(h)
    ir_v4, ir_v6, audit["bgp"] = _bgp_adjust(
        h, reg_v4, reg_v6, ir_asns, routes,
        set().union(*provider_asns.values()))

    cloud_v4, cloud_v6, _ = parse_networks(h.any_of("cloud-"))
    cloud = cloud_v4 + cloud_v6

    clean_v4, dropped4 = exclude_networks(ir_v4, cloud)
    clean_v6, dropped6 = exclude_networks(ir_v6, cloud)
    audit["foreign_cloud_overlap_addresses"] = dropped4 + dropped6
    audit["foreign_cloud_prefixes_known"] = len(cloud)
    audit["foreign_cloud_excluded"] = bool(strict_exclude)

    if strict_exclude:
        ir_v4, ir_v6 = clean_v4, clean_v6
        log(f"  foreign-cloud exclusion: {dropped4 + dropped6} addresses removed")
    else:
        log(f"  foreign-cloud overlap (reported, not removed): "
            f"{dropped4 + dropped6} addresses")

    ir = IPSet(slug="ir", title=IP_ROLES["ir"][0], v4=_collapse(ir_v4),
               v6=_collapse(ir_v6), sources=[RIR_CREDIT, RIS_CREDIT],
               malformed=reg_bad)

    private_nets = [ipaddress.ip_network(p) for p in PRIVATE_RANGES]
    cdn, audit["providers"] = _provider_networks(h, routes, private_nets,
                                                 provider_asns)

    full = make_ipset("ir-full", IP_ROLES["ir-full"][0],
                      [str(n) for n in ir.all_networks() + cdn.all_networks()],
                      list(dict.fromkeys(ir.sources + cdn.sources)))

    private = make_ipset("private", IP_ROLES["private"][0], PRIVATE_RANGES,
                         ["RFC 1918 / 5735 / 6598 / 4193"])

    # Safety subtraction (spec §6.3): a threat feed that lists a bogon, a
    # cloud range or an Iranian provider's edge would block far more than
    # one bad host.
    t4, t6, t_bad = parse_networks(h.get("threat-ip-malware") +
                                   h.get("threat-ip-hagezi"))
    guard = private_nets + cloud + cdn.all_networks()
    t4, removed4 = _subtract(t4, guard)
    t6, _ = _subtract(t6, guard)
    audit["threat_ip_removed"] = removed4
    log(f"  threat IPs: {len(t4)} IPv4 + {len(t6)} IPv6 after removing "
        f"{removed4} IPv4 addresses (bogons, clouds, ir-cdn)")
    malware_ip = IPSet(slug="malware", title=IP_ROLES["malware"][0], v4=t4,
                       v6=t6, malformed=t_bad,
                       sources=["Feodo Tracker / abuse.ch (CC0)",
                                "HaGeZi Threat Intelligence Feeds (GPL-3.0)"])
    # no vetted phishing IP feed yet; kept so geoip:phishing still resolves
    phishing_ip = make_ipset("phishing", IP_ROLES["phishing"][0], [], [])

    for label, key in (("ipverse", "xc-ipverse-"), ("ipdeny", "xc-ipdeny-")):
        other_raw = h.any_of(key)
        if not other_raw:
            continue
        o4, o6, _ = parse_networks(other_raw)
        ours, theirs = set(map(str, ir.v4)), set(map(str, o4))
        audit[f"crosscheck_{label}"] = {
            "their_ipv4_prefixes": len(o4), "their_ipv6_prefixes": len(o6),
            "exact_prefix_matches": len(ours & theirs),
            "only_ours": len(ours - theirs), "only_theirs": len(theirs - ours),
            "address_coverage_ratio": round(
                sum(n.num_addresses for n in o4) /
                max(1, sum(n.num_addresses for n in ir.v4)), 4),
        }
        log(f"  cross-check {label}: {len(ours & theirs)} identical prefixes, "
            f"coverage ratio {audit[f'crosscheck_{label}']['address_coverage_ratio']}")

    audit["ir_ipv4_addresses"] = sum(n.num_addresses for n in ir.v4)
    audit["ir_ipv4_prefixes"] = len(ir.v4)
    audit["ir_ipv6_prefixes"] = len(ir.v6)

    return ({"ir": ir, "ir-cdn": cdn, "ir-full": full, "private": private,
             "malware": malware_ip, "phishing": phishing_ip}, audit)


def _ir_domains(h: fetch.Harvest, psl_rules: list[str]
                ) -> tuple[DomainSet, int | None]:
    """`ir`: bootmortis ∪ v2fly CATEGORY-IR, both ccTLDs, PSL-filtered.

    The PSL filter runs after the ccTLD collapse, so a name under .ir is not
    counted (the `ir` rule covers it either way), and before pruning, which
    would otherwise drop foo.dyndns.org as covered by dyndns.org just before
    the filter removes dyndns.org. Hence two passes: collapse without
    pruning, filter the suffixes, then build again with pruning. Exact-match
    names are left alone; the filter is about suffix rules.
    """
    title = DOMAIN_ROLES["ir"][0]
    credits = ["Iran Hosted Domains (MIT)", "v2fly domain-list-community (MIT)"]
    suffix, full = [], []
    for value in h.get("ir-domains") + h.get("ir-v2fly"):
        if value.startswith("full:"):
            full.append(value[len("full:"):])
        else:
            suffix.append(value)
    raw = make_domainset("ir", title, suffix=suffix, full=full,
                         sources=credits, collapse_tld=IR_TLDS, prune=False)
    if psl_rules:
        kept, removed = psl_filter(raw.suffix, psl_rules,
                                   keep=IR_PLATFORM_SUFFIXES)
    else:
        log("  warn: no Public Suffix List — ir is published without the "
            "PSL filter")
        kept, removed = raw.suffix, None
    ds = make_domainset("ir", title, suffix=kept, full=raw.full,
                        sources=credits, collapse_tld=IR_TLDS)
    ds.malformed = raw.malformed
    return ds, removed


def build_domain_sets(h: fetch.Harvest) -> tuple[dict[str, DomainSet], dict]:
    out: dict[str, DomainSet] = {}
    psl_rules = h.get("psl")

    out["ir"], psl_removed = _ir_domains(h, psl_rules)

    # AdGuard's own allowlists: names it found to break real sites when
    # blocked. An entry that is a single label or a public suffix is ignored
    # (spec §5); without the PSL only single labels are.
    allow = (set(h.get("allow-adguard-exclusions")) |
             set(h.get("allow-adguard-exceptions")))
    suffixes = public_suffixes(psl_rules)
    persian = (h.get("ads-persian-hosts") + h.get("ads-persian-ads") +
               h.get("ads-persian-trackers"))
    allow_removed = {}
    for slug, names, credits in (
            ("ads-ir", persian, ["PersianBlocker (AGPL-3.0)"]),
            ("ads", persian + h.get("ads-hagezi"),
             ["PersianBlocker (AGPL-3.0)", "HaGeZi Multi LIGHT (GPL-3.0)"])):
        kept, allow_removed[slug] = subtract_allowlist(set(names), allow,
                                                       suffixes)
        out[slug] = make_domainset(slug, DOMAIN_ROLES[slug][0], suffix=kept,
                                   sources=credits)
    daudit = {"psl_removed": psl_removed,
              "allowlist_removed": {"ads": allow_removed["ads"],
                                    "ads-ir": allow_removed["ads-ir"]}}
    if psl_removed is not None:
        log(f"  PSL filter: {psl_removed} shared-hosting suffixes removed "
            f"from ir")
    log(f"  AdGuard allowlist: {allow_removed['ads']} names removed from ads, "
        f"{allow_removed['ads-ir']} from ads-ir")

    out["malware"] = make_domainset(
        "malware", DOMAIN_ROLES["malware"][0],
        suffix=h.get("malware-hagezi-tif"),
        sources=["HaGeZi Threat Intelligence Feeds mini (GPL-3.0)"])

    out["phishing"] = make_domainset(
        "phishing", DOMAIN_ROLES["phishing"][0], suffix=h.get("phishing-certpl"),
        sources=["CERT Polska warning list"])

    out["cryptominers"] = make_domainset(
        "cryptominers", DOMAIN_ROLES["cryptominers"][0],
        suffix=h.get("crypto-nocoin"), sources=["NoCoin adblock list (MIT)"])

    out["nsfw"] = make_domainset(
        "nsfw", DOMAIN_ROLES["nsfw"][0],
        suffix=h.get("nsfw-stevenblack") + h.get("nsfw-stevenblack-gambling"),
        sources=["StevenBlack unified hosts (MIT)"])

    combined, combined_sources = [], []
    for key in ("ads", "malware", "phishing", "cryptominers"):
        combined += out[key].plain_domains()
        combined_sources += out[key].sources
    out["block-all"] = make_domainset(
        "block-all", DOMAIN_ROLES["block-all"][0], suffix=combined,
        sources=sorted(set(combined_sources)))

    for slug, ds in out.items():
        log(f"  {slug:<14} suffix={len(ds.suffix):<7} full={len(ds.full):<5} "
            f"keyword={len(ds.keyword):<4} regex={len(ds.regex):<4} "
            f"pruned={ds.pruned}")
    return out, daudit


def build_dat_files(ctx: BuildContext, ips: dict, doms: dict) -> int:
    """Write the Xray .dat files; returns the byte size of geosite.dat.

    The size goes into the release notes: jsDelivr serves nothing over 20 MB.
    """
    geoip = {slug: s.all_networks() for slug, s in ips.items()}
    _write_bin(ctx, "xray/geoip.dat", geodat.encode_geoip(geoip),
               sum(len(v) for v in geoip.values()))

    lite_ip = {k: geoip[k] for k in ("ir", "private") if k in geoip}
    _write_bin(ctx, "xray/geoip-lite.dat", geodat.encode_geoip(lite_ip),
               sum(len(v) for v in lite_ip.values()))

    def as_domains(d: DomainSet):
        return ([(geodat.ROOT_DOMAIN, n) for n in sorted(d.suffix)] +
                [(geodat.FULL, n) for n in sorted(d.full)] +
                [(geodat.PLAIN, n) for n in sorted(d.keyword)] +
                [(geodat.REGEX, n) for n in sorted(d.regex)])

    # block-all is the union of four categories already present; including it
    # would roughly double the file for no new information.
    geosite = {slug: as_domains(d) for slug, d in doms.items()
               if slug != "block-all"}
    geosite["category-ads-all"] = geosite["ads"]
    geosite_blob = geodat.encode_geosite(geosite)
    _write_bin(ctx, "xray/geosite.dat", geosite_blob,
               sum(len(v) for v in geosite.values()))

    lite_site = {k: geosite[k] for k in ("ir", "ads-ir") if k in geosite}
    _write_bin(ctx, "xray/geosite-lite.dat", geodat.encode_geosite(lite_site),
               sum(len(v) for v in lite_site.values()))

    sec_site = {k: geosite[k] for k in
                ("ads", "malware", "phishing", "cryptominers") if k in geosite}
    _write_bin(ctx, "xray/geosite-security.dat", geodat.encode_geosite(sec_site),
               sum(len(v) for v in sec_site.values()))

    check = {c.code: c.domains for c in geodat.decode_geosite(
        open(ctx.path("xray/geosite.dat"), "rb").read())}
    assert check["IR"] == geosite["ir"], "geosite.dat failed round-trip"
    check_ip = {c.code: c.networks for c in geodat.decode_geoip(
        open(ctx.path("xray/geoip.dat"), "rb").read())}
    assert check_ip["IR"] == geoip["ir"], "geoip.dat failed round-trip"
    log("  xray .dat round-trip verified")
    return len(geosite_blob)


def _write_bin(ctx: BuildContext, relpath: str, blob: bytes, entries: int) -> None:
    with open(ctx.path(relpath), "wb") as fh:
        fh.write(blob)
    ctx.record(relpath, entries)
    log(f"  wrote {relpath:<28} {len(blob) / 1024:>8.0f} KiB  {entries} entries")


def _tool(env_var: str, name: str) -> str | None:
    return os.environ.get(env_var) or shutil.which(name)


def compile_singbox(ctx: BuildContext, require: bool) -> int:
    exe = _tool("SING_BOX", "sing-box")
    srcdir = os.path.join(ctx.outdir, "sing-box", "source")
    if not exe:
        msg = "sing-box not found — .srs rule-sets skipped"
        if require:
            sys.exit(f"ERROR: {msg}")
        log(f"  warn: {msg}")
        return 0
    made = 0
    for name in sorted(os.listdir(srcdir)):
        if not name.endswith(".json"):
            continue
        dst = ctx.path(f"sing-box/rule-set/{name[:-5]}.srs")
        res = subprocess.run(
            [exe, "rule-set", "compile", "--output", dst,
             os.path.join(srcdir, name)], capture_output=True, text=True)
        if res.returncode != 0:
            with open(os.path.join(srcdir, name), encoding="utf-8") as fh:
                rules = json.load(fh).get("rules", [])
            if any(v for r in rules for v in r.values() if isinstance(v, list)):
                sys.exit(f"ERROR: sing-box compile failed for {name}: {res.stderr}")
            # an empty set has nothing to lose, and must not cost the release
            log(f"  warn: sing-box rejected empty {name}, no .srs this build")
            if os.path.exists(dst):
                os.remove(dst)
            continue
        ctx.record(f"sing-box/rule-set/{name[:-5]}.srs", 0)
        made += 1
    log(f"  compiled {made} sing-box .srs rule-sets")
    return made


def compile_mihomo(ctx: BuildContext, require: bool) -> int:
    exe = _tool("MIHOMO", "mihomo")
    if not exe:
        msg = "mihomo not found — .mrs rule-sets skipped"
        if require:
            sys.exit(f"ERROR: {msg}")
        log(f"  warn: {msg}")
        return 0
    made = 0
    clashdir = os.path.join(ctx.outdir, "clash")
    for name in sorted(os.listdir(clashdir)):
        if not name.endswith(".list"):
            continue
        src = os.path.join(clashdir, name)
        # mihomo panics with "empty rule" on a list with no entries, which
        # threat feeds such as Feodo Tracker legitimately produce some days
        with open(src, encoding="utf-8") as fh:
            if not any(ln.strip() and not ln.startswith("#") for ln in fh):
                log(f"  skip {name}: no entries, no .mrs this build")
                continue
        # only domain and ipcidr behaviours have an .mrs representation
        behavior = "ipcidr" if name.endswith("-ip.list") else "domain"
        dst = ctx.path(f"mihomo/{name[:-5]}.mrs")
        res = subprocess.run(
            [exe, "convert-ruleset", behavior, "text", src, dst],
            capture_output=True, text=True)
        if res.returncode != 0:
            log(f"  warn: mihomo failed on {name}: "
                f"{(res.stderr or res.stdout).strip()[:200]}")
            # a crashed convert can leave a partial file, and an empty
            # release asset fails the whole upload
            if os.path.exists(dst):
                os.remove(dst)
            continue
        ctx.record(f"mihomo/{name[:-5]}.mrs", 0)
        made += 1
    log(f"  compiled {made} mihomo .mrs rule-sets")
    return made


def write_configs(ctx: BuildContext, base_url: str) -> None:
    xray = {
        "_comment": "Xray / v2ray routing block. Place geoip.dat and "
                    "geosite.dat next to the core binary or in its asset dir.",
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {"type": "field", "outboundTag": "block",
             "domain": ["geosite:ads", "geosite:malware", "geosite:phishing",
                        "geosite:cryptominers"]},
            {"type": "field", "outboundTag": "block",
             "ip": ["geoip:malware", "geoip:phishing"]},
            {"type": "field", "outboundTag": "direct", "domain": ["geosite:ir"]},
            {"type": "field", "outboundTag": "direct",
             "ip": ["geoip:ir", "geoip:private"]},
        ],
    }
    emitters.write_json(ctx, "xray/routing-rules.json", xray, 4)

    singbox = {
        "route": {
            "rules": [
                {"rule_set": ["geosite-ads", "geosite-malware",
                              "geosite-phishing"], "action": "reject"},
                {"rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct"},
            ],
            "rule_set": [
                {"type": "remote", "tag": tag, "format": "binary",
                 "url": f"{base_url}/sing-box/rule-set/{tag}.srs",
                 "download_detour": "direct", "update_interval": "1d"}
                for tag in ("geosite-ir", "geoip-ir", "geosite-ads",
                            "geosite-malware", "geosite-phishing")
            ],
        },
    }
    emitters.write_json(ctx, "sing-box/config-snippet.json", singbox, 5)

    clash_yaml = ["rule-providers:"]
    for tag, behavior in (("ir-domain", "domain"), ("ir-ip", "ipcidr"),
                          ("ads-domain", "domain"), ("malware-domain", "domain"),
                          ("phishing-domain", "domain")):
        clash_yaml += [
            f"  {tag}:", "    type: http", f"    behavior: {behavior}",
            "    format: mrs", "    interval: 86400",
            f"    url: {base_url}/mihomo/{tag}.mrs",
            f"    path: ./ruleset/{tag}.mrs",
        ]
    clash_yaml += [
        "", "rules:",
        "  - RULE-SET,ads-domain,REJECT",
        "  - RULE-SET,malware-domain,REJECT",
        "  - RULE-SET,phishing-domain,REJECT",
        "  - RULE-SET,ir-domain,DIRECT",
        "  - RULE-SET,ir-ip,DIRECT,no-resolve",
        "  - MATCH,PROXY",
    ]
    emitters.write_lines(ctx, "clash/config-snippet.yaml", clash_yaml,
                         "Mihomo / Clash.Meta configuration snippet", 5, [])

    # The scheduler's policy must cover the script's, or RouterOS refuses to
    # run it ("not enough permissions"), so both carry the same list.
    policy = "ftp,read,write,test,policy"
    mikrotik = [
        # pasting the installer again replaces it instead of failing on
        # "already have script with such name"
        "/system scheduler remove [find name=IR-Geo-Schedule]",
        "/system script remove [find name=IR-Geo-Update]",
        "/system script",
        f"add name=IR-Geo-Update policy={policy} source={{",
        f':local url "{base_url}/mikrotik/ir-ipv4-reset.rsc"',
        ':do { /file remove [find name="ir-geo.rsc"] } on-error={}',
        ':do { /tool fetch url=$url mode=https dst-path="ir-geo.rsc" } on-error={',
        '  :log error "IR-Geo: fetch failed, address list left untouched"',
        '  :error "fetch failed" }',
        ":delay 5s",
        ':if ([:len [/file find name="ir-geo.rsc"]] = 0) do={ :error "no file" }',
        # a truncated download would otherwise wipe the list on import
        ':if ([/file get [find name="ir-geo.rsc"] size] < 20000) do={',
        '  :log warning "IR-Geo: file too small, refusing to import"',
        '  :error "short file" }',
        '/import file-name="ir-geo.rsc"',
        ':log info ("IR-Geo: " . [/ip firewall address-list print count-only '
        'where list=IR] . " prefixes loaded")',
        "}",
        "",
        "/system scheduler",
        "add name=IR-Geo-Schedule interval=1d start-time=04:00:00 \\",
        f"    on-event=IR-Geo-Update policy={policy}",
    ]
    emitters.write_lines(ctx, "mikrotik/auto-update.rsc", mikrotik,
                         "RouterOS self-updating installer", 1, [])


def source_provenance(h: fetch.Harvest) -> dict:
    """Per source, in registry order: how it was acquired, and its terms."""
    order = {s.key: i for i, s in enumerate(sources.SOURCES)}
    out = {}
    for key in sorted(h.outcomes, key=lambda k: order.get(k, len(order))):
        src = sources.BY_KEY.get(key)
        out[key] = h.outcomes[key].report() | {
            "license": src.license if src else "",
            "homepage": src.homepage if src else "",
            "attribution": src.attribution if src else ""}
    return out


def write_metadata(ctx: BuildContext, ips: dict, doms: dict, h: fetch.Harvest,
                   audit: dict) -> dict:
    stats = {
        "version": ctx.version,
        "generated": ctx.timestamp,
        "ip_sets": {k: v.stats() for k, v in ips.items()},
        "domain_sets": {k: v.stats() for k, v in doms.items()},
        # kept for anything that read them before `sources` existed
        "sources_ok": sorted(h.values),
        "sources_failed": h.failed,
        "sources": source_provenance(h),
        "audit": audit,
    }
    emitters.write_json(ctx, "stats.json", stats, 0)
    emitters.write_json(ctx, "manifest.json", {
        "version": ctx.version, "generated": ctx.timestamp,
        "files": sorted(ctx.manifest, key=lambda r: r["file"]),
    }, len(ctx.manifest))

    lines = []
    for root, _dirs, files in os.walk(ctx.outdir):
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, ctx.outdir).replace(os.sep, "/")
            if rel == "SHA256SUMS":
                continue
            lines.append(f"{hashlib.sha256(open(full, 'rb').read()).hexdigest()}  {rel}")
    with open(os.path.join(ctx.outdir, "SHA256SUMS"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(sorted(lines)) + "\n")
    return stats


# Release assets are loose files, not archives: v2ray, sing-box, mihomo and
# RouterOS all fetch a single file by URL and cannot open a zip. Names are
# flattened, so anything ambiguous once the directory is gone gets a prefix.
RELEASE_ASSETS: list[tuple[str, str, str]] = [
    # Extensions that already identify their tool keep their canonical name,
    # because that is the filename clients expect to fetch.
    ("xray", "*.dat", ""),
    ("xray", "routing-rules.json", "xray-"),
    ("sing-box/rule-set", "*.srs", ""),
    ("sing-box", "config-snippet.json", "singbox-"),
    ("mihomo", "*.mrs", ""),
    ("mikrotik", "*.rsc", ""),
    ("mikrotik", "adlist-*.txt", ""),
    ("ipset", "*.ipset", ""),
    ("nftables", "*.nft", ""),
    ("rpz", "*.zone", ""),
    ("text", "*.txt", ""),
    # Shared extensions need a prefix once the directory is gone.
    ("hosts", "*.txt", "hosts-"),
    ("adguard", "*.txt", "adguard-"),
    ("clash", "*.yaml", "clash-"),
    ("clash", "*.list", "clash-"),
    ("surge", "*.list", "surge-"),
    ("surge", "*.txt", "surge-"),
    ("quantumultx", "*.list", "quantumultx-"),
    ("dnsmasq", "*.conf", "dnsmasq-"),
    ("unbound", "*.conf", "unbound-"),
    ("smartdns", "*.conf", "smartdns-"),
    ("wireguard", "*.conf", "wireguard-"),
    # sing-box JSON sources and the json/ dumps are omitted: they restate the
    # compiled .srs and the text lists. Both remain on the dist branch.
]


def stage_release(ctx: BuildContext, outdir_parent: str) -> str:
    """Flatten the directly-consumable files into one directory for upload."""
    import fnmatch

    staging = os.path.join(outdir_parent, "release-assets")
    if os.path.isdir(staging):
        shutil.rmtree(staging)
    os.makedirs(staging)

    seen: dict[str, str] = {}
    for subdir, pattern, prefix in RELEASE_ASSETS:
        src_dir = os.path.join(ctx.outdir, subdir)
        if not os.path.isdir(src_dir):
            continue
        for name in sorted(os.listdir(src_dir)):
            if not fnmatch.fnmatch(name, pattern):
                continue
            # GitHub rejects a zero-byte asset with "Bad Content-Length" and
            # fails the release; verify.py already refuses to pass one
            if os.path.getsize(os.path.join(src_dir, name)) == 0:
                log(f"  skip {subdir}/{name}: empty file not uploaded")
                continue
            flat = prefix + name
            if flat in seen:
                raise SystemExit(
                    f"release asset name collision: {flat} from "
                    f"{subdir} and {seen[flat]}")
            seen[flat] = subdir
            shutil.copy2(os.path.join(src_dir, name),
                         os.path.join(staging, flat))

    for meta in ("SHA256SUMS", "stats.json", "manifest.json"):
        path = os.path.join(ctx.outdir, meta)
        if os.path.exists(path):
            shutil.copy2(path, os.path.join(staging, meta))

    # checksums for the flattened names, so `sha256sum -c` works on downloads
    sums = []
    for name in sorted(os.listdir(staging)):
        if name == "SHA256SUMS":
            continue
        digest = hashlib.sha256(open(os.path.join(staging, name), "rb").read())
        sums.append(f"{digest.hexdigest()}  {name}")
    with open(os.path.join(staging, "SHA256SUMS"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(sums) + "\n")

    total = sum(os.path.getsize(os.path.join(staging, f))
                for f in os.listdir(staging))
    log(f"  staged {len(os.listdir(staging))} release assets "
        f"({total / 1024 / 1024:.0f} MiB)")
    return staging


def package(ctx: BuildContext, outdir_parent: str) -> str:
    """One archive of the full tree, for mirroring and offline use."""
    path = os.path.join(outdir_parent, f"ir-geo-db-{ctx.version}.zip")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, _dirs, files in os.walk(ctx.outdir):
            for name in sorted(files):
                fp = os.path.join(root, name)
                zf.write(fp, os.path.relpath(fp, ctx.outdir))
    log(f"  packaged {os.path.basename(path)} "
        f"{os.path.getsize(path) / 1024 / 1024:.0f} MiB")
    return path


def sanity_check(ips: dict, doms: dict) -> None:
    """Refuse to publish an obviously broken build."""
    problems = []
    if len(ips["ir"].v4) < 1000:
        problems.append(f"ir IPv4 prefixes = {len(ips['ir'].v4)}, expected >1000")
    if len(ips["ir"].v6) < 100:
        problems.append(f"ir IPv6 prefixes = {len(ips['ir'].v6)}, expected >100")
    if doms["ir"].total < 1000:
        problems.append(f"ir domains = {doms['ir'].total}, expected >1000")
    if doms["ads"].total < 1000:
        problems.append(f"ads domains = {doms['ads'].total}, expected >1000")

    ir_nets = ips["ir"].v4
    must_have = ipaddress.ip_network("2.144.0.0/14")
    if not any(must_have.subnet_of(n) or n.subnet_of(must_have) for n in ir_nets):
        problems.append("2.144.0.0/14 (TCI) missing from the Iranian set")
    if any(ipaddress.ip_address("8.8.8.8") in n for n in ir_nets):
        problems.append("8.8.8.8 is inside the Iranian set — source contamination")

    if problems:
        for p in problems:
            log(f"  FAIL {p}")
        sys.exit("sanity check failed — refusing to publish")
    log("  sanity checks passed")


def previous_stats(url: str = PREVIOUS_STATS_URL,
                   sleep=time.sleep) -> dict | None:
    """The previous release's stats.json, or None when it cannot be had: no
    release yet, GitHub down, a non-200 answer, or a body that is not an object.

    A None switches the day-over-day guard off, so one network blip must not
    cause it: the request goes through fetch's retrying getter, the same
    policy as every source (network errors and 5xx retried, a 404 not, since
    it means there is no release yet). Why the guard is skipped is logged.
    """
    def get(u: str, headers: dict) -> fetch.Response:
        # looked up at call time, so the tests can stand in for it
        return fetch.http_get(u, headers, timeout=60)

    def skip(why: str) -> None:
        log(f"  previous release stats.json: {why}")

    try:
        resp = fetch._get(url, {"User-Agent": fetch.USER_AGENT}, get, sleep)
    except fetch.FetchError as exc:
        skip("no release yet (HTTP 404)" if exc.status == 404 else str(exc))
        return None
    except Exception as exc:   # any failure skips the guard; never the build
        skip(f"{type(exc).__name__}: {exc}")
        return None
    if resp.status != 200:
        skip(f"HTTP {resp.status}")
        return None
    try:
        data = json.loads(resp.body)
    except Exception as exc:       # JSONDecodeError, UnicodeDecodeError, ...
        skip(f"not JSON ({type(exc).__name__})")
        return None
    if not isinstance(data, dict):
        skip(f"not a JSON object ({type(data).__name__})")
        return None
    return data


def _dig(stats, *path):
    """stats[path[0]][path[1]]..., or None as soon as a step is missing."""
    for key in path:
        if not isinstance(stats, dict):
            return None
        stats = stats.get(key)
    return stats


def _count(value) -> int | None:
    numeric = isinstance(value, (int, float)) and not isinstance(value, bool)
    return int(value) if numeric else None


def _domain_count(stats, slug: str) -> int | None:
    parts = [_count(_dig(stats, "domain_sets", slug, k)) for k in ("suffix", "full")]
    return None if None in parts else sum(parts)


def shrink_problems(now: dict, prev: dict | None) -> list[str]:
    """Sets that lost more than their limit since the previous release.

    `now` and `prev` are stats.json dicts. A set is skipped, with a logged
    reason, when its `sources` differ from the previous release's: a source
    that came or went is meant to change the size. Anything the previous
    release does not record (an older schema), or a previous value of 0, skips
    that comparison. Growth never fails.
    """
    if not isinstance(now, dict) or not isinstance(prev, dict):
        return []
    checks = [("ir IPv4 addresses",
               lambda s: _count(_dig(s, "audit", "ir_ipv4_addresses")),
               ("ip_sets", "ir"), IR_IPV4_SHRINK_PCT),
              ("ir domains", lambda s: _domain_count(s, "ir"),
               ("domain_sets", "ir"), IR_DOMAIN_SHRINK_PCT)]
    for slug in BLOCKLIST_SETS:
        checks.append((slug, lambda s, slug=slug: _domain_count(s, slug),
                       ("domain_sets", slug), BLOCKLIST_SHRINK_PCT))

    problems = []
    for label, value, where, limit in checks:
        old, new = value(prev), value(now)
        if old is None or new is None or old <= 0:
            continue
        old_src, new_src = (_dig(s, *where, "sources") for s in (prev, now))
        if not isinstance(old_src, list) or not isinstance(new_src, list):
            log(f"  skip {label}: previous release lists no sources")
        elif sorted(map(str, old_src)) != sorted(map(str, new_src)):
            log(f"  skip {label}: sources changed")
        elif (old - new) * 100 > old * limit:     # integers: the limit is exact
            problems.append(f"{label}: {old:,} → {new:,} "
                            f"(−{(old - new) / old * 100:.1f}%, "
                            f"limit −{limit}%)")
    return problems


def enforce_shrink_limits(ips: dict, doms: dict, audit: dict,
                          prev: dict | None, allow_shrink: bool) -> None:
    """Refuse to publish when a set shrank past its day-over-day limit."""
    if prev is None:
        log("  previous release unavailable — guard skipped")
        return
    now = {"audit": audit,
           "ip_sets": {k: v.stats() for k, v in ips.items()},
           "domain_sets": {k: v.stats() for k, v in doms.items()}}
    problems = shrink_problems(now, prev)
    for p in problems:
        log(f"  {'warn' if allow_shrink else 'FAIL'} {p}")
    if problems and not allow_shrink:
        sys.exit("set shrank beyond its limit — refusing to publish")
    if not problems:
        log("  day-over-day guard passed")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outdir", default="dist")
    ap.add_argument("--version", default=None)
    ap.add_argument("--cache", default=None,
                    help="cache downloads here (local iteration only)")
    ap.add_argument("--lkg-dir", default=".lkg",
                    help="state store: the last validated copy of each source")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--resolver", default="178.22.122.100")
    ap.add_argument("--require-binaries", action="store_true")
    ap.add_argument("--strict-exclude", action="store_true", default=True)
    ap.add_argument("--no-strict-exclude", dest="strict_exclude",
                    action="store_false")
    ap.add_argument("--skip-package", action="store_true")
    ap.add_argument("--allow-shrink", action="store_true",
                    help="publish even if a set shrank past its day-over-day "
                         "limit, once a human has reviewed the change")
    args = ap.parse_args()
    # the guard's messages use → and −, which a Windows pipe (cp1252) cannot encode
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")

    now = datetime.now(timezone.utc)
    version = args.version or now.strftime("v%Y.%m.%d")
    base_url = args.base_url or (
        "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist")

    if os.path.isdir(args.outdir):
        shutil.rmtree(args.outdir)
    os.makedirs(args.outdir, exist_ok=True)

    ctx = BuildContext(outdir=args.outdir,
                       timestamp=now.strftime("%Y-%m-%d %H:%M:%S UTC"),
                       version=version, resolver=args.resolver)

    log(f"IR-Geo-DB {version}\n")
    log("[1/7] fetching sources")
    store = fetch.StateStore(args.lkg_dir)
    # The state branch republishes every input, so it carries their licences
    # and attributions. Written before the harvest: the workflow saves the
    # store after a failed build too.
    store.write_notice(sources.SOURCES)
    try:
        h = fetch.harvest(sources.SOURCES, store, cache_dir=args.cache, log=log)
    except fetch.SourceUnavailable as exc:
        sys.exit(f"ERROR: {exc}")

    log("\n[2/7] building IP datasets")
    try:
        ips, audit = build_ip_sets(h, args.strict_exclude)
    except bgp.BGPAnomaly as exc:
        # a leak or a broken dump: yesterday's release stays up
        sys.exit(f"ERROR: {exc}")

    log("\n[3/7] building domain datasets")
    doms, daudit = build_domain_sets(h)
    audit.update(daudit)

    log("\n[4/7] sanity checks")
    sanity_check(ips, doms)
    enforce_shrink_limits(ips, doms, audit, previous_stats(), args.allow_shrink)

    log("\n[5/7] emitting formats")
    for slug, s in ips.items():
        emitters.emit_ipset(ctx, s, IP_ROLES[slug][1])
    audit["format_profiles"] = {}
    for slug, d in doms.items():
        profile = "aggregate" if slug == "block-all" else "auto"
        used = emitters.emit_domainset(ctx, d, DOMAIN_ROLES[slug][1], profile)
        audit["format_profiles"][slug] = used
        if used != "full":
            log(f"  {slug}: '{used}' format profile ({d.total} entries)")
    audit["geosite_dat_bytes"] = build_dat_files(ctx, ips, doms)
    write_configs(ctx, base_url)
    log(f"  {len(ctx.manifest)} files written")

    log("\n[6/7] compiling binary rule-sets")
    compile_singbox(ctx, args.require_binaries)
    compile_mihomo(ctx, args.require_binaries)

    log("\n[7/7] metadata")
    stats = write_metadata(ctx, ips, doms, h, audit)
    if not args.skip_package:
        parent = os.path.dirname(os.path.abspath(args.outdir))
        stage_release(ctx, parent)
        package(ctx, parent)

    total = sum(len(fs) for _, _, fs in os.walk(args.outdir))
    log(f"\ndone: {total} files in {args.outdir}/")
    log(f"ir = {len(ips['ir'].v4)} IPv4 + {len(ips['ir'].v6)} IPv6 prefixes, "
        f"{stats['ip_sets']['ir']['ipv4']} v4 entries")


if __name__ == "__main__":
    main()
