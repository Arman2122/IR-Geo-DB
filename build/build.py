#!/usr/bin/env python3
"""
build.py — fetch every source, normalise it, and emit every output format.

    python3 build/build.py --outdir dist --version v2026.08.03

Runs end to end on a bare GitHub Actions runner: standard library only, no
network access beyond plain HTTPS GETs, no services, no state carried between
runs. ``sing-box`` and ``mihomo`` are used if present on PATH (or pointed at
by $SING_BOX / $MIHOMO) to compile the binary rule-set formats; without them
everything else is still produced and the build reports what it skipped.
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
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emitters  # noqa: E402
import geodat  # noqa: E402
import sources  # noqa: E402
from emitters import BuildContext  # noqa: E402
from model import DomainSet, IPSet, make_domainset, make_ipset, parse_networks  # noqa: E402

# RFC-reserved space. Static because it is defined by RFC, not published by
# anyone, and a build should not depend on a network fetch for a constant.
PRIVATE_RANGES = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "255.255.255.255/32",
    "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "::/128",
]

# slug -> (title, role). Role drives which emitters run; see emitters.py.
IP_ROLES = {
    "ir": ("Iran — IP ranges delegated to Iranian organisations", "direct"),
    "ir-cdn": ("Iranian CDN and hosting provider ranges", "direct"),
    "ir-full": ("Iran — registry ranges plus Iranian CDN ranges", "direct"),
    "private": ("RFC-reserved and private address space", "plain"),
    # Same slugs as the domain sets on purpose. geoip: and geosite: are
    # separate namespaces in Xray, so `geoip:malware` and `geosite:malware`
    # coexist, and that pairing is what published configs already expect.
    # No output file collides: IP sets emit -ipv4/-ip/geoip- names, domain
    # sets emit -domains/-domain/geosite- names.
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


def log(msg: str = "") -> None:
    print(msg, flush=True)


# --------------------------------------------------------------- IP datasets


def exclude_networks(base: list, drop: list) -> tuple[list, int]:
    """Remove every part of ``base`` that overlaps ``drop``.

    Returns the remaining networks and the number of *addresses* removed.
    Counting prefixes would be misleading: excluding a /24 from a /8 leaves
    more prefixes than it started with, so a prefix delta can be negative
    even though space was taken away.

    Two CIDRs either nest or are disjoint, so an overlap always means one
    contains the other — which is exactly the case ``address_exclude``
    handles.
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
                # else: piece sits entirely inside bad, so it is dropped
            pieces = nxt
        kept.extend(pieces)
    kept = sorted(ipaddress.collapse_addresses(kept)) if kept else []
    return kept, before - sum(n.num_addresses for n in kept)


def build_ip_sets(h: sources.Harvest, strict_exclude: bool) -> tuple[dict, dict]:
    """Assemble the IP datasets and the audit numbers that justify them."""
    audit: dict = {}

    # --- registry truth: every RIR record delegated to a country of IR
    registry_raw = h.any_of("rir-")
    reg_v4, reg_v6, reg_bad = parse_networks(registry_raw)
    log(f"  registry IR: {len(reg_v4)} IPv4 + {len(reg_v6)} IPv6 prefixes "
        f"({len(registry_raw)} raw records, {reg_bad} malformed)")

    # --- foreign cloud and CDN space, for subtraction and for the audit
    cloud_v4, cloud_v6, _ = parse_networks(h.any_of("cloud-"))
    cloud = cloud_v4 + cloud_v6

    clean_v4, dropped4 = exclude_networks(reg_v4, cloud)
    clean_v6, dropped6 = exclude_networks(reg_v6, cloud)
    audit["foreign_cloud_overlap_addresses"] = dropped4 + dropped6
    audit["foreign_cloud_prefixes_known"] = len(cloud)
    audit["foreign_cloud_excluded"] = bool(strict_exclude)

    if strict_exclude:
        reg_v4, reg_v6 = clean_v4, clean_v6
        log(f"  foreign-cloud exclusion: {dropped4 + dropped6} addresses removed")
    else:
        log(f"  foreign-cloud overlap (reported, not removed): "
            f"{dropped4 + dropped6} addresses")

    ir = IPSet(slug="ir", title=IP_ROLES["ir"][0], v4=reg_v4, v6=reg_v6,
               sources=["RIR delegated statistics (RIPE NCC, APNIC, ARIN, "
                        "LACNIC, AFRINIC)"], malformed=reg_bad)

    # --- Iranian CDN and hosting providers, kept separate on purpose: their
    # published ranges include edge nodes that are not physically in Iran.
    cdn_raw = h.get("arvancloud") + h.get("parspack")
    cdn = make_ipset("ir-cdn", IP_ROLES["ir-cdn"][0], cdn_raw,
                     ["ArvanCloud", "ParsPack"])

    full = make_ipset("ir-full", IP_ROLES["ir-full"][0],
                      [str(n) for n in ir.all_networks() + cdn.all_networks()],
                      ir.sources + cdn.sources)

    private = make_ipset("private", IP_ROLES["private"][0], PRIVATE_RANGES,
                         ["RFC 1918 / 5735 / 6598 / 4193"])

    malware_ip = make_ipset("malware", IP_ROLES["malware"][0],
                            h.get("threat-ip-malware"),
                            ["Feodo Tracker / abuse.ch (CC0)"])
    phishing_ip = make_ipset("phishing", IP_ROLES["phishing"][0],
                             h.get("threat-ip-phishing"),
                             ["Phishing.Database (MIT)"])

    # --- cross-check our RIR parsing against two independent implementations
    for label, key in (("ipverse", "xc-ipverse-"), ("ipdeny", "xc-ipdeny-")):
        other_raw = h.any_of(key)
        if not other_raw:
            continue
        o4, o6, _ = parse_networks(other_raw)
        ours = set(map(str, ir.v4))
        theirs = set(map(str, o4))
        both = len(ours & theirs)
        audit[f"crosscheck_{label}"] = {
            "their_ipv4_prefixes": len(o4), "their_ipv6_prefixes": len(o6),
            "exact_prefix_matches": both,
            "only_ours": len(ours - theirs), "only_theirs": len(theirs - ours),
            "address_coverage_ratio": round(
                sum(n.num_addresses for n in o4) /
                max(1, sum(n.num_addresses for n in ir.v4)), 4),
        }
        log(f"  cross-check {label}: {both} identical prefixes, "
            f"coverage ratio {audit[f'crosscheck_{label}']['address_coverage_ratio']}")

    audit["ir_ipv4_addresses"] = sum(n.num_addresses for n in ir.v4)
    audit["ir_ipv4_prefixes"] = len(ir.v4)
    audit["ir_ipv6_prefixes"] = len(ir.v6)

    return ({"ir": ir, "ir-cdn": cdn, "ir-full": full, "private": private,
             "malware": malware_ip, "phishing": phishing_ip}, audit)


# ----------------------------------------------------------- domain datasets


def build_domain_sets(h: sources.Harvest) -> dict[str, DomainSet]:
    out: dict[str, DomainSet] = {}

    # Iranian domains. Every .ir name is covered by the single suffix rule
    # "ir", so tens of thousands of individual entries collapse into one.
    out["ir"] = make_domainset(
        "ir", DOMAIN_ROLES["ir"][0], suffix=h.get("ir-domains"),
        sources=["Iran Hosted Domains (MIT)"], collapse_tld="ir")

    out["ads-ir"] = make_domainset(
        "ads-ir", DOMAIN_ROLES["ads-ir"][0], suffix=h.get("ads-persian"),
        sources=["PersianBlocker (AGPL-3.0)"])

    out["ads"] = make_domainset(
        "ads", DOMAIN_ROLES["ads"][0],
        suffix=h.get("ads-persian") + h.get("ads-hagezi") + h.get("ads-adguard"),
        sources=["PersianBlocker (AGPL-3.0)", "HaGeZi Multi PRO (GPL-3.0)",
                 "AdGuard DNS filter (GPL-3.0)"])

    out["malware"] = make_domainset(
        "malware", DOMAIN_ROLES["malware"][0], suffix=h.get("malware-urlhaus"),
        sources=["URLhaus / abuse.ch (CC0)"])

    out["phishing"] = make_domainset(
        "phishing", DOMAIN_ROLES["phishing"][0], suffix=h.get("phishing-db"),
        sources=["Phishing.Database (MIT)"])

    out["cryptominers"] = make_domainset(
        "cryptominers", DOMAIN_ROLES["cryptominers"][0],
        suffix=h.get("crypto-nocoin"), sources=["NoCoin adblock list (MIT)"])

    out["nsfw"] = make_domainset(
        "nsfw", DOMAIN_ROLES["nsfw"][0], suffix=h.get("nsfw-stevenblack"),
        sources=["StevenBlack unified hosts (MIT)"])

    combined_sources: list[str] = []
    combined: list[str] = []
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
    return out


# ------------------------------------------------------------ Xray .dat files


def build_dat_files(ctx: BuildContext, ips: dict, doms: dict) -> None:
    """Emit geoip.dat / geosite.dat plus trimmed -lite variants."""
    geoip = {slug: s.all_networks() for slug, s in ips.items()}
    blob = geodat.encode_geoip(geoip)
    _write_bin(ctx, "xray/geoip.dat", blob, sum(len(v) for v in geoip.values()))

    lite_ip = {k: geoip[k] for k in ("ir", "private") if k in geoip}
    _write_bin(ctx, "xray/geoip-lite.dat", geodat.encode_geoip(lite_ip),
               sum(len(v) for v in lite_ip.values()))

    def as_domains(d: DomainSet):
        return ([(geodat.ROOT_DOMAIN, n) for n in sorted(d.suffix)] +
                [(geodat.FULL, n) for n in sorted(d.full)] +
                [(geodat.PLAIN, n) for n in sorted(d.keyword)] +
                [(geodat.REGEX, n) for n in sorted(d.regex)])

    # block-all is deliberately left out: it is the union of four categories
    # that are all already present, and carrying it would roughly double the
    # file for no new information.
    geosite = {slug: as_domains(d) for slug, d in doms.items()
               if slug != "block-all"}
    # "category-ads-all" is the name most published Xray configs already use
    geosite["category-ads-all"] = geosite["ads"]
    _write_bin(ctx, "xray/geosite.dat", geodat.encode_geosite(geosite),
               sum(len(v) for v in geosite.values()))

    lite_site = {k: geosite[k] for k in ("ir", "ads-ir") if k in geosite}
    _write_bin(ctx, "xray/geosite-lite.dat", geodat.encode_geosite(lite_site),
               sum(len(v) for v in lite_site.values()))

    sec_site = {k: geosite[k] for k in
                ("ads", "malware", "phishing", "cryptominers") if k in geosite}
    _write_bin(ctx, "xray/geosite-security.dat", geodat.encode_geosite(sec_site),
               sum(len(v) for v in sec_site.values()))

    # verify what we just wrote actually parses back to the same thing
    check = {c.code: c.domains for c in geodat.decode_geosite(
        open(ctx.path("xray/geosite.dat"), "rb").read())}
    assert check["IR"] == geosite["ir"], "geosite.dat failed round-trip"
    check_ip = {c.code: c.networks for c in geodat.decode_geoip(
        open(ctx.path("xray/geoip.dat"), "rb").read())}
    assert check_ip["IR"] == geoip["ir"], "geoip.dat failed round-trip"
    log("  xray .dat round-trip verified")


def _write_bin(ctx: BuildContext, relpath: str, blob: bytes, entries: int) -> None:
    with open(ctx.path(relpath), "wb") as fh:
        fh.write(blob)
    ctx.record(relpath, entries)
    log(f"  wrote {relpath:<28} {len(blob) / 1024:>8.0f} KiB  {entries} entries")


# ---------------------------------------------- binary rule-sets via toolchain


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
        src = os.path.join(srcdir, name)
        dst = ctx.path(f"sing-box/rule-set/{name[:-5]}.srs")
        res = subprocess.run([exe, "rule-set", "compile", "--output", dst, src],
                             capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"ERROR: sing-box compile failed for {name}: {res.stderr}")
        ctx.record(f"sing-box/rule-set/{name[:-5]}.srs", 0)
        made += 1
    log(f"  compiled {made} sing-box .srs rule-sets")
    return made


def compile_mihomo(ctx: BuildContext, require: bool) -> int:
    """Compile Clash text rule-providers into mihomo's binary .mrs format.

    Only ``domain`` and ``ipcidr`` behaviours have an .mrs representation;
    classical rules stay YAML.
    """
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
        behavior = "ipcidr" if name.endswith("-ip.list") else "domain"
        src = os.path.join(clashdir, name)
        dst = ctx.path(f"mihomo/{name[:-5]}.mrs")
        res = subprocess.run([exe, "convert-ruleset", behavior, "text", src, dst],
                             capture_output=True, text=True)
        if res.returncode != 0:
            log(f"  warn: mihomo failed on {name}: "
                f"{(res.stderr or res.stdout).strip()[:200]}")
            continue
        ctx.record(f"mihomo/{name[:-5]}.mrs", 0)
        made += 1
    log(f"  compiled {made} mihomo .mrs rule-sets")
    return made


# --------------------------------------------------------- ready-made configs


def write_configs(ctx: BuildContext, base_url: str) -> None:
    """Drop-in snippets so a user does not have to write the plumbing."""
    xray = {
        "_comment": "Xray / v2ray routing block. Place geoip.dat and "
                    "geosite.dat next to the core binary (or in its asset dir).",
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
        "_comment": "sing-box route fragment. Remote rule-sets update daily.",
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

    clash_yaml = [
        "# Mihomo / Clash.Meta rule-providers. .mrs is the compact binary",
        "# form; swap the url and format to yaml if your client predates it.",
        "rule-providers:",
    ]
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

    mikrotik = [
        "# RouterOS: fetch the Iranian address-list daily and import it.",
        "# Paste once, then it maintains itself.",
        "",
        "/system script",
        "add name=IR-Geo-Update policy=ftp,read,write,test,policy source={",
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
        "    on-event=IR-Geo-Update policy=ftp,read,write,test",
    ]
    emitters.write_lines(ctx, "mikrotik/auto-update.rsc", mikrotik,
                         "RouterOS self-updating installer", 1, [])


# ------------------------------------------------------------------- metadata


def write_metadata(ctx: BuildContext, ips: dict, doms: dict, h: sources.Harvest,
                   audit: dict) -> dict:
    stats = {
        "version": ctx.version,
        "generated": ctx.timestamp,
        "ip_sets": {k: v.stats() for k, v in ips.items()},
        "domain_sets": {k: v.stats() for k, v in doms.items()},
        "sources_ok": sorted(h.values),
        "sources_failed": h.failed,
        "audit": audit,
    }
    emitters.write_json(ctx, "stats.json", stats, 0)

    emitters.write_json(ctx, "manifest.json", {
        "version": ctx.version, "generated": ctx.timestamp,
        "files": sorted(ctx.manifest, key=lambda r: r["file"]),
    }, len(ctx.manifest))

    # checksums last: they cover everything written before this point
    lines = []
    for root, _dirs, files in os.walk(ctx.outdir):
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, ctx.outdir).replace(os.sep, "/")
            if rel == "SHA256SUMS":
                continue
            digest = hashlib.sha256(open(full, "rb").read()).hexdigest()
            lines.append(f"{digest}  {rel}")
    with open(os.path.join(ctx.outdir, "SHA256SUMS"), "w", encoding="utf-8",
              newline="\n") as fh:
        fh.write("\n".join(sorted(lines)) + "\n")
    return stats


# One archive per tool, so nobody downloads 300 MiB of Unbound stanzas to get
# a MikroTik address-list. The full archive stays available for mirroring.
BUNDLES: dict[str, list[str]] = {
    "xray": ["xray"],
    "sing-box": ["sing-box"],
    "mihomo": ["mihomo", "clash"],
    "mikrotik": ["mikrotik"],
    "dns": ["dnsmasq", "unbound", "adguard", "hosts", "rpz", "smartdns"],
    "firewall": ["ipset", "nftables", "wireguard", "text", "json"],
    "surge": ["surge", "quantumultx"],
}


def package(ctx: BuildContext, outdir_parent: str) -> list[str]:
    """Per-tool zips plus one full archive, all written beside dist/."""
    made = []
    meta = ["manifest.json", "stats.json", "SHA256SUMS"]

    def add_tree(zf: zipfile.ZipFile, subdirs: list[str]) -> int:
        n = 0
        for sub in subdirs:
            root_dir = os.path.join(ctx.outdir, sub)
            if not os.path.isdir(root_dir):
                continue
            for root, _dirs, files in os.walk(root_dir):
                for name in sorted(files):
                    full = os.path.join(root, name)
                    zf.write(full, os.path.relpath(full, ctx.outdir))
                    n += 1
        return n

    for bundle, subdirs in BUNDLES.items():
        path = os.path.join(outdir_parent, f"{bundle}.zip")
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            count = add_tree(zf, subdirs)
            for m in meta:
                mp = os.path.join(ctx.outdir, m)
                if os.path.exists(mp):
                    zf.write(mp, m)
        if count == 0:
            os.remove(path)
            continue
        made.append(path)
        log(f"  packaged {bundle + '.zip':<20} {count:>4} files  "
            f"{os.path.getsize(path) / 1024 / 1024:>7.1f} MiB")

    full = os.path.join(outdir_parent, f"ir-geo-db-{ctx.version}.zip")
    with zipfile.ZipFile(full, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for root, _dirs, files in os.walk(ctx.outdir):
            for name in sorted(files):
                fp = os.path.join(root, name)
                zf.write(fp, os.path.relpath(fp, ctx.outdir))
    made.append(full)
    log(f"  packaged {os.path.basename(full):<20}      "
        f"{os.path.getsize(full) / 1024 / 1024:>7.1f} MiB")
    return made


# ---------------------------------------------------------------- sanity gate


def sanity_check(ips: dict, doms: dict) -> None:
    """Refuse to publish an obviously broken build.

    A bad upstream day should produce no release, not a release that empties
    somebody's router address-list.
    """
    problems = []
    if len(ips["ir"].v4) < 1000:
        problems.append(f"ir IPv4 prefixes = {len(ips['ir'].v4)}, expected >1000")
    if len(ips["ir"].v6) < 100:
        problems.append(f"ir IPv6 prefixes = {len(ips['ir'].v6)}, expected >100")
    if doms["ir"].total < 1000:
        problems.append(f"ir domains = {doms['ir'].total}, expected >1000")
    if doms["ads"].total < 1000:
        problems.append(f"ads domains = {doms['ads'].total}, expected >1000")

    # a well-known Iranian range and a well-known foreign one
    ir_nets = ips["ir"].v4
    must_have = ipaddress.ip_network("2.144.0.0/14")
    if not any(must_have.subnet_of(n) or n.subnet_of(must_have) for n in ir_nets):
        problems.append("2.144.0.0/14 (TCI) missing from the Iranian set")
    google_dns = ipaddress.ip_address("8.8.8.8")
    if any(google_dns in n for n in ir_nets):
        problems.append("8.8.8.8 is inside the Iranian set — source contamination")

    if problems:
        for p in problems:
            log(f"  FAIL {p}")
        sys.exit("sanity check failed — refusing to publish")
    log("  sanity checks passed")


# ------------------------------------------------------------------ main


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outdir", default="dist")
    ap.add_argument("--version", default=None)
    ap.add_argument("--cache", default=None,
                    help="cache downloads here (local iteration only)")
    ap.add_argument("--base-url", default=None,
                    help="URL the generated configs point at")
    ap.add_argument("--resolver", default="178.22.122.100")
    ap.add_argument("--require-binaries", action="store_true",
                    help="fail if sing-box/mihomo are missing")
    ap.add_argument("--strict-exclude", action="store_true", default=True,
                    help="subtract foreign cloud ranges from the Iranian set")
    ap.add_argument("--no-strict-exclude", dest="strict_exclude",
                    action="store_false")
    ap.add_argument("--skip-package", action="store_true")
    args = ap.parse_args()

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
    h = sources.harvest(cache_dir=args.cache, log=log)

    log("\n[2/7] building IP datasets")
    ips, audit = build_ip_sets(h, args.strict_exclude)

    log("\n[3/7] building domain datasets")
    doms = build_domain_sets(h)

    log("\n[4/7] sanity checks")
    sanity_check(ips, doms)

    log("\n[5/7] emitting formats")
    for slug, s in ips.items():
        emitters.emit_ipset(ctx, s, IP_ROLES[slug][1])
    for slug, d in doms.items():
        profile = "aggregate" if slug == "block-all" else "auto"
        used = emitters.emit_domainset(ctx, d, DOMAIN_ROLES[slug][1], profile)
        if used != "full":
            log(f"  {slug}: '{used}' format profile ({d.total} entries)")
    build_dat_files(ctx, ips, doms)
    write_configs(ctx, base_url)
    log(f"  {len(ctx.manifest)} files written")

    log("\n[6/7] compiling binary rule-sets")
    compile_singbox(ctx, args.require_binaries)
    compile_mihomo(ctx, args.require_binaries)

    log("\n[7/7] metadata")
    stats = write_metadata(ctx, ips, doms, h, audit)
    if not args.skip_package:
        package(ctx, os.path.dirname(os.path.abspath(args.outdir)))

    total = sum(len(fs) for _, _, fs in os.walk(args.outdir))
    log(f"\ndone: {total} files in {args.outdir}/")
    log(f"ir = {len(ips['ir'].v4)} IPv4 + {len(ips['ir'].v6)} IPv6 prefixes, "
        f"{stats['ip_sets']['ir']['ipv4']} v4 entries")


if __name__ == "__main__":
    main()
