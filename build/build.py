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
import zipfile
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import emitters  # noqa: E402
import geodat  # noqa: E402
import sources  # noqa: E402
from emitters import BuildContext  # noqa: E402
from model import DomainSet, IPSet, make_domainset, make_ipset, parse_networks  # noqa: E402

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


def log(msg: str = "") -> None:
    print(msg, flush=True)


def exclude_networks(base: list, drop: list) -> tuple[list, int]:
    """Remove every part of ``base`` that overlaps ``drop``.

    Returns the remainder and the number of *addresses* removed; a prefix
    count would be misleading, since excluding a /24 from a /8 leaves more
    prefixes than it started with.
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
    kept = sorted(ipaddress.collapse_addresses(kept)) if kept else []
    return kept, before - sum(n.num_addresses for n in kept)


def build_ip_sets(h: sources.Harvest, strict_exclude: bool) -> tuple[dict, dict]:
    audit: dict = {}

    registry_raw = h.any_of("rir-")
    reg_v4, reg_v6, reg_bad = parse_networks(registry_raw)
    log(f"  registry IR: {len(reg_v4)} IPv4 + {len(reg_v6)} IPv6 prefixes "
        f"({len(registry_raw)} raw records, {reg_bad} malformed)")

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

    # Kept out of `ir`: these published lists include edge nodes that are not
    # in Iran (ParsPack ships Leaseweb and Vultr ranges).
    cdn = make_ipset("ir-cdn", IP_ROLES["ir-cdn"][0],
                     h.get("arvancloud") + h.get("parspack"),
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


def build_domain_sets(h: sources.Harvest) -> dict[str, DomainSet]:
    out: dict[str, DomainSet] = {}

    out["ir"] = make_domainset(
        "ir", DOMAIN_ROLES["ir"][0], suffix=h.get("ir-domains"),
        sources=["Iran Hosted Domains (MIT)"], collapse_tld="ir")

    out["ads-ir"] = make_domainset(
        "ads-ir", DOMAIN_ROLES["ads-ir"][0], suffix=h.get("ads-persian"),
        sources=["PersianBlocker (AGPL-3.0)"])

    out["ads"] = make_domainset(
        "ads", DOMAIN_ROLES["ads"][0],
        suffix=h.get("ads-persian") + h.get("ads-hagezi") + h.get("ads-adguard"),
        sources=["PersianBlocker (AGPL-3.0)", "HaGeZi Multi LIGHT (GPL-3.0)",
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
    return out


def build_dat_files(ctx: BuildContext, ips: dict, doms: dict) -> None:
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
    _write_bin(ctx, "xray/geosite.dat", geodat.encode_geosite(geosite),
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
            sys.exit(f"ERROR: sing-box compile failed for {name}: {res.stderr}")
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
        # only domain and ipcidr behaviours have an .mrs representation
        behavior = "ipcidr" if name.endswith("-ip.list") else "domain"
        dst = ctx.path(f"mihomo/{name[:-5]}.mrs")
        res = subprocess.run(
            [exe, "convert-ruleset", behavior, "text",
             os.path.join(clashdir, name), dst],
            capture_output=True, text=True)
        if res.returncode != 0:
            log(f"  warn: mihomo failed on {name}: "
                f"{(res.stderr or res.stdout).strip()[:200]}")
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

    mikrotik = [
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


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--outdir", default="dist")
    ap.add_argument("--version", default=None)
    ap.add_argument("--cache", default=None,
                    help="cache downloads here (local iteration only)")
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--resolver", default="178.22.122.100")
    ap.add_argument("--require-binaries", action="store_true")
    ap.add_argument("--strict-exclude", action="store_true", default=True)
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
        parent = os.path.dirname(os.path.abspath(args.outdir))
        stage_release(ctx, parent)
        package(ctx, parent)

    total = sum(len(fs) for _, _, fs in os.walk(args.outdir))
    log(f"\ndone: {total} files in {args.outdir}/")
    log(f"ir = {len(ips['ir'].v4)} IPv4 + {len(ips['ir'].v6)} IPv6 prefixes, "
        f"{stats['ip_sets']['ir']['ipv4']} v4 entries")


if __name__ == "__main__":
    main()
