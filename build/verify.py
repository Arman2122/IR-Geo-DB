#!/usr/bin/env python3
"""Post-build acceptance checks against a produced dist/ tree.

    python3 build/verify.py dist [--lkg-dir .lkg]

Separate from the sanity gate in build.py: that one asks whether the data
looked sane before writing, this re-reads the files from disk and decodes the
binary formats to check what actually got written. Non-zero exit on failure.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build  # noqa: E402
import fetch  # noqa: E402
import geodat  # noqa: E402
import model  # noqa: E402
import sources  # noqa: E402

# Addresses that must be classified as Iranian. These are the largest and
# oldest IR delegations in the registry — /12s and /13s held since 2001-2012 —
# so they are stable anchors rather than blocks that may be transferred away.
MUST_BE_IR = [
    ("2.176.0.1", "TCI, /12 held since 2010"),
    ("5.112.0.1", "/12 held since 2012"),
    ("5.232.0.1", "/13 held since 2012"),
    ("217.218.0.1", "TCI, /15 held since 2001"),
    ("151.232.0.1", "/14 held since 2012"),
    ("178.22.122.100", "Shecan resolver"),
    ("185.51.200.2", "Iranian allocation"),
]

# Anchors verified when BGP routing adjustment is applied (offshore-LIR
# Iranian blocks announced by Iranian / domestic-provider ASNs).
MUST_BE_IR_ROUTED = [
    ("5.160.0.1", "Respina /16 (AE registry, IR AS42337)"),
    ("185.211.56.1", "Server.ir /22 (UAE LIR, 100% IR transit)"),
    ("185.39.180.1", "Dorna /22 (CA LIR, 100% IR transit)"),
]

# Anchors verified when RPKI ROV is applied (RPKI-valid sub-assignments under
# foreign covering routes, rescued by valid ROAs).
MUST_BE_IR_RPKI = [
    ("5.230.17.1", "ParsUptime /24 (Asiatech AS43754, RPKI-valid)"),
]

# Stable Iranian IPv6 anchor (IPM, /32 allocated in 2005).
MUST_BE_IR_V6 = [
    ("2001:790::1", "IPM /32 held since 2005"),
]

# Addresses that must NOT be classified as Iranian. A hit here means a source
# was mis-parsed or contaminated, which is the failure mode that would send a
# user's traffic the wrong way.
MUST_NOT_BE_IR = [
    ("8.8.8.8", "Google DNS"),
    ("1.1.1.1", "Cloudflare DNS"),
    ("104.16.0.1", "Cloudflare"),
    ("13.107.21.200", "Microsoft"),
    ("142.250.0.1", "Google"),
    ("52.94.0.1", "AWS"),
    ("192.168.1.1", "RFC1918"),
]

# Iranian domains that must be present in `ir` (curated + upstream anchors).
MUST_BE_IR_DOMAINS = [
    "ir", "xn--mgba3a4f16a", "digikala.com", "aparat.com",
    "khanoumi.com", "mizbancloud.com", "abramad.com", "netafraz.com",
]

# Global / non-Iranian domains that must never appear in `ir`.
MUST_NOT_BE_IR_DOMAINS = [
    "google.com", "cloudflare.com", "github.com",
    "asia.pool.ntp.org", "pool.ntp.org",
]

# Shared platforms that no blocklist may cover. Every set is emitted as suffix
# rules, so one of these in a feed takes down every site hosted under it —
# the 2026-10 Phishing.Database failure listed sites.google.com, bit.ly and
# nflxvideo.net. Checked against each name and all of its parents.
MUST_NOT_BLOCK = """
    google.com sites.google.com docs.google.com googleapis.com gstatic.com
    youtube.com bit.ly github.com github.io githubusercontent.com gravatar.com
    netflix.com nflxvideo.net cloudflare.com pages.dev workers.dev
    cloudfront.net amazonaws.com azurewebsites.net blogspot.com wordpress.com
    web.app firebaseapp.com vercel.app netlify.app herokuapp.com t.me
    telegram.org whatsapp.net instagram.com apple.com icloud.com microsoft.com
    windowsupdate.com wikipedia.org digikala.com aparat.com shaparak.ir
    snapp.ir divar.ir
""".split()

failures: list[str] = []
checks = 0


def check(ok: bool, label: str) -> None:
    global checks
    checks += 1
    if not ok:
        failures.append(label)
        print(f"  FAIL  {label}")
    else:
        print(f"  ok    {label}")


def provider_checks(stats: dict) -> list[tuple[str, bool | None]]:
    """(label, passed) for key providers `ir-cdn` must hold addresses of;
    passed is None when this build had no way to find them.

    ArvanCloud and Sotoon publish their own lists, so they are always checked.
    Liara, Server.ir and Dorna publish no list: their addresses come only from
    what their ASNs announce in RIS, so without IPv4 routing data they are
    skipped rather than blocking a degraded release.
    """
    audit = stats.get("audit") or {}
    providers = audit.get("providers") or {}
    ris_v4 = (stats.get("sources") or {}).get("ris-v4") or {}
    routed = (bool((audit.get("bgp") or {}).get("applied"))
              and ris_v4.get("status") not in (None, "dropped"))
    out = []
    for name, needs_routing in (("ArvanCloud", False), ("Sotoon", False),
                                ("Liara", True), ("Server.ir", True),
                                ("Dorna", True)):
        addresses = (providers.get(name) or {}).get("addresses", 0)
        label = f"audit.providers: {name} has {addresses} IPv4 addresses in ir-cdn"
        if needs_routing and not routed:
            out.append((f"{label} (no IPv4 routing data, not checked)", None))
        else:
            out.append((label, addresses > 0))
    return out


def load_cidrs(path: str) -> list:
    nets = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dist", nargs="?", default="dist",
                    help="the build output directory (default: dist)")
    ap.add_argument("--lkg-dir", default=".lkg",
                    help="the state store the build read and wrote, for the "
                         "PSL re-check (default: .lkg)")
    args = ap.parse_args()
    dist = args.dist
    print(f"verifying {dist}/\n")

    with open(os.path.join(dist, "stats.json"), encoding="utf-8") as fh:
        stats = json.load(fh)
    bgp_audit = (stats.get("audit") or {}).get("bgp") or {}
    ris_v4_ok = (bool(bgp_audit.get("applied"))
                 and ((stats.get("sources") or {}).get("ris-v4") or {}).get("status")
                 not in (None, "dropped"))

    # ---------------------------------------------------------- IP accuracy
    print("Iranian IP set accuracy")
    v4 = load_cidrs(os.path.join(dist, "text", "ir-ipv4.txt"))
    v6 = load_cidrs(os.path.join(dist, "text", "ir-ipv6.txt"))
    cdn_v4 = load_cidrs(os.path.join(dist, "text", "ir-cdn-ipv4.txt"))
    full_v4 = load_cidrs(os.path.join(dist, "text", "ir-full-ipv4.txt"))
    check(len(v4) > 1000, f"ir IPv4 prefix count = {len(v4)} (> 1000)")
    check(len(v6) > 100, f"ir IPv6 prefix count = {len(v6)} (> 100)")

    for addr, who in MUST_BE_IR:
        ip = ipaddress.ip_address(addr)
        check(any(ip in n for n in v4), f"{addr} ({who}) is in the Iranian set")
    if ris_v4_ok:
        for addr, who in MUST_BE_IR_ROUTED:
            ip = ipaddress.ip_address(addr)
            check(any(ip in n for n in v4),
                  f"{addr} ({who}) is in the routed Iranian set")
        if bgp_audit.get("rpki_applied"):
            for addr, who in MUST_BE_IR_RPKI:
                ip = ipaddress.ip_address(addr)
                check(any(ip in n for n in v4),
                      f"{addr} ({who}) is in the RPKI-validated Iranian set")
    for addr, who in MUST_BE_IR_V6:
        ip = ipaddress.ip_address(addr)
        check(any(ip in n for n in v6), f"{addr} ({who}) is in the Iranian IPv6 set")
    for addr, who in MUST_NOT_BE_IR:
        ip = ipaddress.ip_address(addr)
        check(not any(ip in n for n in v4),
              f"{addr} ({who}) is NOT in the Iranian set")

    private = [ipaddress.ip_network(p) for p in build.PRIVATE_RANGES]
    for label, nets in (("ir", v4 + v6), ("ir-cdn", cdn_v4), ("ir-full", full_v4)):
        hits = [str(n) for n in nets for p in private
                if n.version == p.version and n.overlaps(p)]
        check(not hits, f"{label}: no overlap with private/reserved ranges ({hits[:3]})")
    # ir-full must cover every address in ir and ir-cdn
    missing_from_full_ir, _ = model.exclude_networks(v4, full_v4)
    missing_from_full_cdn, _ = model.exclude_networks(cdn_v4, full_v4)
    check(not missing_from_full_ir and not missing_from_full_cdn,
          "ir-full IPv4 is a superset of both ir and ir-cdn")

    # ------------------------------------------------- duplicates everywhere
    # Collapsing is the definitive test for IP redundancy: if the count drops,
    # something was a duplicate or contained inside another prefix. Comparing
    # only adjacent pairs would miss a subnet separated from its supernet.
    print("\nDuplicates and redundancy")
    text_dir = os.path.join(dist, "text")
    for fn in sorted(os.listdir(text_dir)):
        if not re.search(r"-(ipv4|ipv6|all)\.txt$", fn):
            continue
        nets = load_cidrs(os.path.join(text_dir, fn))
        if not nets:
            continue
        by_ver: dict[int, list] = {}
        for n in nets:
            by_ver.setdefault(n.version, []).append(n)
        collapsed = sum(len(list(ipaddress.collapse_addresses(g)))
                        for g in by_ver.values())
        check(collapsed == len(nets),
              f"text/{fn}: {len(nets)} prefixes, none redundant "
              f"(collapses to {collapsed})")

    for fn in sorted(os.listdir(text_dir)):
        if not fn.endswith("-domains.txt"):
            continue
        with open(os.path.join(text_dir, fn), encoding="utf-8") as fh:
            lines = [l.strip() for l in fh
                     if l.strip() and not l.startswith("#")]
        check(len(lines) == len(set(lines)),
              f"text/{fn}: {len(lines)} domains, no exact duplicates")
        doms = set(lines)
        # Only suffix rules cover subdomains; two exact (full) matches such
        # as `asusrouter.com` and `www.asusrouter.com` in `private` are not
        # redundant. When sing-box/source preserves the suffix/full split,
        # check against suffix rules only.
        slug = fn[:-len("-domains.txt")]
        sb_path = os.path.join(dist, "sing-box", "source", f"geosite-{slug}.json")
        if os.path.exists(sb_path):
            with open(sb_path, encoding="utf-8") as fh:
                sb_rules = json.load(fh).get("rules") or [{}]
            parents = set(sb_rules[0].get("domain_suffix", ()))
        else:
            parents = doms
        covered = [d for d in doms
                   if any(".".join(d.split(".")[i:]) in parents
                          for i in range(1, len(d.split("."))))]
        check(not covered,
              f"text/{fn}: no domain covered by a suffix parent already in the set "
              f"({len(covered)} found)")

    # A value must not appear twice in a category, nor under two match types
    for fn in sorted(os.listdir(os.path.join(dist, "xray"))):
        if not fn.endswith(".dat"):
            continue
        with open(os.path.join(dist, "xray", fn), "rb") as fh:
            blob = fh.read()
        if fn.startswith("geoip"):
            for cat in geodat.decode_geoip(blob):
                strs = [str(n) for n in cat.networks]
                check(len(strs) == len(set(strs)),
                      f"xray/{fn} [{cat.code}]: no duplicate prefixes")
        else:
            for cat in geodat.decode_geosite(blob):
                vals = [v for _t, v in cat.domains]
                check(len(vals) == len(set(vals)),
                      f"xray/{fn} [{cat.code}]: no value repeated "
                      f"(across types or within one)")

    # domain and domain_suffix are different matchers; the same name in both
    # is a rule that can never add anything
    srcdir = os.path.join(dist, "sing-box", "source")
    for fn in sorted(os.listdir(srcdir)):
        with open(os.path.join(srcdir, fn), encoding="utf-8") as fh:
            data = json.load(fh)
        for rule in data.get("rules", []):
            for key, vals in rule.items():
                if isinstance(vals, list):
                    check(len(vals) == len(set(vals)),
                          f"sing-box/source/{fn} [{key}]: no duplicates")
            both = set(rule.get("domain", [])) & set(rule.get("domain_suffix", []))
            check(not both,
                  f"sing-box/source/{fn}: nothing in both domain and "
                  f"domain_suffix ({len(both)} found)")

    clash_dir = os.path.join(dist, "clash")
    for fn in sorted(os.listdir(clash_dir)):
        if not fn.endswith("-domain.list"):
            continue
        with open(os.path.join(clash_dir, fn), encoding="utf-8") as fh:
            lines = [l.strip() for l in fh
                     if l.strip() and not l.startswith("#")]
        check(len(lines) == len(set(lines)),
              f"clash/{fn}: no duplicate lines")
        both = {l[2:] for l in lines if l.startswith("+.")} & \
               {l for l in lines if not l.startswith("+.")}
        check(not both,
              f"clash/{fn}: nothing listed as both '+.x' and 'x' "
              f"({len(both)} found)")

    # ----------------------------------------------------- blocklist safety
    print("\nBlocklist safety")
    block_slugs = {slug for slug, (_title, role) in build.DOMAIN_ROLES.items()
                   if role == "block"}
    for fn in sorted(os.listdir(text_dir)):
        if not fn.endswith("-domains.txt"):
            continue
        slug = fn[:-len("-domains.txt")]
        if slug not in block_slugs:
            continue
        with open(os.path.join(text_dir, fn), encoding="utf-8") as fh:
            doms = {l.strip() for l in fh
                    if l.strip() and not l.startswith("#")}
        hits = sorted(s for s in MUST_NOT_BLOCK
                      if any(".".join(s.split(".")[i:]) in doms
                             for i in range(len(s.split(".")))))
        check(not hits, f"text/{fn}: blocks no shared platform ({hits})")

    # a bogon in a threat-IP set would block a user's own LAN or a resolver
    for fn in ("malware-ipv4.txt", "malware-ipv6.txt"):
        path = os.path.join(text_dir, fn)
        if not os.path.exists(path):
            continue
        nets = load_cidrs(path)
        hits = sorted({str(n) for n in nets for p in private
                       if n.version == p.version and n.overlaps(p)})
        check(not hits, f"text/{fn}: {len(nets)} prefixes, none overlap a "
                        f"private or reserved range ({hits[:3]})")

    # ------------------------------------------------------------ Xray .dat
    print("\nXray data files")
    gi = os.path.join(dist, "xray", "geoip.dat")
    with open(gi, "rb") as fh:
        cats = {c.code: c.networks for c in geodat.decode_geoip(fh.read())}
    check("IR" in cats and "IR-CDN" in cats and "IR-FULL" in cats,
          f"geoip.dat has IR, IR-CDN and IR-FULL categories ({sorted(cats)})")
    check(len(cats["IR"]) == len(v4) + len(v6),
          f"geoip.dat IR entry count matches text output "
          f"({len(cats['IR'])} vs {len(v4) + len(v6)})")
    ip = ipaddress.ip_address("2.144.0.1")
    check(any(ip in n for n in cats["IR"]), "geoip.dat IR resolves 2.144.0.1")

    gs = os.path.join(dist, "xray", "geosite.dat")
    with open(gs, "rb") as fh:
        scats = {c.code: c.domains for c in geodat.decode_geosite(fh.read())}
    for req_cat in ("IR", "CATEGORY-IR", "TLD-IR", "PRIVATE",
                    "CATEGORY-ADS-ALL", "CATEGORY-ADS-IR"):
        check(req_cat in scats, f"geosite.dat has {req_cat} category")
    ir_vals = {v for t, v in scats["IR"]}
    check("ir" in ir_vals, "geosite.dat IR contains the collapsed 'ir' TLD rule")
    check("xn--mgba3a4f16a" in ir_vals,
          "geosite.dat IR contains the collapsed 'xn--mgba3a4f16a' TLD rule")
    check(not any(v.endswith(".ir") for v in ir_vals),
          "geosite.dat IR carries no redundant *.ir entries")
    types = {t for t, _ in scats["IR"]}
    check(types <= {geodat.ROOT_DOMAIN, geodat.FULL, geodat.PLAIN, geodat.REGEX},
          f"geosite.dat IR uses only valid domain types ({types})")

    # ------------------------------------------------------- sing-box .srs
    print("\nsing-box rule-sets")
    srs_dir = os.path.join(dist, "sing-box", "rule-set")
    exe = os.environ.get("SING_BOX") or shutil.which("sing-box")
    # without the binary the build skips .srs entirely, so there is no
    # directory to look for
    if not exe:
        print("  skip  sing-box binary unavailable, cannot decompile")
    elif not os.path.isdir(srs_dir):
        check(False, "sing-box/rule-set/ exists")
    else:
        srs = os.path.join(srs_dir, "geoip-ir.srs")
        out = os.path.join(dist, "_verify-geoip-ir.json")
        res = subprocess.run([exe, "rule-set", "decompile", "--output", out, srs],
                             capture_output=True, text=True)
        check(res.returncode == 0, f"geoip-ir.srs decompiles ({res.stderr.strip()[:80]})")
        if res.returncode == 0:
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            got = data["rules"][0]["ip_cidr"]
            check(len(got) == len(v4) + len(v6),
                  f"geoip-ir.srs round-trips {len(got)} prefixes "
                  f"(expected {len(v4) + len(v6)})")
            os.remove(out)

        srs_d = os.path.join(srs_dir, "geosite-ir.srs")
        out_d = os.path.join(dist, "_verify-geosite-ir.json")
        res = subprocess.run([exe, "rule-set", "decompile", "--output", out_d, srs_d],
                             capture_output=True, text=True)
        check(res.returncode == 0, "geosite-ir.srs decompiles")
        if res.returncode == 0:
            with open(out_d, encoding="utf-8") as fh:
                data = json.load(fh)
            suffixes = data["rules"][0].get("domain_suffix", [])
            check("ir" in suffixes, "geosite-ir.srs keeps the collapsed 'ir' rule")
            os.remove(out_d)

    # ----------------------------------------------------------- mihomo .mrs
    print("\nmihomo rule-sets")
    mrs_dir = os.path.join(dist, "mihomo")
    if os.path.isdir(mrs_dir):
        names = sorted(os.listdir(mrs_dir))
        check(len(names) > 0, f"mihomo/ has {len(names)} .mrs files")
        for want in ("ir-ip.mrs", "ir-domain.mrs"):
            path = os.path.join(mrs_dir, want)
            ok = os.path.exists(path) and os.path.getsize(path) > 100
            check(ok, f"mihomo/{want} exists and is non-trivial")
        # .mrs is zstd-framed; check the magic rather than trusting the size
        path = os.path.join(mrs_dir, "ir-ip.mrs")
        head = b""
        if os.path.exists(path):
            with open(path, "rb") as fh:
                head = fh.read(4)
        check(head == b"\x28\xb5\x2f\xfd", f"ir-ip.mrs has a zstd frame header ({head.hex()})")
    else:
        print("  skip  mihomo/ not built")

    # ---------------------------------------- MikroTik / DNS / WG / Amnezia
    print("\nRouter, DNS, WireGuard and Amnezia formats")
    rsc = os.path.join(dist, "mikrotik", "ir-ipv4-reset.rsc")
    with open(rsc, encoding="utf-8") as fh:
        lines = [l.rstrip("\n") for l in fh
                 if l.strip() and not l.startswith("#")]
    check(lines[0] == "/ip firewall address-list",
          f"reset script opens the right menu ({lines[0]!r})")
    check(lines[1].startswith("remove [find list=IR "),
          f"reset script clears static entries first ({lines[1]!r})")
    adds = [l for l in lines if l.startswith("add address=")]
    check(len(adds) == len(v4), f"reset script has {len(adds)} adds (expected {len(v4)})")
    check(all(" list=IR" in l for l in adds), "every add targets the IR list")

    dns_rsc = os.path.join(dist, "mikrotik", "ir-dns-reset.rsc")
    check(os.path.exists(dns_rsc), "mikrotik/ir-dns-reset.rsc exists")
    if os.path.exists(dns_rsc):
        with open(dns_rsc, encoding="utf-8") as fh:
            dlines = [l.rstrip("\n") for l in fh
                      if l.strip() and not l.startswith("#")]
        check(dlines[0] == "/ip dns static" and "comment=IR-Geo-DB-IR" in dlines[1],
              "ir-dns-reset.rsc clears only IR-Geo-DB-IR tagged static DNS entries")

    rpz_dir = os.path.join(dist, "rpz")
    if os.path.isdir(rpz_dir):
        for fn in sorted(os.listdir(rpz_dir)):
            if not fn.endswith(".zone"):
                continue
            with open(os.path.join(rpz_dir, fn), encoding="utf-8") as fh:
                soa = next((l for l in fh if "IN SOA" in l), "")
            m = re.search(r"\((\d+)\s+\d+\s+\d+\s+\d+\s+\d+\)", soa)
            ok_serial = bool(m and 1 <= int(m.group(1)) <= 4_294_967_295)
            check(ok_serial, f"rpz/{fn}: valid numeric SOA serial")

    dm_blk = os.path.join(dist, "dnsmasq", "ads-block.conf")
    if os.path.exists(dm_blk):
        with open(dm_blk, encoding="utf-8") as fh:
            sample = [l.strip() for l in fh if l.strip() and not l.startswith("#")][:5]
        check(bool(sample) and all(l.startswith("address=/") and l.endswith("/") for l in sample),
              "dnsmasq/ads-block.conf emits dual-stack NXDOMAIN rules (address=/domain/)")

    wg_excl = os.path.join(dist, "wireguard", "ir-exclude-allowedips.conf")
    check(os.path.exists(wg_excl), "wireguard/ir-exclude-allowedips.conf exists")
    if os.path.exists(wg_excl):
        with open(wg_excl, encoding="utf-8") as fh:
            wg_line = next((l.strip() for l in fh if l.startswith("AllowedIPs =")), "")
        wg_nets = [ipaddress.ip_network(x.strip())
                   for x in wg_line.removeprefix("AllowedIPs =").split(",") if x.strip()]
        check(len(wg_nets) > 100 and not any(ipaddress.ip_address("2.176.0.1") in n for n in wg_nets)
              and any(ipaddress.ip_address("8.8.8.8") in n for n in wg_nets),
              f"wireguard/ir-exclude-allowedips.conf ({len(wg_nets)} CIDRs) routes 8.8.8.8 and excludes Iran")

    for am_fn in ("ir-domains.json", "ir-ipv4.json", "ir-full-ipv4.json"):
        am_path = os.path.join(dist, "amnezia", am_fn)
        ok_am = False
        if os.path.exists(am_path):
            with open(am_path, encoding="utf-8") as fh:
                am_data = json.load(fh)
            ok_am = (isinstance(am_data, list) and len(am_data) > 0
                     and isinstance(am_data[0], dict)
                     and "hostname" in am_data[0] and "ip" in am_data[0])
        check(ok_am, f"amnezia/{am_fn}: valid AmneziaVPN split-tunnel JSON array")

    # ------------------------------------------------------ domain filters
    print("\nIranian domain accuracy and filters")
    with open(os.path.join(text_dir, "ir-domains.txt"), encoding="utf-8") as fh:
        ir_names = {l.strip() for l in fh
                    if l.strip() and not l.startswith("#")}
    missing_ir_doms = [d for d in MUST_BE_IR_DOMAINS if d not in ir_names]
    check(not missing_ir_doms,
          f"text/ir-domains.txt contains all Iranian anchor domains (missing {missing_ir_doms})")
    leaked_ir_doms = [d for d in MUST_NOT_BE_IR_DOMAINS if d in ir_names]
    check(not leaked_ir_doms,
          f"text/ir-domains.txt excludes global non-Iranian domains (found {leaked_ir_doms})")

    stored_psl = fetch.StateStore(args.lkg_dir).load("psl")
    if stored_psl is None:
        print(f"  skip  PSL re-check: no stored PSL in {args.lkg_dir}")
    else:
        # the build filters before it collapses and prunes, so a name that
        # survives into the output and is still a shared-hosting suffix means
        # the filter missed it. Every name is treated as suffix-capable.
        psl_rules, _meta = stored_psl
        kept, removed = model.psl_filter(ir_names, psl_rules,
                                         keep=build.IR_PLATFORM_SUFFIXES)
        check(removed == 0,
              f"text/ir-domains.txt: {len(ir_names)} names, none a PSL "
              f"shared-hosting suffix ({sorted(ir_names - kept)[:5]})")

    # ----------------------------------------------------------- provenance
    print("\nProvenance")
    recorded = stats.get("sources", {})
    missing = [src.key for src in sources.SOURCES if src.key not in recorded]
    check(not missing, f"stats.json has a sources entry for each of the "
                       f"{len(sources.SOURCES)} registry keys (missing {missing})")
    for label, passed in provider_checks(stats):
        if passed is None:
            print(f"  skip  {label}")
        else:
            check(passed, label)

    # ------------------------------------------------------------ integrity
    print("\nIntegrity")
    sums = os.path.join(dist, "SHA256SUMS")
    check(os.path.exists(sums), "SHA256SUMS present")
    if os.path.exists(sums):
        sum_mismatches = []
        sum_count = 0
        with open(sums, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                digest, rel = line.split("  ", 1)
                fp = os.path.join(dist, rel)
                sum_count += 1
                if not os.path.isfile(fp):
                    sum_mismatches.append(f"missing:{rel}")
                    continue
                actual = hashlib.sha256()
                with open(fp, "rb") as target:
                    while chunk := target.read(65536):
                        actual.update(chunk)
                if actual.hexdigest() != digest:
                    sum_mismatches.append(f"mismatch:{rel}")
        check(sum_count > 100 and not sum_mismatches,
              f"SHA256SUMS verified {sum_count} files on disk ({len(sum_mismatches)} errors)")

    with open(os.path.join(dist, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    check(len(manifest["files"]) > 100,
          f"manifest lists {len(manifest['files'])} files")
    missing = [r["file"] for r in manifest["files"]
               if not os.path.exists(os.path.join(dist, r["file"]))]
    check(not missing, f"every manifest entry exists on disk ({len(missing)} missing)")
    has_digests = all("sha256" in r and "bytes" in r for r in manifest["files"])
    check(has_digests, "every manifest entry carries bytes and sha256")
    paths = [r["file"] for r in manifest["files"]]
    dupes = sorted({p for p in paths if paths.count(p) > 1})
    check(not dupes, f"no file is listed twice in the manifest ({dupes})")
    # an emitted file always carries at least a header, so zero bytes means a
    # crashed compiler, and GitHub refuses to upload one as a release asset
    empty = [os.path.relpath(os.path.join(root, f), dist).replace(os.sep, "/")
             for root, _dirs, files in os.walk(dist) for f in files
             if os.path.getsize(os.path.join(root, f)) == 0]
    check(not empty, f"no zero-byte files ({empty})")

    print(f"\n{checks - len(failures)}/{checks} checks passed")
    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
