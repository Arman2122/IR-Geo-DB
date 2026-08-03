#!/usr/bin/env python3
"""Post-build acceptance checks against a produced dist/ tree.

    python3 build/verify.py dist

Separate from the sanity gate in build.py: that one asks whether the data
looked sane before writing, this re-reads the files from disk and decodes the
binary formats to check what actually got written. Non-zero exit on failure.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import geodat  # noqa: E402

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


def load_cidrs(path: str) -> list:
    nets = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                nets.append(ipaddress.ip_network(line, strict=False))
    return nets


def main() -> int:
    dist = sys.argv[1] if len(sys.argv) > 1 else "dist"
    print(f"verifying {dist}/\n")

    # ---------------------------------------------------------- IP accuracy
    print("Iranian IP set accuracy")
    v4 = load_cidrs(os.path.join(dist, "text", "ir-ipv4.txt"))
    v6 = load_cidrs(os.path.join(dist, "text", "ir-ipv6.txt"))
    check(len(v4) > 1000, f"ir IPv4 prefix count = {len(v4)} (> 1000)")
    check(len(v6) > 100, f"ir IPv6 prefix count = {len(v6)} (> 100)")

    for addr, who in MUST_BE_IR:
        ip = ipaddress.ip_address(addr)
        check(any(ip in n for n in v4), f"{addr} ({who}) is in the Iranian set")
    for addr, who in MUST_NOT_BE_IR:
        ip = ipaddress.ip_address(addr)
        check(not any(ip in n for n in v4),
              f"{addr} ({who}) is NOT in the Iranian set")

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
        lines = [l.strip() for l in open(os.path.join(text_dir, fn),
                                         encoding="utf-8")
                 if l.strip() and not l.startswith("#")]
        check(len(lines) == len(set(lines)),
              f"text/{fn}: {len(lines)} domains, no exact duplicates")
        doms = set(lines)
        covered = [d for d in doms
                   if any(".".join(d.split(".")[i:]) in doms
                          for i in range(1, len(d.split("."))))]
        check(not covered,
              f"text/{fn}: no domain covered by a parent already in the set "
              f"({len(covered)} found)")

    # A value must not appear twice in a category, nor under two match types
    for fn in sorted(os.listdir(os.path.join(dist, "xray"))):
        if not fn.endswith(".dat"):
            continue
        blob = open(os.path.join(dist, "xray", fn), "rb").read()
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
        data = json.load(open(os.path.join(srcdir, fn), encoding="utf-8"))
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
        lines = [l.strip() for l in open(os.path.join(clash_dir, fn),
                                         encoding="utf-8")
                 if l.strip() and not l.startswith("#")]
        check(len(lines) == len(set(lines)),
              f"clash/{fn}: no duplicate lines")
        both = {l[2:] for l in lines if l.startswith("+.")} & \
               {l for l in lines if not l.startswith("+.")}
        check(not both,
              f"clash/{fn}: nothing listed as both '+.x' and 'x' "
              f"({len(both)} found)")

    # ------------------------------------------------------------ Xray .dat
    print("\nXray data files")
    gi = os.path.join(dist, "xray", "geoip.dat")
    cats = {c.code: c.networks for c in geodat.decode_geoip(open(gi, "rb").read())}
    check("IR" in cats, f"geoip.dat has an IR category ({sorted(cats)})")
    check(len(cats["IR"]) == len(v4) + len(v6),
          f"geoip.dat IR entry count matches text output "
          f"({len(cats['IR'])} vs {len(v4) + len(v6)})")
    ip = ipaddress.ip_address("2.144.0.1")
    check(any(ip in n for n in cats["IR"]), "geoip.dat IR resolves 2.144.0.1")

    gs = os.path.join(dist, "xray", "geosite.dat")
    scats = {c.code: c.domains for c in geodat.decode_geosite(open(gs, "rb").read())}
    check("IR" in scats, f"geosite.dat has an IR category ({len(scats)} categories)")
    ir_vals = {v for t, v in scats["IR"]}
    check("ir" in ir_vals, "geosite.dat IR contains the collapsed 'ir' TLD rule")
    check(not any(v.endswith(".ir") for v in ir_vals),
          "geosite.dat IR carries no redundant *.ir entries")
    types = {t for t, _ in scats["IR"]}
    check(types <= {geodat.ROOT_DOMAIN, geodat.FULL, geodat.PLAIN, geodat.REGEX},
          f"geosite.dat IR uses only valid domain types ({types})")

    # ------------------------------------------------------- sing-box .srs
    print("\nsing-box rule-sets")
    srs_dir = os.path.join(dist, "sing-box", "rule-set")
    exe = os.environ.get("SING_BOX") or shutil.which("sing-box")
    if not os.path.isdir(srs_dir):
        check(False, "sing-box/rule-set/ exists")
    elif not exe:
        print("  skip  sing-box binary unavailable, cannot decompile")
    else:
        srs = os.path.join(srs_dir, "geoip-ir.srs")
        out = os.path.join(dist, "_verify-geoip-ir.json")
        res = subprocess.run([exe, "rule-set", "decompile", "--output", out, srs],
                             capture_output=True, text=True)
        check(res.returncode == 0, f"geoip-ir.srs decompiles ({res.stderr.strip()[:80]})")
        if res.returncode == 0:
            data = json.load(open(out, encoding="utf-8"))
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
            data = json.load(open(out_d, encoding="utf-8"))
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
        head = open(os.path.join(mrs_dir, "ir-ip.mrs"), "rb").read(4)
        check(head == b"\x28\xb5\x2f\xfd", f"ir-ip.mrs has a zstd frame header ({head.hex()})")
    else:
        print("  skip  mihomo/ not built")

    # -------------------------------------------------------------- MikroTik
    print("\nMikroTik scripts")
    rsc = os.path.join(dist, "mikrotik", "ir-ipv4-reset.rsc")
    lines = [l.rstrip("\n") for l in open(rsc, encoding="utf-8")
             if l.strip() and not l.startswith("#")]
    check(lines[0] == "/ip firewall address-list",
          f"reset script opens the right menu ({lines[0]!r})")
    check(lines[1].startswith("remove [find list=IR "),
          f"reset script clears static entries first ({lines[1]!r})")
    adds = [l for l in lines if l.startswith("add address=")]
    check(len(adds) == len(v4), f"reset script has {len(adds)} adds (expected {len(v4)})")
    check(all(" list=IR" in l for l in adds), "every add targets the IR list")

    # ------------------------------------------------------------ integrity
    print("\nIntegrity")
    sums = os.path.join(dist, "SHA256SUMS")
    check(os.path.exists(sums), "SHA256SUMS present")
    manifest = json.load(open(os.path.join(dist, "manifest.json"), encoding="utf-8"))
    check(len(manifest["files"]) > 100,
          f"manifest lists {len(manifest['files'])} files")
    missing = [r["file"] for r in manifest["files"]
               if not os.path.exists(os.path.join(dist, r["file"]))]
    check(not missing, f"every manifest entry exists on disk ({len(missing)} missing)")

    print(f"\n{checks - len(failures)}/{checks} checks passed")
    if failures:
        print("\nFAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
