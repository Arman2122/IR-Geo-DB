#!/usr/bin/env python3
"""
release_notes.py — render GitHub release notes from a completed build.

    python3 build/release_notes.py dist/stats.json v2026.08.03 > NOTES.md

Kept out of the workflow YAML because generating a table with shell
here-documents is how workflows become unreadable.
"""

from __future__ import annotations

import json
import sys

REPO = "Arman2122/IR-Geo-DB"
RAW = f"https://raw.githubusercontent.com/{REPO}/dist"
REL = f"https://github.com/{REPO}/releases/latest/download"


def fmt(n: int) -> str:
    return f"{n:,}"


def main() -> None:
    stats = json.load(open(sys.argv[1], encoding="utf-8"))
    version = sys.argv[2] if len(sys.argv) > 2 else stats["version"]

    ip = stats["ip_sets"]
    dom = stats["domain_sets"]
    audit = stats.get("audit", {})

    out: list[str] = []
    add = out.append

    add(f"Automated daily build — **{stats['generated']}**")
    add("")
    add("Routing and filtering data for Iran, rebuilt from primary sources "
        "every day and published in the formats real clients and routers "
        "actually consume.")
    add("")

    # ---- headline numbers
    add("## What's in this build")
    add("")
    add("| Set | Kind | Entries |")
    add("|---|---|---|")
    add(f"| `ir` | IPv4 prefixes | {fmt(ip['ir']['ipv4'])} |")
    add(f"| `ir` | IPv6 prefixes | {fmt(ip['ir']['ipv6'])} |")
    add(f"| `ir` | domains | {fmt(dom['ir']['suffix'] + dom['ir']['full'])} |")
    add(f"| `ir-cdn` | Iranian CDN IP prefixes | "
        f"{fmt(ip['ir-cdn']['ipv4'] + ip['ir-cdn']['ipv6'])} |")
    for key, label in (("ads", "advertising / tracking"),
                       ("malware", "malware"), ("phishing", "phishing"),
                       ("cryptominers", "cryptominers"), ("nsfw", "adult / gambling")):
        if key in dom:
            add(f"| `{key}` | {label} domains | "
                f"{fmt(dom[key]['suffix'] + dom[key]['full'])} |")
    for key in ("malware", "phishing"):
        if key in ip:
            add(f"| `{key}` | threat IPs | {fmt(ip[key]['ipv4'] + ip[key]['ipv6'])} |")
    add("")

    # ---- provenance, which is the part people should actually check
    add("## Where the Iranian IP data comes from")
    add("")
    add("Addresses are taken from the **Regional Internet Registries' own "
        "delegation records** — an address is Iranian only if a RIR has "
        "delegated it to an organisation registered in Iran. No geolocation "
        "guessing is involved.")
    add("")
    for label in ("ipverse", "ipdeny"):
        xc = audit.get(f"crosscheck_{label}")
        if not xc:
            continue
        add(f"- Cross-checked against **{label}** (an independent parse of the "
            f"same registry data): {fmt(xc['exact_prefix_matches'])} identical "
            f"prefixes, coverage ratio {xc['address_coverage_ratio']}.")
    if audit.get("foreign_cloud_excluded"):
        add(f"- Published ranges belonging to Cloudflare, AWS, Google, Fastly "
            f"and G-Core are subtracted "
            f"({fmt(audit.get('foreign_cloud_overlap_addresses', 0))} addresses "
            f"this build).")
    add("- Iranian CDN provider ranges are published **separately** as "
        "`ir-cdn`, because those lists include edge nodes hosted outside "
        "Iran. Use `ir-full` if you want both.")
    add("")

    # ---- how to use it
    add("## Quick start")
    add("")
    add("<details><summary><b>Xray / v2ray</b></summary>")
    add("")
    add("```bash")
    add(f"curl -sfLO {REL}/geoip.dat")
    add(f"curl -sfLO {REL}/geosite.dat")
    add("```")
    add("")
    add("Then use `geoip:ir`, `geosite:ir`, `geosite:ads`, `geoip:malware` in "
        "your routing rules. A ready-made rule block is in `xray/routing-rules.json`.")
    add("</details>")
    add("")
    add("<details><summary><b>sing-box</b></summary>")
    add("")
    add("```json")
    add('{ "type": "remote", "tag": "geosite-ir", "format": "binary",')
    add(f'  "url": "{RAW}/sing-box/rule-set/geosite-ir.srs",')
    add('  "download_detour": "direct", "update_interval": "1d" }')
    add("```")
    add("</details>")
    add("")
    add("<details><summary><b>Mihomo / Clash.Meta</b></summary>")
    add("")
    add("```yaml")
    add("rule-providers:")
    add("  ir-domain:")
    add("    type: http")
    add("    behavior: domain")
    add("    format: mrs")
    add(f"    url: {RAW}/mihomo/ir-domain.mrs")
    add("    interval: 86400")
    add("```")
    add("</details>")
    add("")
    add("<details><summary><b>MikroTik RouterOS</b></summary>")
    add("")
    add("```")
    add("/tool fetch mode=https dst-path=ir.rsc \\")
    add(f'  url="{RAW}/mikrotik/ir-ipv4-reset.rsc"')
    add("/import file-name=ir.rsc")
    add("```")
    add("")
    add(f"`{RAW}/mikrotik/auto-update.rsc` installs a scheduler that does "
        "this daily, with a size guard so a truncated download cannot wipe "
        "your address list.")
    add("</details>")
    add("")

    # ---- assets
    add("## Assets")
    add("")
    add("| Archive | Contents |")
    add("|---|---|")
    add("| `xray.zip` | `geoip.dat`, `geosite.dat`, lite and security variants |")
    add("| `sing-box.zip` | compiled `.srs` rule-sets + JSON sources |")
    add("| `mihomo.zip` | compiled `.mrs` rule-sets + Clash YAML/list providers |")
    add("| `mikrotik.zip` | `.rsc` address-lists, DNS scripts, adlists |")
    add("| `dns.zip` | dnsmasq, Unbound, AdGuard, hosts, RPZ, SmartDNS |")
    add("| `firewall.zip` | ipset, nftables, WireGuard, plain text / CIDR |")
    add("| `surge.zip` | Surge, Loon, Quantumult X rule lists |")
    add(f"| `ir-geo-db-{version}.zip` | everything above in one archive |")
    add("")
    add("`SHA256SUMS` covers every file in the tree. The full tree is also "
        f"on the [`dist` branch](https://github.com/{REPO}/tree/dist) for "
        "direct `raw.githubusercontent.com` URLs, which is what routers want "
        "— release asset URLs redirect, and not every device follows "
        "redirects.")

    failed = stats.get("sources_failed") or {}
    if failed:
        add("")
        add("## Degraded sources")
        add("")
        add("These optional feeds were unreachable for this build; the "
            "affected sets fall back to their remaining sources:")
        add("")
        for key, err in sorted(failed.items()):
            add(f"- `{key}` — {str(err)[:120]}")

    print("\n".join(out))


if __name__ == "__main__":
    main()
