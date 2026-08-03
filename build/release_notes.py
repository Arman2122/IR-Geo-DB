#!/usr/bin/env python3
"""Render GitHub release notes from a completed build.

    python3 build/release_notes.py dist/stats.json v2026.08.03 > NOTES.md
"""

from __future__ import annotations

import json
import sys

REPO = "Arman2122/IR-Geo-DB"
LATEST = f"https://github.com/{REPO}/releases/latest/download"
RAW = f"https://raw.githubusercontent.com/{REPO}/dist"
CDN = f"https://cdn.jsdelivr.net/gh/{REPO}@dist"


def fmt(n: int) -> str:
    return f"{n:,}"


def main() -> None:
    stats = json.load(open(sys.argv[1], encoding="utf-8"))
    version = sys.argv[2] if len(sys.argv) > 2 else stats["version"]
    ip, dom = stats["ip_sets"], stats["domain_sets"]
    audit = stats.get("audit", {})

    out: list[str] = []
    add = out.append

    add(f"Daily build — **{stats['generated']}**")
    add("")
    add("Every file below is attached individually. Point your client straight "
        "at a URL — no archive to unpack.")
    add("")

    add("## Stable URLs")
    add("")
    add("These always resolve to the newest build:")
    add("")
    add("```")
    add(f"{LATEST}/geoip.dat")
    add(f"{LATEST}/geosite.dat")
    add(f"{LATEST}/geoip-ir.srs")
    add(f"{LATEST}/ir-domain.mrs")
    add(f"{LATEST}/ir-ipv4-reset.rsc")
    add("```")
    add("")
    add(f"Mirrors: [`dist` branch]({RAW}/xray/geoip.dat) · "
        f"[jsDelivr CDN]({CDN}/xray/geoip.dat) — the CDN is usually reachable "
        "from Iran when `raw.githubusercontent.com` is not.")
    add("")

    add("## Contents")
    add("")
    add("| Set | Kind | Entries |")
    add("|---|---|---|")
    add(f"| `ir` | IPv4 prefixes | {fmt(ip['ir']['ipv4'])} |")
    add(f"| `ir` | IPv6 prefixes | {fmt(ip['ir']['ipv6'])} |")
    add(f"| `ir` | domains | {fmt(dom['ir']['suffix'] + dom['ir']['full'])} |")
    add(f"| `ir-cdn` | Iranian CDN prefixes | "
        f"{fmt(ip['ir-cdn']['ipv4'] + ip['ir-cdn']['ipv6'])} |")
    for key, label in (("ads", "advertising / tracking"),
                       ("malware", "malware"), ("phishing", "phishing"),
                       ("cryptominers", "cryptominers"),
                       ("nsfw", "adult / gambling")):
        if key in dom:
            add(f"| `{key}` | {label} domains | "
                f"{fmt(dom[key]['suffix'] + dom[key]['full'])} |")
    for key in ("malware", "phishing"):
        if key in ip:
            add(f"| `{key}` | threat IPs | {fmt(ip[key]['ipv4'] + ip[key]['ipv6'])} |")
    add("")

    add("## Iranian IP provenance")
    add("")
    add("Addresses come from the Regional Internet Registries' own delegation "
        "records. An address is Iranian only if a RIR delegated it to an "
        "organisation registered in Iran — no geolocation guessing.")
    add("")
    for label in ("ipverse", "ipdeny"):
        xc = audit.get(f"crosscheck_{label}")
        if xc:
            add(f"- Cross-checked against **{label}**, an independent parse of "
                f"the same registry data: {fmt(xc['exact_prefix_matches'])} "
                f"identical prefixes, coverage ratio "
                f"{xc['address_coverage_ratio']}.")
    if audit.get("foreign_cloud_excluded"):
        add(f"- Cloudflare, AWS, Google, Fastly and G-Core ranges subtracted "
            f"({fmt(audit.get('foreign_cloud_overlap_addresses', 0))} addresses).")
    add("- Iranian CDN ranges ship separately as `ir-cdn` — those published "
        "lists include edge nodes outside Iran. `ir-full` is the union.")
    add("")

    add("## Quick start")
    add("")
    add("<details><summary><b>Xray / v2ray</b></summary>")
    add("")
    add("```bash")
    add(f"curl -sfLO {LATEST}/geoip.dat")
    add(f"curl -sfLO {LATEST}/geosite.dat")
    add("```")
    add("")
    add("Use `geoip:ir`, `geosite:ir`, `geosite:ads`, `geoip:malware`. "
        "`geosite:category-ads-all` is present as an alias for existing configs. "
        "A ready-made rule block is attached as `xray-routing-rules.json`.")
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
    add("    interval: 86400")
    add(f"    url: {RAW}/mihomo/ir-domain.mrs")
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
    add(f"`{RAW}/mikrotik/auto-update.rsc` installs a daily scheduler with a "
        "size guard, so a truncated download cannot wipe your address list.")
    add("</details>")
    add("")

    add("## Verifying")
    add("")
    add("```bash")
    add(f"curl -sfLO {LATEST}/SHA256SUMS")
    add("sha256sum -c SHA256SUMS --ignore-missing")
    add("```")

    failed = stats.get("sources_failed") or {}
    if failed:
        add("")
        add("## Degraded sources")
        add("")
        add("Unreachable this build; affected sets fall back to their "
            "remaining sources:")
        add("")
        for key, err in sorted(failed.items()):
            add(f"- `{key}` — {str(err)[:120]}")

    print("\n".join(out))


if __name__ == "__main__":
    main()
