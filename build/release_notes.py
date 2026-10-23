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

# jsDelivr will not serve a file larger than this from a GitHub repository
JSDELIVR_LIMIT = 20_000_000

RIS_ATTRIBUTION = "Contains RIPE NCC RIS data © RIPE NCC."

# a source in either state was served as it should be; anything else is health
SERVED = ("fresh", "not-modified")


def fmt(n: int) -> str:
    return f"{n:,}"


def count(sets: dict, key: str, *fields: str) -> int | None:
    """Sum of `fields` of one set's stats, or None if the set is not there."""
    entry = sets.get(key)
    if not isinstance(entry, dict):
        return None
    return sum(entry.get(field, 0) for field in fields)


def cell(text, limit: int | None = None) -> str:
    """Text safe inside a markdown table cell: cut, then `|` and newlines."""
    text = str(text or "")[:limit]
    return text.replace("\r", "").replace("\n", " ").replace("|", "\\|")


def health_rows(sources: dict) -> list[str]:
    """One table row per source that was not served fresh or not-modified."""
    rows = []
    for key, src in sources.items():
        if not isinstance(src, dict) or src.get("status") in SERVED:
            continue
        status = src.get("status") or "unknown"
        age = float(src.get("stale_days") or 0)
        # a dropped source with nothing stored has no age, only a 0.0 default
        shown = "—" if status == "dropped" and age == 0 else f"{age:.1f}"
        rows.append(f"| `{key}` | {cell(status)} | "
                    f"{cell(src.get('served_by')) or '—'} | {shown} | "
                    f"{cell(src.get('error'), 120)} |")
    return rows


def render(stats: dict, version: str) -> str:
    """The release notes, as markdown, for a stats.json.

    Whatever depends on a field added after the first schema is left out when
    that field is missing, so an old stats.json still renders. `version` is
    the release tag; the notes are dated by the build time in `stats`.
    """
    ip, dom = stats.get("ip_sets", {}), stats.get("domain_sets", {})
    audit = stats.get("audit") or {}
    bgp = audit.get("bgp") or {}
    sources = stats.get("sources") or {}

    out: list[str] = []
    add = out.append

    add(f"Daily build — **{stats.get('generated', '')}**")
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
    dat_bytes = audit.get("geosite_dat_bytes") or 0
    if dat_bytes >= JSDELIVR_LIMIT:
        add(f"> **Warning:** geosite.dat is {dat_bytes / 1e6:.1f} MB — over "
            "jsDelivr's 20 MB limit, so the CDN mirror will not serve it.")
        add("")

    add("## Contents")
    add("")
    add("| Set | Kind | Entries |")
    add("|---|---|---|")
    rows = [("ir", "IPv4 prefixes", count(ip, "ir", "ipv4")),
            ("ir", "IPv6 prefixes", count(ip, "ir", "ipv6")),
            ("ir", "domains", count(dom, "ir", "suffix", "full")),
            ("ir-cdn", "Iranian CDN prefixes",
             count(ip, "ir-cdn", "ipv4", "ipv6"))]
    for key, label in (("ads", "advertising / tracking"),
                       ("malware", "malware"), ("phishing", "phishing"),
                       ("cryptominers", "cryptominers"),
                       ("nsfw", "adult / gambling")):
        rows.append((key, f"{label} domains",
                     count(dom, key, "suffix", "full")))
    for key in ("malware", "phishing"):
        rows.append((key, "threat IPs", count(ip, key, "ipv4", "ipv6")))
    for key, kind, entries in rows:
        if entries is not None:
            add(f"| `{key}` | {kind} | {fmt(entries)} |")
    add("")

    add("## Iranian IP provenance")
    add("")
    add("Addresses start from the Regional Internet Registries' own delegation "
        "records. An address is Iranian only if a RIR delegated it to an "
        "organisation registered in Iran — no geolocation guessing.")
    add("")
    if bgp.get("applied"):
        add(f"- Adjusted with BGP routing data from RIPE NCC RIS "
            f"({fmt(bgp.get('ir_asns', 0))} Iranian ASNs): added "
            f"{fmt(bgp.get('added_addresses', 0))} addresses "
            f"({fmt(bgp.get('added_prefixes', 0))} prefixes) that Iranian "
            f"networks announce outside the registry's delegations, removed "
            f"{fmt(bgp.get('removed_addresses', 0))} addresses "
            f"({fmt(bgp.get('removed_prefixes', 0))} prefixes) inside them "
            f"that only foreign networks announce, on "
            f"{fmt(bgp.get('registry_addresses', 0))} registry IPv4 addresses.")
    else:
        add("- No BGP adjustment: routing data was unavailable for this "
            "build, so `ir` is registry-only.")
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
    providers = audit.get("providers") or {}
    if providers:
        listed = " · ".join(f"{name} {fmt(info.get('addresses', 0))}"
                            for name, info in providers.items()
                            if isinstance(info, dict))
        add(f"- `ir-cdn` is each provider's published list plus the prefixes "
            f"its own ASNs announce (IPv4 addresses): {listed}.")
    add("")

    health = health_rows(sources)
    if health:
        add("## Source health")
        add("")
        add("Not served fresh this build; affected sets fall back to the last "
            "validated copy, or to their remaining sources:")
        add("")
        add("| Source | Status | Served by | Age (days) | Error |")
        add("|---|---|---|---|---|")
        out.extend(health)
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

    # RIS data is in this build if the adjustment ran, or if any RIS source
    # was not dropped (a stored copy is still RIS data)
    if bgp.get("applied") or any(
            key.startswith("ris-") and isinstance(src, dict) and
            src.get("status") != "dropped" for key, src in sources.items()):
        add("")
        add(RIS_ATTRIBUTION)

    return "\n".join(out)


def main() -> None:
    with open(sys.argv[1], encoding="utf-8") as fh:
        stats = json.load(fh)
    version = sys.argv[2] if len(sys.argv) > 2 else stats["version"]
    print(render(stats, version))


if __name__ == "__main__":
    main()
