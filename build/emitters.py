#!/usr/bin/env python3
"""
emitters.py — one function per output format.

Every emitter takes a normalised ``IPSet`` or ``DomainSet`` plus a
``BuildContext`` and writes files under ``ctx.outdir``, recording each one in
the manifest. Emitters never mutate the dataset.

A dataset carries a *role* which decides intent, because the same domain list
means different things in different places:

    direct  Iranian services — route directly, resolve with an Iranian DNS
    block   ads / malware / phishing / cryptominers / nsfw — sinkhole
    proxy   sites that block Iran — force through the proxy
    plain   reference data (private ranges, CDN ranges) — lists only

Formats that cannot represent a match type drop what they cannot express and
the count is reported, rather than silently emitting something that means
something else.

Match-type equivalence used throughout (verified against each implementation):

    our `suffix`   == Xray `domain:x`      == sing-box `domain_suffix: x`
                   == Clash `+.x`          == Surge `DOMAIN-SUFFIX,x`
    our `full`     == Xray `full:x`        == sing-box `domain: x`
                   == Clash `x`            == Surge `DOMAIN,x`
    our `keyword`  == Xray `keyword:x`     == sing-box `domain_keyword`
    our `regex`    == Xray `regexp:x`      == sing-box `domain_regex`
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from model import DomainSet, IPSet

PROJECT = "https://github.com/Arman2122/IR-Geo-DB"


@dataclass
class BuildContext:
    outdir: str
    timestamp: str
    version: str
    resolver: str = "178.22.122.100"          # Shecan, an Iranian resolver
    resolver_alt: str = "10.202.10.10"        # Radar
    manifest: list = field(default_factory=list)

    def path(self, relpath: str) -> str:
        full = os.path.join(self.outdir, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        return full

    def record(self, relpath: str, entries: int, note: str = "") -> None:
        self.manifest.append({"file": relpath.replace(os.sep, "/"),
                              "entries": entries, "note": note})


def header(ctx: BuildContext, title: str, count: int, sources, comment="#") -> str:
    src = ", ".join(sources) if sources else "n/a"
    lines = [
        f"{title}",
        f"Entries: {count}",
        f"Built:   {ctx.timestamp}   Release: {ctx.version}",
        f"Sources: {src}",
        f"Project: {PROJECT}",
    ]
    return "".join(f"{comment} {ln}\n" for ln in lines) + comment + "\n"


def write_lines(ctx: BuildContext, relpath: str, lines, title: str, count: int,
                sources, comment="#", note="") -> None:
    body = header(ctx, title, count, sources, comment) + "\n".join(lines)
    if body and not body.endswith("\n"):
        body += "\n"
    with open(ctx.path(relpath), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    ctx.record(relpath, count, note)


def write_json(ctx: BuildContext, relpath: str, obj, count: int, note="") -> None:
    with open(ctx.path(relpath), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    ctx.record(relpath, count, note)


# =============================================================== IP emitters


def ip_text(ctx: BuildContext, s: IPSet) -> None:
    """Plain CIDR per line. Also the pfSense/OPNsense URL-table format."""
    if s.v4:
        write_lines(ctx, f"text/{s.slug}-ipv4.txt", [str(n) for n in s.v4],
                    f"{s.title} — IPv4 CIDR", len(s.v4), s.sources)
    if s.v6:
        write_lines(ctx, f"text/{s.slug}-ipv6.txt", [str(n) for n in s.v6],
                    f"{s.title} — IPv6 CIDR", len(s.v6), s.sources)
    write_lines(ctx, f"text/{s.slug}-all.txt",
                [str(n) for n in s.all_networks()],
                f"{s.title} — all CIDR", s.total, s.sources)


def ip_mikrotik(ctx: BuildContext, s: IPSet) -> None:
    """RouterOS address-lists, in append and replace variants.

    The ``-reset`` file removes only ``dynamic=no`` entries first, so a
    re-import replaces the static geo data while leaving entries that DNS
    static rules populated dynamically untouched.
    """
    listname = s.slug.upper().replace("-", "_")
    for ver, nets, root in (("ipv4", s.v4, "/ip"), ("ipv6", s.v6, "/ipv6")):
        if not nets:
            continue
        adds = [f"add address={n} list={listname}" for n in nets]
        write_lines(ctx, f"mikrotik/{s.slug}-{ver}.rsc",
                    [f"{root} firewall address-list"] + adds,
                    f"{s.title} — RouterOS {ver} address-list {listname} (append)",
                    len(nets), s.sources)
        write_lines(ctx, f"mikrotik/{s.slug}-{ver}-reset.rsc",
                    [f"{root} firewall address-list",
                     f"remove [find list={listname} dynamic=no]"] + adds,
                    f"{s.title} — RouterOS {ver} address-list {listname} (replace)",
                    len(nets), s.sources)


def ip_ipset(ctx: BuildContext, s: IPSet) -> None:
    """``ipset restore`` input — covers iptables users."""
    lines = []
    if s.v4:
        lines.append(f"create {s.slug}-v4 hash:net family inet -exist")
        lines.append(f"flush {s.slug}-v4")
        lines += [f"add {s.slug}-v4 {n} -exist" for n in s.v4]
    if s.v6:
        lines.append(f"create {s.slug}-v6 hash:net family inet6 -exist")
        lines.append(f"flush {s.slug}-v6")
        lines += [f"add {s.slug}-v6 {n} -exist" for n in s.v6]
    write_lines(ctx, f"ipset/{s.slug}.ipset", lines,
                f"{s.title} — ipset restore", s.total, s.sources)


def _nft_elements(nets, indent="      ") -> list[str]:
    """Wrap a big element list; one very long line is legal but unreadable."""
    out, row = [], []
    for n in nets:
        row.append(str(n))
        if len(row) == 8:
            out.append(indent + ", ".join(row) + ",")
            row = []
    if row:
        out.append(indent + ", ".join(row))
    elif out:
        out[-1] = out[-1].rstrip(",")
    return out


def ip_nftables(ctx: BuildContext, s: IPSet) -> None:
    name = s.slug.replace("-", "_")
    lines = ["table inet geo {"]
    for ver, nets, typ in (("v4", s.v4, "ipv4_addr"), ("v6", s.v6, "ipv6_addr")):
        if not nets:
            continue
        lines += [f"  set {name}_{ver} {{", f"    type {typ}",
                  "    flags interval", "    auto-merge", "    elements = {"]
        lines += _nft_elements(nets)
        lines += ["    }", "  }"]
    lines.append("}")
    write_lines(ctx, f"nftables/{s.slug}.nft", lines,
                f"{s.title} — nftables sets", s.total, s.sources)


def ip_clash(ctx: BuildContext, s: IPSet) -> None:
    """Clash / Mihomo ipcidr rule-provider, yaml and text payloads.

    The ``.list`` text form is also what ``mihomo convert-ruleset`` compiles
    into ``.mrs``.
    """
    nets = [str(n) for n in s.all_networks()]
    write_lines(ctx, f"clash/{s.slug}-ip.yaml",
                ["payload:"] + [f"  - '{n}'" for n in nets],
                f"{s.title} — Clash ipcidr rule-provider", len(nets), s.sources)
    write_lines(ctx, f"clash/{s.slug}-ip.list", nets,
                f"{s.title} — Clash ipcidr rule-provider (text)",
                len(nets), s.sources)


def ip_singbox_source(ctx: BuildContext, s: IPSet) -> None:
    """sing-box headless rule-set source, compiled to .srs by the build."""
    obj = {"version": 1, "rules": [{"ip_cidr": [str(n) for n in s.all_networks()]}]}
    write_json(ctx, f"sing-box/source/geoip-{s.slug}.json", obj, s.total)


def ip_surge(ctx: BuildContext, s: IPSet, role: str) -> None:
    policy = {"block": "REJECT", "proxy": "PROXY"}.get(role, "DIRECT")
    lines = [f"IP-CIDR,{n},no-resolve" for n in s.v4]
    lines += [f"IP-CIDR6,{n},no-resolve" for n in s.v6]
    write_lines(ctx, f"surge/{s.slug}-ip.list", lines,
                f"{s.title} — Surge / Loon rule list", s.total, s.sources)
    qx = [f"IP-CIDR,{n},{policy}" for n in s.v4]
    qx += [f"IP6-CIDR,{n},{policy}" for n in s.v6]
    write_lines(ctx, f"quantumultx/{s.slug}-ip.list", qx,
                f"{s.title} — Quantumult X filter ({policy})", s.total, s.sources)


def ip_wireguard(ctx: BuildContext, s: IPSet) -> None:
    """A single AllowedIPs value — split tunnelling straight into wg-quick."""
    nets = ", ".join(str(n) for n in s.all_networks())
    write_lines(ctx, f"wireguard/{s.slug}-allowedips.conf",
                [f"AllowedIPs = {nets}"],
                f"{s.title} — WireGuard AllowedIPs", s.total, s.sources)


def ip_json(ctx: BuildContext, s: IPSet) -> None:
    write_json(ctx, f"json/{s.slug}-ip.json", {
        "set": s.slug, "title": s.title, "sources": s.sources,
        "generated": ctx.timestamp, "version": ctx.version,
        "ipv4": [str(n) for n in s.v4], "ipv6": [str(n) for n in s.v6],
    }, s.total)


IP_EMITTERS = [ip_text, ip_mikrotik, ip_ipset, ip_nftables, ip_clash,
               ip_singbox_source, ip_wireguard, ip_json]


# =========================================================== domain emitters


def dom_text(ctx: BuildContext, d: DomainSet) -> None:
    plain = d.plain_domains()
    write_lines(ctx, f"text/{d.slug}-domains.txt", plain,
                f"{d.title} — domains", len(plain), d.sources,
                note=f"{d.unrepresentable()} keyword/regex rules omitted"
                if d.unrepresentable() else "")
    if d.keyword:
        write_lines(ctx, f"text/{d.slug}-keywords.txt", sorted(d.keyword),
                    f"{d.title} — keywords", len(d.keyword), d.sources)
    if d.regex:
        write_lines(ctx, f"text/{d.slug}-regex.txt", sorted(d.regex),
                    f"{d.title} — regular expressions", len(d.regex), d.sources)


def dom_singbox_source(ctx: BuildContext, d: DomainSet) -> None:
    rule = {}
    if d.full:
        rule["domain"] = sorted(d.full)
    if d.suffix:
        rule["domain_suffix"] = sorted(d.suffix)
    if d.keyword:
        rule["domain_keyword"] = sorted(d.keyword)
    if d.regex:
        rule["domain_regex"] = sorted(d.regex)
    write_json(ctx, f"sing-box/source/geosite-{d.slug}.json",
               {"version": 1, "rules": [rule] if rule else []}, d.total)


def dom_clash(ctx: BuildContext, d: DomainSet) -> None:
    """Clash / Mihomo domain rule-provider.

    ``+.x`` is Clash's suffix form (x and all subdomains); a bare ``x`` is an
    exact match. Keywords and regexes have no place in a ``domain``-behaviour
    provider, so they go to a separate classical-behaviour file instead.
    """
    payload = [f"+.{n}" for n in sorted(d.suffix)] + sorted(d.full)
    write_lines(ctx, f"clash/{d.slug}-domain.yaml",
                ["payload:"] + [f"  - '{p}'" for p in payload],
                f"{d.title} — Clash domain rule-provider", len(payload), d.sources)
    write_lines(ctx, f"clash/{d.slug}-domain.list", payload,
                f"{d.title} — Clash domain rule-provider (text)",
                len(payload), d.sources)

    if d.keyword or d.regex:
        classical = [f"DOMAIN-SUFFIX,{n}" for n in sorted(d.suffix)]
        classical += [f"DOMAIN,{n}" for n in sorted(d.full)]
        classical += [f"DOMAIN-KEYWORD,{k}" for k in sorted(d.keyword)]
        classical += [f"DOMAIN-REGEX,{r}" for r in sorted(d.regex)]
        write_lines(ctx, f"clash/{d.slug}-classical.yaml",
                    ["payload:"] + [f"  - '{c}'" for c in classical],
                    f"{d.title} — Clash classical rule-provider",
                    len(classical), d.sources)


def dom_surge(ctx: BuildContext, d: DomainSet, role: str) -> None:
    policy = {"block": "REJECT", "proxy": "PROXY"}.get(role, "DIRECT")
    rules = [f"DOMAIN-SUFFIX,{n}" for n in sorted(d.suffix)]
    rules += [f"DOMAIN,{n}" for n in sorted(d.full)]
    rules += [f"DOMAIN-KEYWORD,{k}" for k in sorted(d.keyword)]
    write_lines(ctx, f"surge/{d.slug}-domain.list", rules,
                f"{d.title} — Surge / Loon rule list", len(rules), d.sources)

    # Surge DOMAIN-SET: a bare domain is exact, a leading dot is the suffix
    dset = [f".{n}" for n in sorted(d.suffix)] + sorted(d.full)
    write_lines(ctx, f"surge/{d.slug}-domainset.txt", dset,
                f"{d.title} — Surge DOMAIN-SET", len(dset), d.sources)

    qx = [f"HOST-SUFFIX,{n},{policy}" for n in sorted(d.suffix)]
    qx += [f"HOST,{n},{policy}" for n in sorted(d.full)]
    qx += [f"HOST-KEYWORD,{k},{policy}" for k in sorted(d.keyword)]
    write_lines(ctx, f"quantumultx/{d.slug}-domain.list", qx,
                f"{d.title} — Quantumult X filter ({policy})", len(qx), d.sources)


# ---- blocking-only outputs -------------------------------------------------


def dom_hosts(ctx: BuildContext, d: DomainSet) -> None:
    plain = d.plain_domains()
    note = (f"{d.unrepresentable()} keyword/regex rules cannot be expressed "
            "in hosts format") if d.unrepresentable() else ""
    body = [f"0.0.0.0 {n}" for n in plain]
    write_lines(ctx, f"hosts/{d.slug}.txt", body,
                f"{d.title} — hosts blocklist", len(plain), d.sources, note=note)
    # RouterOS 7.15+ /ip dns adlist reads the same hosts format
    write_lines(ctx, f"mikrotik/adlist-{d.slug}.txt", body,
                f"{d.title} — RouterOS adlist", len(plain), d.sources, note=note)


def dom_adguard(ctx: BuildContext, d: DomainSet) -> None:
    """AdGuard Home / AdGuard DNS filter syntax."""
    rules = [f"||{n}^" for n in d.plain_domains()]
    rules += [f"/{r}/" for r in sorted(d.regex)]
    write_lines(ctx, f"adguard/{d.slug}.txt", rules,
                f"{d.title} — AdGuard DNS filter", len(rules), d.sources)


def dom_rpz(ctx: BuildContext, d: DomainSet) -> None:
    """BIND / Knot / PowerDNS Response Policy Zone returning NXDOMAIN."""
    serial = ctx.version.replace(".", "").replace("v", "")[:10] or "1"
    lines = ["$TTL 60",
             f"@ IN SOA localhost. root.localhost. ({serial} 3600 600 86400 60)",
             "  IN NS localhost.", ""]
    for n in d.plain_domains():
        lines.append(f"{n} CNAME .")
        lines.append(f"*.{n} CNAME .")
    write_lines(ctx, f"rpz/{d.slug}.zone", lines,
                f"{d.title} — RPZ zone (NXDOMAIN)", len(d.plain_domains()),
                d.sources, comment=";")


def dom_dnsmasq_block(ctx: BuildContext, d: DomainSet) -> None:
    write_lines(ctx, f"dnsmasq/{d.slug}-block.conf",
                [f"address=/{n}/0.0.0.0" for n in d.plain_domains()],
                f"{d.title} — dnsmasq sinkhole", len(d.plain_domains()), d.sources)


def dom_unbound_block(ctx: BuildContext, d: DomainSet) -> None:
    lines = ["server:"] + [f'  local-zone: "{n}." always_nxdomain'
                           for n in d.plain_domains()]
    write_lines(ctx, f"unbound/{d.slug}-block.conf", lines,
                f"{d.title} — Unbound NXDOMAIN zones",
                len(d.plain_domains()), d.sources)


def dom_smartdns_block(ctx: BuildContext, d: DomainSet) -> None:
    write_lines(ctx, f"smartdns/{d.slug}-block.conf",
                [f"address /{n}/#" for n in d.plain_domains()],
                f"{d.title} — SmartDNS block", len(d.plain_domains()), d.sources)


# ---- direct-routing outputs ------------------------------------------------


def dom_mikrotik_dns(ctx: BuildContext, d: DomainSet) -> None:
    """RouterOS static DNS: forward to an Iranian resolver *and* learn the IP.

    ``address-list=`` on a ``type=FWD`` entry writes every resolved address
    into that address list dynamically. That is what catches Iranian services
    sitting behind a foreign CDN — no IP list can know about those in advance.
    """
    listname = d.slug.upper().replace("-", "_")
    lines = ["/ip dns static"]
    for n in sorted(d.suffix):
        lines.append(f"add type=FWD name={n} match-subdomain=yes "
                     f"forward-to={ctx.resolver} address-list={listname} ttl=1d")
    for n in sorted(d.full):
        lines.append(f"add type=FWD name={n} "
                     f"forward-to={ctx.resolver} address-list={listname} ttl=1d")
    count = len(d.suffix) + len(d.full)
    note = (f"{len(d.regex)} regex rules omitted — RouterOS uses POSIX regex, "
            "not RE2") if d.regex else ""
    write_lines(ctx, f"mikrotik/{d.slug}-dns.rsc", lines,
                f"{d.title} — RouterOS DNS forwarders + {listname} address-list",
                count, d.sources, note=note)


def dom_dnsmasq_route(ctx: BuildContext, d: DomainSet) -> None:
    write_lines(ctx, f"dnsmasq/{d.slug}-route.conf",
                [f"server=/{n}/{ctx.resolver}" for n in d.plain_domains()],
                f"{d.title} — dnsmasq split DNS via {ctx.resolver}",
                len(d.plain_domains()), d.sources)


def dom_unbound_route(ctx: BuildContext, d: DomainSet) -> None:
    lines = []
    for n in d.plain_domains():
        lines += ["forward-zone:", f'  name: "{n}."',
                  f"  forward-addr: {ctx.resolver}", ""]
    write_lines(ctx, f"unbound/{d.slug}-route.conf", lines,
                f"{d.title} — Unbound forward zones via {ctx.resolver}",
                len(d.plain_domains()), d.sources)


def dom_smartdns_route(ctx: BuildContext, d: DomainSet) -> None:
    lines = [f"server {ctx.resolver} -group iran -exclude-default-group"]
    lines += [f"nameserver /{n}/iran" for n in d.plain_domains()]
    write_lines(ctx, f"smartdns/{d.slug}-route.conf", lines,
                f"{d.title} — SmartDNS group routing",
                len(d.plain_domains()), d.sources)


DOMAIN_EMITTERS_COMMON = [dom_text, dom_singbox_source, dom_clash]
DOMAIN_EMITTERS_BLOCK = [dom_hosts, dom_adguard, dom_rpz, dom_dnsmasq_block,
                         dom_unbound_block, dom_smartdns_block]
DOMAIN_EMITTERS_DIRECT = [dom_mikrotik_dns, dom_dnsmasq_route,
                          dom_unbound_route, dom_smartdns_route]

# Emitting every format for every set produces roughly 700 MiB, most of it
# the same domains rewritten with different punctuation. Above this many
# entries a set only gets the formats people actually point a resolver at;
# the verbose ones (RPZ writes two lines per domain, Unbound writes a stanza)
# are skipped and noted in the manifest.
LARGE_SET = 100_000

# The union set exists so a router can be given a single URL. Anyone using
# Clash, sing-box or Surge references the individual rule-sets instead, which
# is the entire point of rule-sets — so it does not need those formats.
AGGREGATE_EMITTERS = [dom_text, dom_hosts, dom_adguard, dom_dnsmasq_block]


# ================================================================ dispatch


def emit_ipset(ctx: BuildContext, s: IPSet, role: str) -> None:
    for fn in IP_EMITTERS:
        fn(ctx, s)
    ip_surge(ctx, s, role)


def emit_domainset(ctx: BuildContext, d: DomainSet, role: str,
                   profile: str = "auto") -> str:
    """Run the emitters appropriate to this set. Returns the profile used."""
    if profile == "auto":
        profile = "large" if d.total >= LARGE_SET else "full"

    if profile == "aggregate":
        for fn in AGGREGATE_EMITTERS:
            fn(ctx, d)
        dom_mikrotik_adlist_only(ctx, d)
        return profile

    for fn in DOMAIN_EMITTERS_COMMON:
        fn(ctx, d)
    if role == "block":
        emitters_for_role = DOMAIN_EMITTERS_BLOCK
    elif role == "direct":
        emitters_for_role = DOMAIN_EMITTERS_DIRECT
    else:
        emitters_for_role = []

    verbose = {dom_rpz, dom_unbound_block, dom_smartdns_block,
               dom_unbound_route, dom_smartdns_route}
    for fn in emitters_for_role:
        if profile == "large" and fn in verbose:
            continue
        fn(ctx, d)

    if profile == "full":
        dom_surge(ctx, d, role)
    else:
        # keep the compact DOMAIN-SET form, drop the per-rule listings
        dset = [f".{n}" for n in sorted(d.suffix)] + sorted(d.full)
        write_lines(ctx, f"surge/{d.slug}-domainset.txt", dset,
                    f"{d.title} — Surge DOMAIN-SET", len(dset), d.sources)
    return profile


def dom_mikrotik_adlist_only(ctx: BuildContext, d: DomainSet) -> None:
    body = [f"0.0.0.0 {n}" for n in d.plain_domains()]
    write_lines(ctx, f"mikrotik/adlist-{d.slug}.txt", body,
                f"{d.title} — RouterOS adlist", len(d.plain_domains()), d.sources)
