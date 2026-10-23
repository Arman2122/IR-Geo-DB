<h1 align="center">IR-Geo-DB</h1>

<p align="center">
  Iranian routing and filtering data, rebuilt daily, in every format your client speaks.
</p>

<p align="center">
  <a href="https://github.com/Arman2122/IR-Geo-DB/actions/workflows/build.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/Arman2122/IR-Geo-DB/build.yml?branch=main&style=flat-square&logo=github&label=daily%20build"></a>
  <a href="https://github.com/Arman2122/IR-Geo-DB/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/Arman2122/IR-Geo-DB?style=flat-square&color=success"></a>
  <a href="https://github.com/Arman2122/IR-Geo-DB/releases/latest"><img alt="Updated" src="https://img.shields.io/github/release-date/Arman2122/IR-Geo-DB?display_date=published_at&style=flat-square&label=updated"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Arman2122/IR-Geo-DB?style=flat-square&color=blue"></a>
</p>

---

Xray, sing-box, Mihomo, MikroTik, dnsmasq, Unbound, AdGuard, Surge, nftables —
one build, every format, updated every day. Iranian IP data is worked out here
from the Regional Internet Registries and RIPE NCC routing data, not taken from
a geolocation guess or someone else's list.

## Download

Every file is a **direct download**. Nothing is zipped — clients fetch a URL.

Three mirrors, same content:

| Mirror | URL pattern |
|---|---|
| **Release** (versioned) | `https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/<file>` |
| **`dist` branch** | `https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/<path>` |
| **jsDelivr CDN** | `https://cdn.jsdelivr.net/gh/Arman2122/IR-Geo-DB@dist/<path>` |

`releases/latest/download/` always resolves to the newest build — the URL never
changes, so you set it once.

**From inside Iran**, prefer jsDelivr: `raw.githubusercontent.com` is commonly
blocked. jsDelivr refuses files over 20 MB; the largest file here is
`geosite.dat` at about 13 MB, and the release notes warn if it ever reaches the
limit.

**On a router**, prefer the `dist` branch. Release URLs redirect through
`objects.githubusercontent.com` and RouterOS `/tool fetch` does not reliably
follow redirects.

## Quick start

<details open>
<summary><b>Xray / v2ray</b></summary>

```bash
curl -sfLO https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/geoip.dat
curl -sfLO https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/geosite.dat
```

Put both next to the core binary or in its asset directory.

```json
"routing": {
  "domainStrategy": "IPIfNonMatch",
  "rules": [
    { "type": "field", "outboundTag": "block",
      "domain": ["geosite:ads", "geosite:malware", "geosite:phishing", "geosite:cryptominers"] },
    { "type": "field", "outboundTag": "block",
      "ip": ["geoip:malware", "geoip:phishing"] },
    { "type": "field", "outboundTag": "direct", "domain": ["geosite:ir"] },
    { "type": "field", "outboundTag": "direct", "ip": ["geoip:ir", "geoip:private"] }
  ]
}
```

`geosite:category-ads-all` works too, as an alias for existing configs.

On phones, `geoip-lite.dat` and `geosite-lite.dat` carry only the Iranian sets.
</details>

<details>
<summary><b>sing-box</b></summary>

```json
"route": {
  "rules": [
    { "rule_set": ["geosite-ads", "geosite-malware", "geosite-phishing"], "action": "reject" },
    { "rule_set": ["geosite-ir", "geoip-ir"], "outbound": "direct" }
  ],
  "rule_set": [
    { "type": "remote", "tag": "geosite-ir", "format": "binary",
      "url": "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/sing-box/rule-set/geosite-ir.srs",
      "download_detour": "direct", "update_interval": "1d" },
    { "type": "remote", "tag": "geoip-ir", "format": "binary",
      "url": "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/sing-box/rule-set/geoip-ir.srs",
      "download_detour": "direct", "update_interval": "1d" },
    { "type": "remote", "tag": "geosite-ads", "format": "binary",
      "url": "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/sing-box/rule-set/geosite-ads.srs",
      "download_detour": "direct", "update_interval": "1d" },
    { "type": "remote", "tag": "geosite-malware", "format": "binary",
      "url": "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/sing-box/rule-set/geosite-malware.srs",
      "download_detour": "direct", "update_interval": "1d" },
    { "type": "remote", "tag": "geosite-phishing", "format": "binary",
      "url": "https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/sing-box/rule-set/geosite-phishing.srs",
      "download_detour": "direct", "update_interval": "1d" }
  ]
}
```

Rule-sets are compiled at format version 1, so they load on sing-box 1.8 and
later; the `"action": "reject"` rule above needs sing-box 1.11 or later. The
same block ships as `sing-box/config-snippet.json`, and the JSON sources are
in `sing-box/source/`.
</details>

<details>
<summary><b>Mihomo / Clash.Meta</b></summary>

```yaml
rule-providers:
  ir-domain:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    url: https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mihomo/ir-domain.mrs
    path: ./ruleset/ir-domain.mrs
  ir-ip:
    type: http
    behavior: ipcidr
    format: mrs
    interval: 86400
    url: https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mihomo/ir-ip.mrs
    path: ./ruleset/ir-ip.mrs

rules:
  - RULE-SET,ir-domain,DIRECT
  - RULE-SET,ir-ip,DIRECT,no-resolve
  - MATCH,PROXY
```

Clients without `.mrs` support can use the YAML providers in `clash/` with
`format: yaml`.
</details>

<details>
<summary><b>MikroTik RouterOS</b></summary>

Address-list:

```
/tool fetch mode=https dst-path=ir.rsc \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/ir-ipv4-reset.rsc"
/import file-name=ir.rsc
```

`-reset` removes only `dynamic=no` entries first, replacing the static geo data
while leaving DNS-populated dynamic entries alone. `ir-ipv4.rsc` appends
instead.

Self-updating — paste once, it maintains itself and refuses to import a
truncated download:

```
/tool fetch mode=https dst-path=setup.rsc \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/auto-update.rsc"
/import file-name=setup.rsc
```

Split DNS. Each entry forwards the domain to an Iranian resolver *and* writes
every resolved address into the `IR` address list — which is how Iranian
services behind a foreign CDN get caught, something no static IP list can do:

```
/tool fetch mode=https dst-path=ir-dns.rsc \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/ir-dns.rsc"
/import file-name=ir-dns.rsc
```

> **This one is big — check your device first.** `ir-dns.rsc` is ~57,500
> static DNS entries and roughly 6 MB. That is fine on an RB5009, CCR or any
> device with 512 MB+, but it will exhaust a hAP ax² / hEX / RB750 and can
> take several minutes to import. On small hardware, skip it and use the IP
> address-list alone, or use this single rule, which covers the entire `.ir`
> TLD at no memory cost:
>
> ```
> /ip dns static
> add type=FWD regexp=".*\\.ir\$" forward-to=178.22.122.100 address-list=IR ttl=1d
> ```
>
> The address-list files (`ir-ipv4.rsc`, ~1,900 entries) are small and safe
> everywhere.

Ad and threat blocking, RouterOS 7.15+:

```
/ip dns adlist add ssl-verify=yes \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/adlist-block-all.txt"
```

`adlist-block-all.txt` is over 300,000 domains. On small devices start
with `adlist-malware.txt` and `adlist-phishing.txt`, then check
`/system resource print` before adding ads.
</details>

<details>
<summary><b>DNS servers</b></summary>

```bash
# dnsmasq — sinkhole
curl -sfL -o /etc/dnsmasq.d/block.conf \
  https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/dnsmasq/block-all-block.conf

# dnsmasq — Iranian domains to an Iranian resolver
curl -sfL -o /etc/dnsmasq.d/ir.conf \
  https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/dnsmasq/ir-route.conf

# Unbound
curl -sfL -o /etc/unbound/unbound.conf.d/ir.conf \
  https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/unbound/ir-route.conf
```

**AdGuard Home** — Filters → DNS blocklists → add `.../dist/adguard/block-all.txt`.

**BIND / Knot / PowerDNS** — the `rpz/` zones return NXDOMAIN and load as a
standard response policy zone.

**SmartDNS** — `smartdns/` has both blocking and group-routing configs.
</details>

<details>
<summary><b>Firewalls</b></summary>

```bash
# nftables — sets ir_v4 / ir_v6 in table inet geo; re-running replaces their
# contents in one transaction, and your rules that use @ir_v4 keep working
curl -sfL https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/nftables/ir.nft \
  -o /etc/nftables.d/ir.nft && nft -f /etc/nftables.d/ir.nft

# ipset / iptables
curl -sfL https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/ipset/ir.ipset | ipset restore
```

`maxelem` is left at the kernel default while a set has 49,152 entries or fewer,
and fixed at 1,048,576 above that, so the `create` line stays the same from day
to day and a daily restore never trips on a resized set. If a set ever crosses
that line, destroy and reload that set once.

**pfSense / OPNsense** — Firewall → Aliases → *URL Table (IPs)* → point at
`.../dist/text/ir-ipv4.txt`, refresh daily.

**WireGuard** — `wireguard/ir-allowedips.conf` is a ready `AllowedIPs =` line
for split tunnelling.
</details>

<details>
<summary><b>Surge, Loon, Quantumult X, Shadowrocket</b></summary>

```
[Rule]
RULE-SET,https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/surge/ir-domain.list,DIRECT
RULE-SET,https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/surge/ir-ip.list,DIRECT
```

`surge/*-domainset.txt` are `DOMAIN-SET` files. Quantumult X filters in
`quantumultx/` ship with policies already attached.
</details>

## Sets

**IP** — `ir` · `ir-cdn` · `ir-full` · `private` · `malware` · `phishing`
**Domain** — `ir` · `ads` · `ads-ir` · `malware` · `phishing` · `cryptominers` · `nsfw` · `block-all`

`geoip:` and `geosite:` are separate namespaces, so `geoip:malware` (C2
addresses) and `geosite:malware` (malware domains) are different sets that
share a name on purpose.

Live counts for the current build are in
[`stats.json`](https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/stats.json).

## Formats

| Directory | Format |
|---|---|
| `xray/` | `geoip.dat`, `geosite.dat`, lite and security variants |
| `sing-box/` | compiled `.srs` + JSON sources |
| `mihomo/` | compiled `.mrs` |
| `clash/` | rule-provider YAML, `.list`, classical |
| `mikrotik/` | `.rsc` address-lists, DNS scripts, adlists |
| `dnsmasq/` | `server=/…/` routing, `address=/…/` sinkhole |
| `unbound/` | forward-zones, `always_nxdomain` zones |
| `smartdns/` | nameserver groups, `address /…/#` |
| `adguard/` | `\|\|domain^` filter syntax |
| `hosts/` | `0.0.0.0 domain` |
| `rpz/` | BIND response policy zones |
| `ipset/` | `ipset restore` |
| `nftables/` | `nft` interval sets |
| `wireguard/` | `AllowedIPs =` |
| `surge/` | rule list + `DOMAIN-SET` |
| `quantumultx/` | filters with policies |
| `text/` | plain CIDR / domain per line |

Sets past 100,000 entries skip the most verbose formats — RPZ writes two lines
per domain, Unbound a stanza each. `stats.json` records which profile each
set used, under `audit.format_profiles`.

## How an address is decided to be Iranian

Not from geolocation, and not from anyone else's list: this project works it
out. The registry says who was *given* a block; routing says who *announces* it
today. The build starts from the first and corrects it with the second.

**The registry.** An address starts in `ir` if a Regional Internet Registry
delegated it to an organisation whose registered country is `IR`. All five RIRs
are read, since an Iranian organisation can hold space from any of them.

**Routing.** The build then reads RIPE NCC's RIS routing table, and the most
specific route decides whose an address is:

- **Added:** prefixes originated by an Iran-registered ASN that the registry
  doesn't cover, such as Respina's `5.160.0.0/16`, which the registry lists
  under the UAE. A foreign more-specific route inside one of them is left out.
- **Removed:** registry space whose most specific route is originated by a
  foreign ASN, such as Iranian space leased to foreign hosts. A foreign
  *covering* route (a less-specific aggregate) never removes anything.

On 2026-10-23 that added 182,272 and removed 86,272 IPv4 addresses, leaving
10,936,064 addresses in 1,917 prefixes. A leak or a broken routing dump must
not reach you as data, so the build fails if routing would add more than 20 %
or remove more than 10 % of the registry's IPv4 addresses (it was +1.7 % and
−0.8 %). Without routing data, `ir` is registry-only.

Three more consequences, all deliberate:

**Iranian CDN and hosting ranges are separate.** See the next section.

**Foreign cloud ranges are subtracted.** Cloudflare, AWS, Google, Fastly and
G-Core publish their own prefixes; any overlap is removed from `ir`. In
practice this is near zero, which is the point — it makes a class of error
impossible rather than unlikely.

**Every build is cross-checked** against [ipverse](https://github.com/ipverse/rir-ip)
and [ipdeny](https://www.ipdeny.com), two independent parses of the same
registry data. The agreement figure appears in every release note. A
disagreement is reported, never silently merged in.

The build refuses to publish if the Iranian set falls below sane thresholds, if
a long-standing Iranian block goes missing, or if a known-foreign address such
as `8.8.8.8` turns up inside it.

## How Iranian provider ranges are built

`ir-cdn` holds the address space of Iranian hosting and CDN providers, which is
not always in Iran: ParsPack's published list includes Leaseweb and Vultr
space, and ArvanCloud's includes foreign edge nodes. It stays apart from `ir`,
and `ir-full` is the union of the two, for "everything serving Iranian traffic"
rather than "machines in Iran".

For each provider the build takes its own published list, if it publishes one,
plus every prefix announced by the networks (ASNs) that the RIPE database
registers to the provider's organisation. ASNs are looked up by organisation
handle on every build, so a network a provider registers tomorrow is picked up
without a code change. Private and bogon ranges are removed. Foreign clouds are
not subtracted, because ParsPack's real edges are on Vultr.

| Provider | RIPE organisation | Published list |
|---|---|---|
| ArvanCloud | `ORG-NAAP1-RIPE`, `ORG-NAAC1-RIPE`, `ORG-AGTL2-RIPE` | yes |
| Sotoon | `ORG-HUCC1-RIPE`, `ORG-IB117-RIPE` | none — its networks are the only source |
| Derak | `ORG-ENDC1-RIPE` | yes |
| IranServer | `ORG-GWSN7-RIPE` | yes |
| MizbanCloud | `ORG-SAML1-RIPE` | yes |
| ParsPack | none — it owns no ASN | yes, the only source |

`ir-cdn` was 87,374 IPv4 addresses on 2026-10-23. `stats.json` records each
provider's ASNs and address counts under `audit.providers`.

## Sources

Each input comes from the body that creates the data wherever GitHub's servers
can reach it, and a third-party aggregator is used only where they can't. The
licence is the upstream's own. Grouped by where each source comes from:

**Authority** — the body that creates the data.

| Source | Publisher | License | Provides |
|---|---|---|---|
| [RIR delegated statistics](https://www.nro.net/about/rirs/statistics/) | RIPE NCC, APNIC, ARIN, LACNIC, AFRINIC | Registry public data | `ir` IPs: Iranian delegations and ASNs |
| [RIPE RIS routing table](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/) | RIPE NCC | RIPE NCC RIS data (attribution required) | BGP adjustment of `ir`; provider prefixes |
| [RIPE database](https://www.ripe.net/manage-ips-and-asns/db/) | RIPE NCC | RIPE Database (public) | ASNs registered to each provider |
| [ArvanCloud](https://www.arvancloud.ir/en/dev/ips) | ArvanCloud | All rights reserved | `ir-cdn` |
| [ParsPack](https://parspack.com) | ParsPack | All rights reserved | `ir-cdn` |
| [Derak Cloud](https://derak.cloud), [IranServer](https://www.iranserver.com), [MizbanCloud](https://mizbancloud.com) | each provider | Provider-published | `ir-cdn` |
| [Public Suffix List](https://publicsuffix.org) | Mozilla | MPL-2.0 | filter only: drops foreign shared-hosting suffixes from `ir` |
| [CERT Polska warning list](https://cert.pl/en/warning-list/) | CERT Polska | free for any use | `phishing` |
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | abuse.ch | CC0 | `geoip:malware` |
| Cloudflare, AWS, Google, Google Cloud, Fastly, G-Core | respective owners | Provider-published | exclusion lists |

**Derived by this project** — computed here from the sources above and below.

| Set | Computed from |
|---|---|
| `ir` IPs | RIR registry, adjusted by RIPE RIS routing |
| `ir-cdn` | each provider's list, plus what its RIPE-registered networks announce |
| `ir-full` | `ir` and `ir-cdn` |
| `geoip:malware` | Feodo Tracker and HaGeZi's IP feed, minus private ranges, every foreign-cloud range and `ir-cdn` |
| `ir` domains | bootmortis and v2fly, with `.ir` and `.ایران` collapsed and foreign shared-hosting suffixes removed |
| `ads` | PersianBlocker and HaGeZi Light, minus AdGuard's own allowlists |

**Maintainer** — the project that curates the list.

| Source | Maintainer | License | Provides |
|---|---|---|---|
| [PersianBlocker](https://github.com/PersianBlocker/PersianBlocker) (3 domain lists) | PersianBlocker | AGPL-3.0 | `ads-ir`, `ads` |
| [HaGeZi Multi LIGHT](https://github.com/hagezi/dns-blocklists) | HaGeZi | GPL-3.0 | `ads` |
| [HaGeZi Threat Intelligence Feeds](https://github.com/hagezi/dns-blocklists#tif) (the mini domain list and the IP list) | HaGeZi | GPL-3.0 | `malware`, `geoip:malware` |
| [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) exclusions and exceptions | AdGuard | GPL-3.0 | not a blocklist: names it found to break real sites are removed from `ads` |
| [NoCoin](https://github.com/hoshsadiq/adblock-nocoin-list) | hoshsadiq | MIT | `cryptominers` |
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) (porn and gambling) | StevenBlack | MIT | `nsfw` |
| [v2fly domain-list-community](https://github.com/v2fly/domain-list-community) (`CATEGORY-IR`) | v2fly | MIT | `ir` domains |

PersianBlocker here is the maintained fork (`PersianBlocker/PersianBlocker`),
which replaced the original repository.

**Aggregator** — republishes someone else's data; used only because the
authority can't be reached.

| Source | Maintainer | License | Provides |
|---|---|---|---|
| [Iran Hosted Domains](https://github.com/bootmortis/iran-hosted-domains) | bootmortis | MIT | `ir` domains |
| [ipverse rir-ip](https://github.com/ipverse/rir-ip) | ipverse | Public domain | cross-check only |
| [ipdeny](https://www.ipdeny.com) | ipdeny | Free to use | cross-check only |

Iran Hosted Domains is kept because the government registries behind it
(enamad.ir, ito.gov.ir) time out from GitHub's servers, so they can't be read
directly. v2fly's `CATEGORY-IR` is a second, independent list, and the `.ir`
and `.ایران` rules need no source at all.

Contains RIPE NCC RIS data © RIPE NCC

**Sources we evaluated and don't use**

- **URLhaus and ThreatFox** (abuse.ch): the terms forbid derivative works. Feodo
  Tracker, also from abuse.ch, is CC0 and is used.
- **OpenPhish**: no redistribution.
- **Spamhaus DROP**: no licence granted.
- **Phishing.Database**: abandoned on 2026-10-02, and it listed whole platforms
  such as `sites.google.com` and `bit.ly`.
- **AdGuard DNS filter, as a blocklist**: it doubled the size of `ads` and blocks
  `doubleclick.net` outright. Only its allowlists are used.

Found a missing Iranian domain or a false positive? Report it to the upstream
source — fixing it there fixes it for everyone. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Set sizes vary a lot, and small does not mean broken.** `cryptominers` is a
few hundred entries because its source tracks *currently active* miners rather
than accumulating history. `geoip:malware` is Feodo Tracker plus HaGeZi's IP
feed, about 31,500 addresses on 2026-10-23 after private, cloud and `ir-cdn`
ranges are removed. `geoip:phishing` is deliberately empty: no clean, licensed
phishing IP feed exists, and an empty set is better than the previous one,
which carried Google and Cloudflare addresses. `ads` is about 70,000 domains;
`malware`, `phishing` and `nsfw` are the large ones. Live counts are always in
`stats.json`.

No blocklist may cover a shared platform such as `sites.google.com`, `bit.ly`
or `github.io`, since a suffix rule there would take down every site hosted
under it; `verify.py` refuses to publish a build that does.

## Resilience

One upstream having a bad day must not reach you as broken data.

**Mirrors.** Where a source has them, the build tries them in order: HaGeZi on
GitLab, Codeberg and jsDelivr; jsDelivr for PersianBlocker, NoCoin, StevenBlack
and AdGuard's allowlists; the Public Suffix List's GitHub mirror; two mirrors
of the Iranian domain list. Requests are conditional, so an unchanged file
costs a `304`.

**Validation.** A download is believed only after it passes. An HTML page is
rejected, and so is a file under the source's minimum size or entry count, or
one that shrank beyond its limit (half, by default) against the last good copy.
A rejected download is treated exactly like a URL that is down.

**An owned copy of every input.** Each validated input is committed to this
repository's `state` branch. If every URL for a source fails, the build uses
that stored copy, for a window set by how fast the data goes stale:

| Input | Stored copy is used for up to |
|---|---|
| Provider lists, RIPE ASN lookups | 90 days |
| Iranian domain lists, Public Suffix List, ads and nsfw lists, cloud guard ranges | 30 days |
| RIR delegations, RIS routing, cross-checks | 14 days |
| Threat feeds: malware, phishing and cryptominer lists, threat IPs | 7 days |

After its window an optional source is dropped and the set is built from what
remains. The two required sources — RIPE NCC's delegation file and the Iranian
domain list — stop the build instead, and yesterday's release stays.

**Day-over-day guard.** The build compares itself with the previous release and
refuses to publish if `ir` IPv4 addresses fall more than 5 %, `ir` domains more
than 10 %, or a blocklist more than 60 %. It skips a set whose source list
changed, and does nothing if the previous release can't be fetched. A manual
run of the workflow has an `allow_shrink` switch for use after reading why.

**Provenance.** `stats.json` records, for every source, its status (`fresh`,
`not-modified`, `stale` or `dropped`), the URL it was read from, the sha256 of
the file, dates and licence. When a source had to fall back to its stored copy
or was dropped, the release notes carry a "Source health" table.

## Design notes

**`.ir` and `.ایران` collapse to one rule each.** Every consumer here matches
subdomains, so each Iranian TLD is a single suffix entry instead of tens of
thousands of names. Around 69,500 names become two rules, and matching gets
faster.

**Shared hosting is not Iranian.** A suffix rule for `dyndns.org` or `co.com`
would route every site hosted under it, so names that are rules in the Public
Suffix List's private section are removed from `ir` (five on 2026-10-23).
`liara.run` stays: Liara is an Iranian host.

**Known false positives are removed.** Names that AdGuard's own allowlists
mark as breaking real sites are subtracted from `ads` and `ads-ir` (521 names
on 2026-10-23).

**Redundant subdomains are pruned.** If `example.com` is in a set,
`ads.example.com` is dead weight.

**Prefixes are merged.** `5.160.0.0/17` + `5.160.128.0/17` collapse to
`5.160.0.0/16`. Malformed entries are dropped and counted.

**Nothing is listed twice.** Domains are held in sets and IP prefixes are run
through interval collapsing, so an exact duplicate cannot survive. The build
then refuses to publish unless it can prove that, per file: no repeated
domain, no prefix contained inside another, no domain already covered by a
parent in the same set, no value appearing under two match types in a `.dat`
category, nothing present in both `domain` and `domain_suffix` in a sing-box
rule-set, and nothing listed as both `+.x` and `x` in a Clash provider.

**Match types survive.** sing-box, Xray, Clash and Surge all distinguish exact,
suffix, keyword and regex matches. Formats that cannot express one — hosts
files, adlists — drop what they cannot represent and record the count, rather
than emitting a rule that means something else.

**Builds fail loudly.** A required source with no usable copy, a routing
anomaly, a set that shrinks past its limit or a failed verification aborts the
run and publishes nothing; yesterday's release stays. An optional source that
fails falls back to its stored copy, and the release notes say so.

## Building it yourself

```bash
git clone https://github.com/Arman2122/IR-Geo-DB && cd IR-Geo-DB
( for t in build/test_*.py; do python3 "$t" || exit 1; done )   # offline tests
python3 build/build.py --outdir dist --cache .cache
python3 build/verify.py dist
```

Python 3.10+, standard library only. `sing-box` and `mihomo` on `PATH` (or via
`$SING_BOX` / `$MIHOMO`) add the `.srs` and `.mrs` outputs; without them
everything else still builds.

`--lkg-dir` (default `.lkg`) is where each validated input is kept between runs,
the local twin of the `state` branch: a second run falls back to it if an
upstream is down. `--cache` only saves downloads, for local iteration. If you
move `--lkg-dir`, pass the same path to `verify.py`.

```
build/geodat.py         Xray .dat protobuf reader/writer
build/model.py          normalisation — merging, pruning, match types, filters
build/sources.py        source registry (SOURCES, PROVIDERS) and per-feed parsers
build/fetch.py          mirrors, conditional requests, validation, the state store
build/bgp.py            routing adjustment of `ir` and provider prefixes
build/emitters.py       one function per output format
build/build.py          orchestration and set-level guards
build/release_notes.py  release notes from stats.json
build/verify.py         post-build acceptance checks
build/test_*.py         offline tests (testkit.py is their shared helper)
```

## Branches

| Branch | Contents |
|---|---|
| `main` | source — the build scripts and workflows |
| `dist` | build output, force-pushed daily, no source history |
| `state` | the last validated copy of every upstream input, one commit replaced on every run |

## License

[GNU GPLv3](LICENSE). Upstream sources keep their own licenses, listed above.

## Disclaimer

Not affiliated with or endorsed by any service, registry or project referenced
here. Data comes from publicly available sources and is provided as-is, with no
guarantee of accuracy or availability.
