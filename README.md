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
one build, every format, updated every day. IP data comes from the Regional
Internet Registries directly, not from a geolocation guess.

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
blocked. Files over 20 MB are not served by jsDelivr; use the release URL for
`geosite.dat` and `geosite-security.dat`.

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
      "download_detour": "direct", "update_interval": "1d" }
  ]
}
```

Rule-sets are compiled at format version 1, so they load on sing-box 1.8 and
later. The JSON sources are in `sing-box/source/`.
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

> **This one is big — check your device first.** `ir-dns.rsc` is ~62,000
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
> The address-list files (`ir-ipv4.rsc`, ~1,700 entries) are small and safe
> everywhere.

Ad and threat blocking, RouterOS 7.15+:

```
/ip dns adlist add ssl-verify=yes \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/adlist-block-all.txt"
```

`adlist-block-all.txt` is over half a million domains. On small devices start
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
# nftables
curl -sfL https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/nftables/ir.nft \
  -o /etc/nftables.d/ir.nft && nft -f /etc/nftables.d/ir.nft

# ipset / iptables
curl -sfL https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/ipset/ir.ipset | ipset restore
```

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
per domain, Unbound a stanza each. `manifest.json` records which profile each
set used.

## How an address is decided to be Iranian

From registry delegation records, not geolocation. An address is in `ir` only
if a Regional Internet Registry delegated it to an organisation whose
registered country is `IR`. All five RIRs are read, since an Iranian
organisation can hold space from any of them.

Three consequences, all deliberate:

**Iranian CDN ranges are separate.** ParsPack's published CDN list includes
Leaseweb and Vultr space; ArvanCloud's includes foreign edge nodes. Those ship
as `ir-cdn`. `ir-full` is the union, for "everything serving Iranian traffic"
rather than "machines in Iran".

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

## Sources

| Source | Maintainer | License | Provides |
|---|---|---|---|
| [RIR delegated statistics](https://www.nro.net/about/rirs/statistics/) | RIPE NCC, APNIC, ARIN, LACNIC, AFRINIC | Registry public data | Iranian IP delegations |
| [ipverse rir-ip](https://github.com/ipverse/rir-ip) | ipverse | Public domain | cross-check |
| [ipdeny](https://www.ipdeny.com) | ipdeny | Free to use | cross-check |
| [ArvanCloud](https://www.arvancloud.ir/en/dev/ips) | ArvanCloud | All rights reserved | `ir-cdn` |
| [ParsPack](https://parspack.com) | ParsPack | All rights reserved | `ir-cdn` |
| [Iran Hosted Domains](https://github.com/bootmortis/iran-hosted-domains) | bootmortis | MIT | Iranian domains |
| [PersianBlocker](https://github.com/MasterKia/PersianBlocker) | MasterKia | AGPL-3.0 | Persian ads |
| [HaGeZi DNS Blocklists](https://github.com/hagezi/dns-blocklists) | HaGeZi | GPL-3.0 | ads / tracking |
| [AdGuard DNS filter](https://github.com/AdguardTeam/AdGuardSDNSFilter) | AdGuard | GPL-3.0 | ads / tracking |
| [URLhaus](https://urlhaus.abuse.ch) | abuse.ch | CC0 | malware |
| [Feodo Tracker](https://feodotracker.abuse.ch/blocklist/) | abuse.ch | CC0 | botnet C2 IPs |

| [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) | mitchellkrogza | MIT | phishing |
| [NoCoin](https://github.com/hoshsadiq/adblock-nocoin-list) | hoshsadiq | MIT | cryptominers |
| [StevenBlack hosts](https://github.com/StevenBlack/hosts) | StevenBlack | MIT | adult / gambling |
| Cloudflare, AWS, Google, Fastly, G-Core | respective owners | — | exclusion lists |

Found a missing Iranian domain or a false positive? Report it to the upstream
source — fixing it there fixes it for everyone. See [CONTRIBUTING.md](CONTRIBUTING.md).

**Set sizes vary a lot, and small does not mean broken.** `malware` and
`cryptominers` are a few hundred entries each because their sources track
*currently active* threats rather than accumulating history; Feodo Tracker's
IP feed in particular is often only a handful of addresses. `ads`, `phishing`
and `nsfw` are the large ones. Live counts are always in `stats.json`.

## Design notes

**`.ir` collapses to one rule.** Every consumer here matches subdomains, so the
whole TLD is a single suffix entry instead of tens of thousands of names.
Around 69,000 entries become one, and matching gets faster.

**Redundant subdomains are pruned.** If `example.com` is in a set,
`ads.example.com` is dead weight.

**Prefixes are merged.** `5.160.0.0/17` + `5.160.128.0/17` collapse to
`5.160.0.0/16`. Malformed entries are dropped and counted.

**Match types survive.** sing-box, Xray, Clash and Surge all distinguish exact,
suffix, keyword and regex matches. Formats that cannot express one — hosts
files, adlists — drop what they cannot represent and record the count, rather
than emitting a rule that means something else.

**Builds fail loudly.** A truncated source, a collapsed prefix count or a
failed verification aborts the run and publishes nothing.

## Building it yourself

```bash
git clone https://github.com/Arman2122/IR-Geo-DB && cd IR-Geo-DB
python3 build/build.py --outdir dist --cache .cache
python3 build/verify.py dist
```

Python 3.10+, standard library only. `sing-box` and `mihomo` on `PATH` (or via
`$SING_BOX` / `$MIHOMO`) add the `.srs` and `.mrs` outputs; without them
everything else still builds.

```
build/geodat.py         Xray .dat protobuf reader/writer
build/model.py          normalisation — merging, pruning, match types
build/sources.py        source registry and per-feed parsers
build/emitters.py       one function per output format
build/build.py          orchestration
build/verify.py         post-build acceptance checks
build/test_units.py     offline unit tests
```

## Branches

| Branch | Contents |
|---|---|
| `main` | source — the build scripts and workflows |
| `dist` | build output, force-pushed daily, no source history |

## License

[GNU GPLv3](LICENSE). Upstream sources keep their own licenses, listed above.

## Disclaimer

Not affiliated with or endorsed by any service, registry or project referenced
here. Data comes from publicly available sources and is provided as-is, with no
guarantee of accuracy or availability.
