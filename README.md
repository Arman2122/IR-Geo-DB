<h1 align="center">IR-Geo-DB</h1>

<p align="center">
  <b>Iranian routing and filtering data, rebuilt daily, in every format your client actually speaks.</b>
</p>

<p align="center">
  <a href="https://github.com/Arman2122/IR-Geo-DB/actions/workflows/build.yml"><img alt="Build" src="https://img.shields.io/github/actions/workflow/status/Arman2122/IR-Geo-DB/build.yml?branch=main&style=for-the-badge&logo=github"></a>
  <a href="https://github.com/Arman2122/IR-Geo-DB/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/Arman2122/IR-Geo-DB?style=for-the-badge"></a>
  <a href="https://github.com/Arman2122/IR-Geo-DB/releases/latest"><img alt="Date" src="https://img.shields.io/github/release-date/Arman2122/IR-Geo-DB?display_date=published_at&style=for-the-badge"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Arman2122/IR-Geo-DB?style=for-the-badge&color=blue"></a>
</p>

---

Most geo-data projects publish one format and leave you to convert. This one
takes the same primary sources and emits **17 formats** — from Xray's binary
`geoip.dat` down to an `nftables` set — so the same daily data lands in your
proxy client, your DNS resolver and your router without a conversion step in
between.

Everything is built by GitHub Actions on a schedule. There is no server, no
database and no state carried between runs: every build starts from the
upstream sources and reproduces the whole tree.

## Download

Two channels, both updated by the same daily build:

| | URL | Use when |
|---|---|---|
| **Release** | `https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/<file>` | You want a versioned, checksummed download |
| **`dist` branch** | `https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/<path>` | Your device fetches by URL — **routers should use this** |

> **Why routers need the branch:** release asset URLs redirect through
> `objects.githubusercontent.com`. RouterOS `/tool fetch` and several embedded
> HTTP clients do not reliably follow redirects. The branch gives a direct
> `raw.githubusercontent.com` URL that always works.

## Quick start

<details open>
<summary><b>Xray / v2ray</b> — <code>geoip.dat</code>, <code>geosite.dat</code></summary>

```bash
curl -sfLO https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/geoip.dat
curl -sfLO https://github.com/Arman2122/IR-Geo-DB/releases/latest/download/geosite.dat
```

Drop both next to the core binary (or in its asset directory), then:

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

`geoip-lite.dat` and `geosite-lite.dat` carry only the Iranian sets — use them
on phones where the full files are more than you need.
</details>

<details>
<summary><b>sing-box</b> — remote <code>.srs</code> rule-sets</summary>

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

The JSON sources the `.srs` files are compiled from are in
`sing-box/source/`, if you would rather compile them yourself.
</details>

<details>
<summary><b>Mihomo / Clash.Meta</b> — <code>.mrs</code> rule-providers</summary>

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

Older clients without `.mrs` support can use the YAML providers in `clash/`
with `format: yaml`.
</details>

<details>
<summary><b>MikroTik RouterOS</b> — address-lists, split DNS, adlists</summary>

**Iranian IP address-list**

```
/tool fetch mode=https dst-path=ir.rsc \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/ir-ipv4-reset.rsc"
/import file-name=ir.rsc
```

The `-reset` variant removes only `dynamic=no` entries first, so it replaces
the static geo data and leaves DNS-populated dynamic entries alone. Use
`ir-ipv4.rsc` to append instead.

**Self-updating** — paste once and it maintains itself, with a size guard so a
truncated download cannot wipe your list:

```
/tool fetch mode=https dst-path=setup.rsc \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/auto-update.rsc"
/import file-name=setup.rsc
```

**Iranian domains → split DNS.** Each entry forwards the domain to an Iranian
resolver *and* writes every resolved address into the `IR` address list. That
is what catches Iranian services sitting behind a foreign CDN — an IP list
alone never can.

```
/tool fetch mode=https dst-path=ir-dns.rsc \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/ir-dns.rsc"
/import file-name=ir-dns.rsc
```

**Ad and threat blocking** (RouterOS 7.15+):

```
/ip dns adlist add ssl-verify=yes \
  url="https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/mikrotik/adlist-block-all.txt"
```

> **Watch RAM on small devices.** `adlist-block-all.txt` is over half a million
> domains. On an hAP ax² or similar, start with `adlist-malware.txt` and
> `adlist-phishing.txt` — small, high value — and add ads only if
> `/system resource print` says you have room.
</details>

<details>
<summary><b>DNS servers</b> — dnsmasq, Unbound, AdGuard Home, SmartDNS, RPZ</summary>

```bash
# dnsmasq — sinkhole
curl -sfL -o /etc/dnsmasq.d/block.conf \
  https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/dnsmasq/block-all-block.conf

# dnsmasq — send Iranian domains to an Iranian resolver
curl -sfL -o /etc/dnsmasq.d/ir.conf \
  https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/dnsmasq/ir-route.conf

# Unbound
curl -sfL -o /etc/unbound/unbound.conf.d/ir.conf \
  https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/unbound/ir-route.conf
```

**AdGuard Home** — Filters → DNS blocklists → add
`.../dist/adguard/block-all.txt`.

**BIND / Knot / PowerDNS** — the `rpz/` zones return NXDOMAIN and load as a
standard response policy zone.
</details>

<details>
<summary><b>Firewalls</b> — nftables, ipset, pfSense, WireGuard</summary>

```bash
# nftables
curl -sfL https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/nftables/ir.nft \
  -o /etc/nftables.d/ir.nft && nft -f /etc/nftables.d/ir.nft

# ipset (iptables)
curl -sfL https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/ipset/ir.ipset | ipset restore
```

**pfSense / OPNsense** — Firewall → Aliases → type *URL Table (IPs)*, point at
`.../dist/text/ir-ipv4.txt`, refresh daily.

**WireGuard split tunnelling** — `wireguard/ir-allowedips.conf` is a ready
`AllowedIPs =` line.
</details>

<details>
<summary><b>Surge, Loon, Quantumult X, Shadowrocket</b></summary>

Surge rule list and `DOMAIN-SET` files are in `surge/`; Quantumult X filters
with policies already attached are in `quantumultx/`.

```
# Surge
[Rule]
RULE-SET,https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/surge/ir-domain.list,DIRECT
RULE-SET,https://raw.githubusercontent.com/Arman2122/IR-Geo-DB/dist/surge/ir-ip.list,DIRECT
```
</details>

## Formats

| Directory | Format | Sets |
|---|---|---|
| `xray/` | `geoip.dat`, `geosite.dat` (+ lite, security) | all |
| `sing-box/` | compiled `.srs` + JSON sources | all |
| `mihomo/` | compiled `.mrs` | all |
| `clash/` | rule-provider YAML, `.list`, classical | all |
| `mikrotik/` | `.rsc` address-lists, DNS scripts, adlists | all |
| `dnsmasq/` | `server=/…/` routing, `address=/…/` sinkhole | domains |
| `unbound/` | forward-zones, `always_nxdomain` zones | domains |
| `smartdns/` | nameserver groups, `address /…/#` | domains |
| `adguard/` | `\|\|domain^` filter syntax | block sets |
| `hosts/` | `0.0.0.0 domain` | block sets |
| `rpz/` | BIND response policy zones | block sets |
| `ipset/` | `ipset restore` | IP sets |
| `nftables/` | `nft` interval sets | IP sets |
| `wireguard/` | `AllowedIPs =` | IP sets |
| `surge/` | rule list + `DOMAIN-SET` | all |
| `quantumultx/` | filters with policies | all |
| `text/` | plain CIDR / domain per line | all |

Sets above 100,000 entries skip the most verbose formats (RPZ writes two lines
per domain, Unbound writes a stanza). The `manifest.json` records which
profile each set used.

## Data sources

### How an address is decided to be Iranian

**Registry delegation records, not geolocation guessing.** An address is in
the `ir` set only if a Regional Internet Registry has delegated it to an
organisation whose registered country is `IR`. All five RIRs are read, because
an Iranian organisation can hold space from any of them.

Three things follow from that choice, and they are deliberate:

1. **Iranian CDN ranges are published separately.** ParsPack's published CDN
   list includes Leaseweb and Vultr space; ArvanCloud's includes foreign edge
   nodes. Folding those into `ir` would mean claiming Amsterdam is in Iran.
   They ship as **`ir-cdn`**, and **`ir-full`** is the union if you want
   "everything serving Iranian traffic" rather than "machines in Iran".
2. **Foreign cloud ranges are subtracted.** Cloudflare, AWS, Google, Fastly
   and G-Core publish their own prefixes; any overlap is removed from `ir`.
   In practice this is near zero — which is the point: it makes a whole class
   of error impossible instead of merely unlikely.
3. **Every build is cross-checked.** The result is compared against
   [ipverse](https://github.com/ipverse/rir-ip) and
   [ipdeny](https://www.ipdeny.com) — two independent parses of the same
   registry data. The agreement figure is printed in every release note. A
   disagreement is reported, never silently merged in.

The build also refuses to publish if the Iranian set falls below sane
thresholds, if a long-standing Iranian block goes missing, or if a
known-foreign address such as `8.8.8.8` turns up inside it.

### Upstream

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

Found an Iranian domain that should be listed, or a false positive? Report it
to the upstream source above — fixing it there fixes it for everyone, not just
here.

## Sets

**IP** — `ir`, `ir-cdn`, `ir-full`, `private`, `malware`, `phishing`
**Domain** — `ir`, `ads`, `ads-ir`, `malware`, `phishing`, `cryptominers`, `nsfw`, `block-all`

`geoip:` and `geosite:` are separate namespaces, so `geoip:malware` (C2
addresses) and `geosite:malware` (malware domains) are different sets with the
same name, on purpose.

## Design notes

**`.ir` collapses to one rule.** Every consumer here matches subdomains, so
the whole `.ir` TLD is a single suffix entry instead of tens of thousands of
individual names. Roughly 69,000 entries become one, and matching gets faster
rather than slower.

**Redundant subdomains are pruned.** If `example.com` is in a set then
`ads.example.com` is dead weight. On real ad lists this removes a meaningful
fraction of the entries, which is what makes them fit on a router.

**Prefixes are merged.** `5.160.0.0/17` + `5.160.128.0/17` collapse to
`5.160.0.0/16`. Malformed entries are dropped and counted, never passed
through.

**Match types survive.** sing-box distinguishes exact, suffix, keyword and
regex matches; so do Xray, Clash and Surge. Formats that cannot express a
match type — hosts files, MikroTik adlists — drop what they cannot represent
and record the count in the manifest, rather than silently emitting a rule
that means something else.

**Builds fail loudly.** If a source is truncated, if the Iranian prefix count
collapses, or if verification fails, the job aborts and publishes nothing. A
bad upstream day cannot push a broken list to your router.

## Building it yourself

```bash
git clone https://github.com/Arman2122/IR-Geo-DB && cd IR-Geo-DB
python3 build/build.py --outdir dist --cache .cache
python3 build/verify.py dist
```

Python 3.10+ and nothing else. `sing-box` and `mihomo` on `PATH` (or via
`$SING_BOX` / `$MIHOMO`) add the `.srs` and `.mrs` outputs; without them
everything else still builds and the run reports what it skipped.

```
build/geodat.py         Xray .dat protobuf reader/writer  (self-test: run it directly)
build/model.py          normalisation — merging, pruning, match types
build/sources.py        source registry and per-feed parsers
build/emitters.py       one function per output format
build/build.py          orchestration
build/verify.py         post-build acceptance checks
build/release_notes.py  release note rendering
```

## License

This project is licensed under the **GNU GPLv3** — see [LICENSE](LICENSE).

All upstream sources remain under their own licenses, listed in the table
above. This repository redistributes their data in converted form.

## Disclaimer

Not affiliated with, endorsed by, or connected to any of the services,
registries or projects referenced here. The data is gathered from publicly
available sources and provided as-is, with no guarantee of accuracy or
availability. Verify before you depend on it.
