# IR-Geo-DB state store

This is the `state` branch of IR-Geo-DB, written by its daily build. It holds the last validated copy of every upstream source, which the build falls back on when that source cannot be fetched. It is not a release: the published data is on the `dist` branch and the Releases page.

For each source, `<key>.values.gz` is the list of values this project parsed from the upstream file, one per line, and `<key>.json` records where and when it was fetched. Each copy is the upstream's data and stays under the upstream's terms, listed below.

Contains RIPE NCC RIS data © RIPE NCC

| Key | Source | Licence | Homepage | Attribution |
|---|---|---|---|---|
| `rir-ripencc` | RIPENCC delegated statistics | Registry public data | https://www.nro.net/about/rirs/statistics/ |  |
| `rir-apnic` | APNIC delegated statistics | Registry public data | https://www.nro.net/about/rirs/statistics/ |  |
| `rir-arin` | ARIN delegated statistics | Registry public data | https://www.nro.net/about/rirs/statistics/ |  |
| `rir-lacnic` | LACNIC delegated statistics | Registry public data | https://www.nro.net/about/rirs/statistics/ |  |
| `rir-afrinic` | AFRINIC delegated statistics | Registry public data | https://www.nro.net/about/rirs/statistics/ |  |
| `ris-v4` | RIPE RIS IPv4 routing table | RIPE NCC RIS data (attribution required) | https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ | Contains RIPE NCC RIS data © RIPE NCC |
| `ris-v6` | RIPE RIS IPv6 routing table | RIPE NCC RIS data (attribution required) | https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ | Contains RIPE NCC RIS data © RIPE NCC |
| `ripe-org-org-naap1-ripe` | RIPE database ASNs of ORG-NAAP1-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-naac1-ripe` | RIPE database ASNs of ORG-NAAC1-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-agtl2-ripe` | RIPE database ASNs of ORG-AGTL2-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-hucc1-ripe` | RIPE database ASNs of ORG-HUCC1-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-ib117-ripe` | RIPE database ASNs of ORG-IB117-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-endc1-ripe` | RIPE database ASNs of ORG-ENDC1-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-gwsn7-ripe` | RIPE database ASNs of ORG-GWSN7-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `ripe-org-org-saml1-ripe` | RIPE database ASNs of ORG-SAML1-RIPE | RIPE Database (public) | https://www.ripe.net/manage-ips-and-asns/db/ |  |
| `arvancloud` | ArvanCloud | All rights reserved | https://www.arvancloud.ir/en/dev/ips |  |
| `parspack` | ParsPack CDN | All rights reserved | https://parspack.com |  |
| `derak-v4` | Derak Cloud | Provider-published | https://derak.cloud |  |
| `derak-v6` | Derak Cloud | Provider-published | https://derak.cloud |  |
| `iranserver` | IranServer | Provider-published | https://www.iranserver.com |  |
| `mizbancloud` | MizbanCloud | Provider-published | https://mizbancloud.com |  |
| `xc-ipverse-v4` | ipverse rir-ip | Public domain | https://github.com/ipverse/rir-ip |  |
| `xc-ipverse-v6` | ipverse rir-ip | Public domain | https://github.com/ipverse/rir-ip |  |
| `xc-ipdeny-v4` | ipdeny country zones | Free to use | https://www.ipdeny.com |  |
| `cloud-cloudflare-v4` | Cloudflare | Provider-published | https://www.cloudflare.com/ips |  |
| `cloud-cloudflare-v6` | Cloudflare | Provider-published | https://www.cloudflare.com/ips |  |
| `cloud-aws` | Amazon AWS | Provider-published | https://ip-ranges.amazonaws.com |  |
| `cloud-google` | Google | Provider-published | https://www.gstatic.com/ipranges/goog.json |  |
| `cloud-gcloud` | Google Cloud | Provider-published | https://www.gstatic.com/ipranges/cloud.json |  |
| `cloud-fastly` | Fastly | Provider-published | https://api.fastly.com/public-ip-list |  |
| `cloud-gcore` | G-Core | Provider-published | https://gcore.com |  |
| `threat-ip-malware` | Feodo Tracker botnet C2 | CC0 | https://feodotracker.abuse.ch/blocklist/ |  |
| `threat-ip-hagezi` | HaGeZi Threat Intelligence Feeds (IPs) | GPL-3.0 | https://github.com/hagezi/dns-blocklists |  |
| `ir-domains` | Iran Hosted Domains | MIT | https://github.com/bootmortis/iran-hosted-domains |  |
| `ir-v2fly` | v2fly domain-list-community (category-ir) | MIT | https://github.com/v2fly/domain-list-community |  |
| `psl` | Public Suffix List | MPL-2.0 | https://publicsuffix.org |  |
| `ads-persian-hosts` | PersianBlocker hosts | AGPL-3.0 | https://github.com/PersianBlocker/PersianBlocker |  |
| `ads-persian-ads` | PersianBlocker ads domains | AGPL-3.0 | https://github.com/PersianBlocker/PersianBlocker |  |
| `ads-persian-trackers` | PersianBlocker trackers domains | AGPL-3.0 | https://github.com/PersianBlocker/PersianBlocker |  |
| `ads-hagezi` | HaGeZi Multi LIGHT | GPL-3.0 | https://github.com/hagezi/dns-blocklists |  |
| `allow-adguard-exclusions` | AdGuard DNS filter exclusions | GPL-3.0 | https://github.com/AdguardTeam/AdGuardSDNSFilter |  |
| `allow-adguard-exceptions` | AdGuard DNS filter exceptions | GPL-3.0 | https://github.com/AdguardTeam/AdGuardSDNSFilter |  |
| `malware-hagezi-tif` | HaGeZi Threat Intelligence Feeds mini | GPL-3.0 | https://github.com/hagezi/dns-blocklists |  |
| `phishing-certpl` | CERT Polska warning list | free for any use | https://cert.pl/en/warning-list/ |  |
| `crypto-nocoin` | NoCoin adblock list | MIT | https://github.com/hoshsadiq/adblock-nocoin-list |  |
| `nsfw-stevenblack` | StevenBlack unified hosts (porn) | MIT | https://github.com/StevenBlack/hosts |  |
| `nsfw-stevenblack-gambling` | StevenBlack unified hosts (gambling) | MIT | https://github.com/StevenBlack/hosts |  |
