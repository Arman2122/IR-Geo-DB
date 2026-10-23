#!/usr/bin/env python3
"""Where the data comes from, and how each feed is parsed.

Every input comes from the most authoritative publisher that can be reached
from a GitHub runner: the five Regional Internet Registries for allocations,
RIPE NCC for routing and for each provider's ASNs, the Iranian providers for
their own ranges, and the project that maintains each blocklist. An
aggregator is used only where the authority is unreachable, and says so.

An address is Iranian only if a RIR delegated it to an organisation whose
registered country is IR (bgp.py then adjusts that to what is routed). ipverse
and ipdeny are fetched purely to cross-check that parsing and never
contribute addresses.

How a source is fetched and when its body is trusted lives in fetch.py.

Standard library only — a GitHub Actions runner needs no install step.
"""

from __future__ import annotations

import gzip
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from typing import NamedTuple

import geodat
from model import clean_domain


@dataclass
class Source:
    key: str
    name: str
    url: str
    parser: str
    kind: str                 # "ip" | "domain"
    tier: str                 # registry | provider | official | crosscheck | cloud | blocklist
    license: str = ""
    homepage: str = ""
    optional: bool = False    # a failure here warns instead of aborting
    note: str = ""
    # how fetch.py acquires and trusts it. The floors default to off; the
    # shrink guard is on, but needs an unexpired stored copy of >= 100 entries
    mirrors: tuple[str, ...] = ()     # tried in order after url
    min_entries: int = 0              # fewer parsed entries: reject the body
    min_bytes: int = 0                # a smaller raw body: reject it
    max_shrink: float = 0.5           # reject a body with fewer than
                                      # (1 - max_shrink) x the stored copy's
                                      # entries, once that copy has >= 100
    max_age_days: int | None = None   # reject a Last-Modified older than this
    max_stale_days: int = 14          # how long the stored copy may stand in
    attribution: str = ""             # text the README and stats.json must carry

    @property
    def credit(self) -> str:
        return f"{self.name} ({self.license})" if self.license else self.name


# --------------------------------------------------------------- the registry
#
# Every source is tagged with where it comes from, using the classes in the
# design spec (section 1):
#   authority   the body that creates the data (RIRs, RIPE NCC, a provider's
#               own list, a national CERT)
#   derived     computed by this project from authority data
#   maintainer  the project that curates a blocklist
#   aggregator  a third party that republishes someone else's data
#
# A floor (min_entries, min_bytes) is about 70 % of what the source returned
# on 2026-10-23, rounded down to two significant digits, with the measured
# figure beside it. A source under 20 entries gets about half instead, so a
# small list is not tripped by one removed line. The shrink guard stays at
# its default except where a source legitimately swings to near zero.

# Iranian infrastructure providers (spec 1.1). A provider's address space is
# derived by this project: each RIPE organisation is looked up for its ASNs
# (the `ripe-org-*` sources below) and every prefix those ASNs announce in RIS
# is taken from the BGP table. `lists` are the provider's own published
# ranges, which are read as well. A provider with no organisation owns no ASN
# of its own; one with no list publishes none.
PROVIDERS: dict[str, dict] = {
    "ArvanCloud": {"orgs": ["ORG-NAAP1-RIPE", "ORG-NAAC1-RIPE", "ORG-AGTL2-RIPE"],
                   "lists": ["arvancloud"]},
    "Sotoon": {"orgs": ["ORG-HUCC1-RIPE", "ORG-IB117-RIPE"], "lists": []},
    "Derak": {"orgs": ["ORG-ENDC1-RIPE"], "lists": ["derak-v4", "derak-v6"]},
    "IranServer": {"orgs": ["ORG-GWSN7-RIPE"], "lists": ["iranserver"]},
    "MizbanCloud": {"orgs": ["ORG-SAML1-RIPE"], "lists": ["mizbancloud"]},
    "ParsPack": {"orgs": [], "lists": ["parspack"]},
}

# (rir, url, min_entries, min_bytes). `entries` is the number of Iranian
# prefixes and ASNs the file yields. Only RIPE NCC has Iranian records in
# any number, so the others keep min_entries at 0 and rely on min_bytes: a
# file that is not the full delegation list is rejected on size.
RIR_STATS = [
    ("ripencc", "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
     2_300, 12_000_000),  # 3,407 entries, 18.1 MB on 2026-10-23
    ("apnic", "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
     0, 6_400_000),  # 0 entries, 9.3 MB on 2026-10-23
    ("arin", "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
     0, 9_000_000),  # 0 entries, 12.9 MB on 2026-10-23
    ("lacnic", "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
     0, 3_200_000),  # 0 entries, 4.6 MB on 2026-10-23
    ("afrinic", "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
     0, 700_000),  # 0 entries, 1.0 MB on 2026-10-23
]

# One lookup per provider organisation, so a newly registered ASN is picked up
# without a code change. Each org holds only a handful of ASNs, so min_entries
# is about half of the ASNs found (at least 1): an empty answer for an org
# that has ASNs is a sign the lookup is broken, not that it lost them all.
_RIPE_ORG_URL = ("https://rest.db.ripe.net/search.json?query-string={org}"
                 "&inverse-attribute=org&type-filter=aut-num&flags=no-referenced")
_RIPE_ORG_FLOOR = {
    "ORG-NAAP1-RIPE": 1,  # 2 found on 2026-10-23
    "ORG-NAAC1-RIPE": 1,  # 1 found on 2026-10-23
    "ORG-AGTL2-RIPE": 1,  # 3 found on 2026-10-23
    "ORG-HUCC1-RIPE": 2,  # 4 found on 2026-10-23
    "ORG-IB117-RIPE": 1,  # 1 found on 2026-10-23
    "ORG-ENDC1-RIPE": 1,  # 2 found on 2026-10-23
    "ORG-GWSN7-RIPE": 1,  # 3 found on 2026-10-23
    "ORG-SAML1-RIPE": 1,  # 3 found on 2026-10-23
}

HAGEZI = "hagezi/dns-blocklists"


def _hagezi_mirrors(path: str) -> tuple[str, ...]:
    """HaGeZi's own mirrors of a file, then jsDelivr's copy."""
    return (f"https://gitlab.com/hagezi/mirror/-/raw/main/dns-blocklists/{path}",
            f"https://codeberg.org/hagezi/mirror2/raw/branch/main/dns-blocklists/{path}",
            f"https://cdn.jsdelivr.net/gh/{HAGEZI}@latest/{path}")


def _jsdelivr(owner: str, repo: str, branch: str, path: str) -> str:
    return f"https://cdn.jsdelivr.net/gh/{owner}/{repo}@{branch}/{path}"


_PB = "https://raw.githubusercontent.com/PersianBlocker/PersianBlocker/main/"

SOURCES: list[Source] = [
    # ---- IP: the registries. Origin: authority. Iran's space is
    # overwhelmingly RIPE NCC, but an Iranian org can hold space from any
    # RIR, so all five are read. RIPE NCC is the only required source besides
    # ir-domains: without it there is no Iranian address set at all.
    *[
        Source(key=f"rir-{rir}", name=f"{rir.upper()} delegated statistics",
               url=url, parser="rir", kind="ip", tier="registry",
               license="Registry public data",
               homepage="https://www.nro.net/about/rirs/statistics/",
               optional=(rir != "ripencc"),
               min_entries=min_entries, min_bytes=min_bytes,
               # regenerated daily; a file a month old is a stalled
               # generator, which would otherwise pass as not-modified
               # forever (the stale window only starts once a URL fails).
               # A month, not a week (ruling R26): delegations stay valid
               # for weeks, and rir-ripencc is required, so a short limit
               # would stop every release over a merely late file.
               max_age_days=30, max_stale_days=14,
               note="authoritative country delegation")
        for rir, url, min_entries, min_bytes in RIR_STATS
    ],

    # ---- IP: BGP. Origin: authority (RIPE NCC's RIS collectors), used by
    # bgp.py to adjust the registry set to what is actually routed from Iran.
    # RIPE NCC grants the use on condition of the attribution below. The
    # dumps are regenerated several times a day, so one 3 days old means
    # the dump generation stalled: max_age_days turns that into a stale
    # source instead of an old routing table served as current.
    Source(key="ris-v4", name="RIPE RIS IPv4 routing table", parser="ris",
           kind="ip", tier="registry", optional=True,
           url="https://www.ris.ripe.net/dumps/riswhoisdump.IPv4.gz",
           license="RIPE NCC RIS data (attribution required)",
           homepage="https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/",
           attribution="Contains RIPE NCC RIS data © RIPE NCC",
           min_entries=790_000, min_bytes=4_000_000,  # 1,133,597 entries, 5.7 MB on 2026-10-23
           max_age_days=3, max_stale_days=14),
    Source(key="ris-v6", name="RIPE RIS IPv6 routing table", parser="ris",
           kind="ip", tier="registry", optional=True,
           url="https://www.ris.ripe.net/dumps/riswhoisdump.IPv6.gz",
           license="RIPE NCC RIS data (attribution required)",
           homepage="https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/",
           attribution="Contains RIPE NCC RIS data © RIPE NCC",
           min_entries=180_000, min_bytes=930_000,  # 267,407 entries, 1.3 MB on 2026-10-23
           max_age_days=3, max_stale_days=14),

    # ---- IP: provider ASNs. Origin: authority (the RIPE database), derived
    # by us: the ASNs registered to each provider's organisation, which bgp.py
    # then turns into the prefixes they announce. See PROVIDERS above.
    *[
        Source(key=f"ripe-org-{org.lower()}", name=f"RIPE database ASNs of {org}",
               url=_RIPE_ORG_URL.format(org=org), parser="ripe_org_asns",
               kind="ip", tier="registry", optional=True,
               license="RIPE Database (public)",
               homepage="https://www.ripe.net/manage-ips-and-asns/db/",
               min_entries=_RIPE_ORG_FLOOR[org], min_bytes=50,
               max_stale_days=90,
               note=f"{provider}: ASNs registered to {org}")
        for provider, info in PROVIDERS.items() for org in info["orgs"]
    ],

    # ---- IP: ranges the Iranian providers publish themselves. Origin:
    # authority, each for its own space. They are read next to the networks
    # derived above because a provider may announce through someone else's AS.
    Source(key="arvancloud", name="ArvanCloud", parser="cidr", kind="ip",
           tier="provider", url="https://www.arvancloud.ir/en/ips.txt",
           homepage="https://www.arvancloud.ir/en/dev/ips",
           license="All rights reserved", optional=True,
           min_entries=7, min_bytes=110,  # 14 entries, 220 bytes on 2026-10-23
           max_stale_days=90),
    Source(key="parspack", name="ParsPack CDN", parser="cidr", kind="ip",
           tier="provider", url="https://parspack.com/cdnips.txt",
           homepage="https://parspack.com", license="All rights reserved",
           optional=True, note="includes foreign edge nodes",
           min_entries=34, min_bytes=570,  # 49 entries, 828 bytes on 2026-10-23
           max_stale_days=90),
    Source(key="derak-v4", name="Derak Cloud", parser="cidr", kind="ip",
           tier="provider", url="https://api.derak.cloud/public/ipv4",
           homepage="https://derak.cloud", license="Provider-published",
           optional=True,
           min_entries=9, min_bytes=160,  # 19 entries, 323 bytes on 2026-10-23
           max_stale_days=90),
    Source(key="derak-v6", name="Derak Cloud", parser="cidr", kind="ip",
           tier="provider", url="https://api.derak.cloud/public/ipv6",
           homepage="https://derak.cloud", license="Provider-published",
           optional=True,
           min_entries=5, min_bytes=100,  # 10 entries, 207 bytes on 2026-10-23
           max_stale_days=90),
    Source(key="iranserver", name="IranServer", parser="cidr", kind="ip",
           tier="provider", url="https://ips.f95.com/ips.txt",
           homepage="https://www.iranserver.com", license="Provider-published",
           optional=True, note="published as bare /32 addresses",
           min_entries=15, min_bytes=210,  # 22 entries, 302 bytes on 2026-10-23
           max_stale_days=90),
    Source(key="mizbancloud", name="MizbanCloud", parser="cidr", kind="ip",
           tier="provider", url="https://mizbancloud.com/ips.txt",
           homepage="https://mizbancloud.com", license="Provider-published",
           optional=True,
           min_entries=4, min_bytes=66,  # 8 entries, 132 bytes on 2026-10-23
           max_stale_days=90),

    # The ITO government messenger-IP page renders its table client-side, so
    # there is nothing to scrape from the HTML. It is no loss: Iranian
    # messengers run on Iranian address space, which the registry feed
    # already covers.

    # ---- IP: cross-checks. Origin: aggregator, deliberately: independent
    # implementations of the same RIR parse, used to validate ours and never
    # to add addresses.
    Source(key="xc-ipverse-v4", name="ipverse rir-ip", parser="cidr", kind="ip",
           tier="crosscheck", optional=True, license="Public domain",
           homepage="https://github.com/ipverse/rir-ip",
           url="https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv4-aggregated.txt",
           min_entries=1_200, min_bytes=19_000,  # 1,747 entries, 28 KB on 2026-10-23
           max_stale_days=14),
    Source(key="xc-ipverse-v6", name="ipverse rir-ip", parser="cidr", kind="ip",
           tier="crosscheck", optional=True, license="Public domain",
           homepage="https://github.com/ipverse/rir-ip",
           url="https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ir/ipv6-aggregated.txt",
           min_entries=400, min_bytes=6_100,  # 574 entries, 8,717 bytes on 2026-10-23
           max_stale_days=14),
    Source(key="xc-ipdeny-v4", name="ipdeny country zones", parser="cidr",
           kind="ip", tier="crosscheck", optional=True, license="Free to use",
           homepage="https://www.ipdeny.com",
           url="https://www.ipdeny.com/ipblocks/data/aggregated/ir-aggregated.zone",
           min_entries=1_200, min_bytes=19_000,  # 1,747 entries, 27 KB on 2026-10-23
           max_stale_days=14),

    # ---- IP: foreign clouds and CDNs, subtracted from the Iranian set as a
    # guard. Origin: authority, each cloud's own published ranges. They change
    # slowly, so a stored copy may stand in for 30 days.
    Source(key="cloud-cloudflare-v4", name="Cloudflare", parser="cidr", kind="ip",
           tier="cloud", url="https://www.cloudflare.com/ips-v4", optional=True,
           license="Provider-published", homepage="https://www.cloudflare.com/ips",
           min_entries=7, min_bytes=110,  # 15 entries, 230 bytes on 2026-10-23
           max_stale_days=30),
    Source(key="cloud-cloudflare-v6", name="Cloudflare", parser="cidr", kind="ip",
           tier="cloud", url="https://www.cloudflare.com/ips-v6", optional=True,
           license="Provider-published", homepage="https://www.cloudflare.com/ips",
           min_entries=3, min_bytes=52,  # 7 entries, 104 bytes on 2026-10-23
           max_stale_days=30),
    Source(key="cloud-aws", name="Amazon AWS", parser="aws_json", kind="ip",
           tier="cloud", url="https://ip-ranges.amazonaws.com/ip-ranges.json",
           optional=True, license="Provider-published",
           homepage="https://ip-ranges.amazonaws.com",
           min_entries=12_000, min_bytes=1_900_000,  # 17,666 entries, 2.7 MB on 2026-10-23
           max_stale_days=30),
    Source(key="cloud-google", name="Google", parser="google_json", kind="ip",
           tier="cloud", url="https://www.gstatic.com/ipranges/goog.json",
           optional=True, license="Provider-published",
           homepage="https://www.gstatic.com/ipranges/goog.json",
           min_entries=100, min_bytes=4_300,  # 145 entries, 6,186 bytes on 2026-10-23
           max_stale_days=30),
    Source(key="cloud-gcloud", name="Google Cloud", parser="google_json", kind="ip",
           tier="cloud", url="https://www.gstatic.com/ipranges/cloud.json",
           optional=True, license="Provider-published",
           homepage="https://www.gstatic.com/ipranges/cloud.json",
           min_entries=780, min_bytes=80_000,  # 1,128 entries, 115 KB on 2026-10-23
           max_stale_days=30),
    Source(key="cloud-fastly", name="Fastly", parser="fastly_json", kind="ip",
           tier="cloud", url="https://api.fastly.com/public-ip-list",
           optional=True, license="Provider-published",
           homepage="https://api.fastly.com/public-ip-list",
           min_entries=16, min_bytes=310,  # 24 entries, 451 bytes on 2026-10-23
           max_stale_days=30),
    Source(key="cloud-gcore", name="G-Core", parser="gcore_json", kind="ip",
           tier="cloud", url="https://api.gcore.com/cdn/public-ip-list",
           optional=True, license="Provider-published",
           homepage="https://gcore.com",
           min_entries=1_200, min_bytes=29_000,  # 1,836 entries, 42 KB on 2026-10-23
           max_stale_days=30),

    # ---- IP: threat feeds, for firewall drop rules rather than DNS. A
    # stale threat feed is worth little, so a stored copy stands in for 7
    # days only.
    # Feodo Tracker is the authority for its own botnet C2 list (abuse.ch,
    # CC0). The list legitimately swings to near zero as C2s are taken down:
    # on 2026-10-23 the file held 5 entries (565 bytes, of which the empty
    # header-only file is ~500). So it has no entry floor and no shrink guard,
    # and a byte floor below an empty-but-valid file keeps out only a
    # truncated or error body.
    Source(key="threat-ip-malware", name="Feodo Tracker botnet C2",
           parser="cidr", kind="ip", tier="blocklist", license="CC0",
           optional=True, homepage="https://feodotracker.abuse.ch/blocklist/",
           url="https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
           min_entries=0, min_bytes=300,  # 5 entries, 565 bytes on 2026-10-23; header-only ~500
           max_shrink=1.0, max_stale_days=7),
    # HaGeZi's TIF IP list: the maintainer's aggregate of threat feeds, under
    # the project's own licence, with its official mirrors. The phishing IP
    # feed was Phishing.Database, which stopped updating on 2026-10-02 and
    # carried Google, Cloudflare and CloudFront addresses; the `phishing` IP
    # set stays empty so geoip:phishing still resolves.
    Source(key="threat-ip-hagezi", name="HaGeZi Threat Intelligence Feeds (IPs)",
           parser="cidr", kind="ip", tier="blocklist", license="GPL-3.0",
           optional=True, homepage="https://github.com/hagezi/dns-blocklists",
           url=f"https://raw.githubusercontent.com/{HAGEZI}/main/ips/tif.txt",
           mirrors=_hagezi_mirrors("ips/tif.txt"),
           min_entries=26_000, min_bytes=370_000,  # 37,191 entries, 530 KB on 2026-10-23
           max_stale_days=7),

    # ---- domains: Iranian. bootmortis is an aggregator, kept only because
    # its upstreams (enamad.ir and ito.gov.ir) time out from GitHub runners,
    # so the registries cannot be read directly. It is the one required
    # domain source; v2fly below is an independent second opinion.
    Source(key="ir-domains", name="Iran Hosted Domains", parser="domains",
           kind="domain", tier="blocklist", license="MIT",
           homepage="https://github.com/bootmortis/iran-hosted-domains",
           url="https://github.com/bootmortis/iran-hosted-domains/releases/latest/download/domains.txt",
           mirrors=("https://raw.githubusercontent.com/bootmortis/iran-hosted-domains/release/domains.txt",
                    "https://cdn.jsdelivr.net/gh/bootmortis/iran-hosted-domains@release/domains.txt"),
           min_entries=88_000, min_bytes=1_200_000,  # 127,069 entries, 1.8 MB on 2026-10-23
           max_stale_days=30),
    # v2fly's CATEGORY-IR is a hand-curated list from a different community
    # (origin: maintainer), read with our own dlc.dat decoder.
    Source(key="ir-v2fly", name="v2fly domain-list-community (category-ir)",
           parser="v2fly_dlc", kind="domain", tier="blocklist", license="MIT",
           optional=True, homepage="https://github.com/v2fly/domain-list-community",
           url="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
           min_entries=130, min_bytes=1_600_000,  # 190 entries, 2.4 MB on 2026-10-23
           max_stale_days=30),
    # The Public Suffix List (origin: authority, Mozilla). Used only as a
    # filter, so a shared platform such as a dynamic-DNS suffix is never
    # published as an Iranian or blocked domain.
    Source(key="psl", name="Public Suffix List", parser="psl", kind="domain",
           tier="official", license="MPL-2.0", optional=True,
           homepage="https://publicsuffix.org",
           url="https://publicsuffix.org/list/public_suffix_list.dat",
           mirrors=("https://raw.githubusercontent.com/publicsuffix/list/main/public_suffix_list.dat",),
           min_entries=7_200, min_bytes=230_000,  # 10,397 entries, 338 KB on 2026-10-23
           max_stale_days=30),

    # ---- domains: advertising and tracking. Origin: maintainer. The
    # PersianBlocker fork is read as its three domain lists; the hosts file
    # despite its name, and both domain files, are plain domain lists with #
    # comments, not hosts syntax.
    Source(key="ads-persian-hosts", name="PersianBlocker hosts",
           parser="domains", kind="domain", tier="blocklist",
           license="AGPL-3.0", optional=True,
           homepage="https://github.com/PersianBlocker/PersianBlocker",
           url=_PB + "PersianBlockerHosts.txt",
           mirrors=(_jsdelivr("PersianBlocker", "PersianBlocker", "main",
                              "PersianBlockerHosts.txt"),),
           min_entries=180, min_bytes=8_000,  # 261 entries, 11 KB on 2026-10-23
           max_stale_days=30),
    Source(key="ads-persian-ads", name="PersianBlocker ads domains",
           parser="domains", kind="domain", tier="blocklist",
           license="AGPL-3.0", optional=True,
           homepage="https://github.com/PersianBlocker/PersianBlocker",
           url=_PB + "PersianBlockerAds-Domains.txt",
           mirrors=(_jsdelivr("PersianBlocker", "PersianBlocker", "main",
                              "PersianBlockerAds-Domains.txt"),),
           min_entries=23, min_bytes=850,  # 34 entries, 1,215 bytes on 2026-10-23
           max_stale_days=30),
    Source(key="ads-persian-trackers", name="PersianBlocker trackers domains",
           parser="domains", kind="domain", tier="blocklist",
           license="AGPL-3.0", optional=True,
           homepage="https://github.com/PersianBlocker/PersianBlocker",
           url=_PB + "PersianBlockerTrackers-Domains.txt",
           mirrors=(_jsdelivr("PersianBlocker", "PersianBlocker", "main",
                              "PersianBlockerTrackers-Domains.txt"),),
           min_entries=17, min_bytes=1_000,  # 25 entries, 1,467 bytes on 2026-10-23
           max_stale_days=30),
    # "light" rather than "pro": pro is ~217k domains and pushes geosite.dat
    # past what is comfortable to ship to a phone, for a false-positive rate
    # that is worse, not better.
    Source(key="ads-hagezi", name="HaGeZi Multi LIGHT", parser="domains",
           kind="domain", tier="blocklist", license="GPL-3.0", optional=True,
           homepage="https://github.com/hagezi/dns-blocklists",
           url=f"https://raw.githubusercontent.com/{HAGEZI}/main/wildcard/light-onlydomains.txt",
           mirrors=_hagezi_mirrors("wildcard/light-onlydomains.txt"),
           min_entries=49_000, min_bytes=1_000_000,  # 70,378 entries, 1.5 MB on 2026-10-23
           max_stale_days=30),

    # ---- domains: allowlists. Origin: maintainer (AdGuard's own exclusions
    # and exceptions). Never blocked, only subtracted from the blocklists
    # above: names AdGuard found to break real sites. Read by the adguard_allow
    # parser, which takes ||name^ and @@||name^ rules and nothing else.
    Source(key="allow-adguard-exclusions", name="AdGuard DNS filter exclusions",
           parser="adguard_allow", kind="domain", tier="official",
           license="GPL-3.0", optional=True,
           homepage="https://github.com/AdguardTeam/AdGuardSDNSFilter",
           url="https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exclusions.txt",
           mirrors=(_jsdelivr("AdguardTeam", "AdGuardSDNSFilter", "master",
                              "Filters/exclusions.txt"),),
           min_entries=310, min_bytes=28_000,  # 454 entries, 41 KB on 2026-10-23
           max_stale_days=30),
    Source(key="allow-adguard-exceptions", name="AdGuard DNS filter exceptions",
           parser="adguard_allow", kind="domain", tier="official",
           license="GPL-3.0", optional=True,
           homepage="https://github.com/AdguardTeam/AdGuardSDNSFilter",
           url="https://raw.githubusercontent.com/AdguardTeam/AdGuardSDNSFilter/master/Filters/exceptions.txt",
           mirrors=(_jsdelivr("AdguardTeam", "AdGuardSDNSFilter", "master",
                              "Filters/exceptions.txt"),),
           min_entries=120, min_bytes=13_000,  # 174 entries, 19 KB on 2026-10-23
           max_stale_days=30),

    # ---- domains: security. Origin: maintainer, except CERT Polska (a
    # national CERT, so authority). A stale threat feed is worth little: 7
    # days.
    # URLhaus data is off limits: abuse.ch's terms (effective 2025-11-04)
    # restrict it to authenticated not-for-profit use and forbid derivative
    # works, and that carries into every mirror of it. HaGeZi's TIF mini is a
    # size-optimised aggregate of threat feeds under the project's own
    # licence, built to stay off popular domains.
    Source(key="malware-hagezi-tif", name="HaGeZi Threat Intelligence Feeds mini",
           parser="domains", kind="domain", tier="blocklist",
           license="GPL-3.0", optional=True,
           homepage="https://github.com/hagezi/dns-blocklists",
           url=f"https://raw.githubusercontent.com/{HAGEZI}/main/wildcard/tif.mini-onlydomains.txt",
           mirrors=_hagezi_mirrors("wildcard/tif.mini-onlydomains.txt"),
           min_entries=140_000, min_bytes=2_700_000,  # 213,814 entries, 3.9 MB on 2026-10-23
           max_stale_days=7),
    # Replaces Phishing.Database, which stopped updating on 2026-10-02 and
    # listed whole platforms (sites.google.com, bit.ly, nflxvideo.net). CERT
    # Polska's terms allow use "for any purpose, including commercial".
    Source(key="phishing-certpl", name="CERT Polska warning list",
           parser="domains", kind="domain", tier="blocklist",
           license="free for any use", optional=True,
           homepage="https://cert.pl/en/warning-list/",
           url="https://hole.cert.pl/domains/v2/domains.txt",
           min_entries=87_000, min_bytes=1_700_000,  # 125,273 entries, 2.6 MB on 2026-10-23
           max_stale_days=7),
    Source(key="crypto-nocoin", name="NoCoin adblock list", parser="hosts",
           kind="domain", tier="blocklist", license="MIT", optional=True,
           homepage="https://github.com/hoshsadiq/adblock-nocoin-list",
           url="https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
           mirrors=(_jsdelivr("hoshsadiq", "adblock-nocoin-list", "master",
                              "hosts.txt"),),
           min_entries=210, min_bytes=5_700,  # 312 entries, 8,150 bytes on 2026-10-23
           max_stale_days=7),

    # ---- domains: adult content and gambling. Origin: maintainer
    # (StevenBlack's unified hosts, two of its alternates).
    Source(key="nsfw-stevenblack", name="StevenBlack unified hosts (porn)",
           parser="hosts", kind="domain", tier="blocklist", license="MIT",
           optional=True, homepage="https://github.com/StevenBlack/hosts",
           url="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts",
           mirrors=(_jsdelivr("StevenBlack", "hosts", "master",
                              "alternates/porn-only/hosts"),),
           min_entries=53_000, min_bytes=1_300_000,  # 76,798 entries, 2.0 MB on 2026-10-23
           max_stale_days=30),
    Source(key="nsfw-stevenblack-gambling",
           name="StevenBlack unified hosts (gambling)",
           parser="hosts", kind="domain", tier="blocklist", license="MIT",
           optional=True, homepage="https://github.com/StevenBlack/hosts",
           url="https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling-only/hosts",
           mirrors=(_jsdelivr("StevenBlack", "hosts", "master",
                              "alternates/gambling-only/hosts"),),
           min_entries=4_600, min_bytes=100_000,  # 6,712 entries, 149 KB on 2026-10-23
           max_stale_days=30),
]

BY_KEY = {s.key: s for s in SOURCES}


# ------------------------------------------------------------------- parsers


class Parsed(NamedTuple):
    """What every parser returns.

    `invalid` counts lines that have the shape of an entry but fail
    validation. Lines skipped on purpose (comments, other countries, rules
    with options this parser does not support) are not invalid, so a feed that
    turns to garbage stands out in the count instead of hiding in it.
    """
    values: list[str]
    invalid: int


_HOSTS_RE = re.compile(r"^\s*(?:0\.0\.0\.0|127\.0\.0\.1|::1?)\s+(\S+)")
_ADBLOCK_RE = re.compile(r"^\|\|([A-Za-z0-9._-]+)\^")
_ADGUARD_ALLOW_RE = re.compile(r"^(?:@@)?\|\|([A-Za-z0-9._-]+)\^\|?$")
_AS_RE = re.compile(r"AS([0-9]+)")

_MAX_ASN = 2 ** 32 - 1

# A route seen by only a few collectors is more likely a leak or a bad
# announcement than a real route, and so is a prefix shorter than these.
_RIS_MIN_PEERS = 10
_RIS_MIN_LENGTH = {4: 8, 6: 16}


def _text(raw: bytes) -> str:
    # utf-8-sig: a BOM would otherwise stay glued to the first entry
    return raw.decode("utf-8-sig", errors="replace")


def _networks(items) -> Parsed:
    """Validate CIDR strings. Bare addresses become /32 or /128."""
    out, bad = [], 0
    for item in items:
        # ip_network() would read a JSON number as an integer address
        if not isinstance(item, str):
            bad += 1
            continue
        try:
            out.append(str(ipaddress.ip_network(item, strict=False)))
        except ValueError:
            bad += 1
    return Parsed(out, bad)


def _domains(names) -> Parsed:
    """Run clean_domain over candidate names and count the rejects."""
    out, bad = [], 0
    for name in names:
        cleaned = clean_domain(name)
        if cleaned is None:
            bad += 1
        else:
            out.append(cleaned)
    return Parsed(out, bad)


def parse_cidr(raw: bytes) -> Parsed:
    lines = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0].split(";", 1)[0].strip()
        if line:
            lines.append(line)
    return _networks(lines)


def parse_rir(raw: bytes, country: str = "IR") -> Parsed:
    """Extract one country's delegations from a RIR delegated-stats file.

    Lines are registry|cc|type|start|value|date|status[|opaque-id]. For IPv4
    `value` is a host count, not a prefix length; for IPv6 it is the prefix
    length; for an asn record it is how many consecutive ASNs start at `start`.
    Only allocated and assigned records are delegated to anyone. Prefixes come
    out as CIDRs and ASNs as "AS<n>".
    """
    out, bad = [], 0
    for line in _text(raw).splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 7 or parts[1] != country:
            continue
        _, _, kind, start, value, _date, status = parts[:7]
        if status not in ("allocated", "assigned"):
            continue
        try:
            if kind == "ipv4":
                first = ipaddress.IPv4Address(start)
                last = ipaddress.IPv4Address(int(first) + int(value) - 1)
                out.extend(str(n) for n in
                           ipaddress.summarize_address_range(first, last))
            elif kind == "ipv6":
                out.append(str(ipaddress.ip_network(f"{start}/{int(value)}",
                                                    strict=False)))
            elif kind == "asn":
                first, count = int(start), int(value)
                # bounded so one corrupt count cannot expand into billions
                if first < 0 or count < 1 or first + count - 1 > _MAX_ASN:
                    raise ValueError(line)
                out.extend(f"AS{n}" for n in range(first, first + count))
        except ValueError:
            bad += 1
    return Parsed(out, bad)


def parse_aws_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    return _networks([p["ip_prefix"] for p in data.get("prefixes", [])] +
                     [p["ipv6_prefix"] for p in data.get("ipv6_prefixes", [])])


def parse_google_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    out = []
    for p in data.get("prefixes", []):
        if "ipv4Prefix" in p:
            out.append(p["ipv4Prefix"])
        if "ipv6Prefix" in p:
            out.append(p["ipv6Prefix"])
    return _networks(out)


def parse_fastly_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    return _networks(data.get("addresses", []) + data.get("ipv6_addresses", []))


def parse_gcore_json(raw: bytes) -> Parsed:
    data = json.loads(_text(raw))
    return _networks(data.get("addresses", []) + data.get("addresses_v6", []))


def parse_ris(raw: bytes) -> Parsed:
    """Read a RIPE RIS whois dump: origin, prefix and peer count per row.

    The dump is published gzipped, so a gzip stream is unpacked first (a
    truncated one raises rather than parsing as a shorter table). Values are
    "<origin> <prefix>". Rows seen by fewer than 10 peers or shorter than
    /8 (IPv4) or /16 (IPv6) are dropped, and so are AS-set origins like
    "{1,2}", which name no single owner. Those are filters, not errors.
    """
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.decompress(raw)
    out, bad = [], 0
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("%"):
            continue
        parts = line.split()
        if len(parts) < 3:
            bad += 1
            continue
        origin, prefix, peers = parts[:3]
        if origin.startswith("{"):
            continue
        try:
            asn, seen = int(origin), int(peers)
            net = ipaddress.ip_network(prefix)
            if not 0 <= asn <= _MAX_ASN or seen < 0:
                raise ValueError(line)
        except ValueError:
            bad += 1
            continue
        if seen >= _RIS_MIN_PEERS and net.prefixlen >= _RIS_MIN_LENGTH[net.version]:
            out.append(f"{asn} {net}")
    return Parsed(out, bad)


def parse_ripe_org_asns(raw: bytes) -> Parsed:
    """Take the aut-num of every object in a RIPE database search result."""
    data = json.loads(_text(raw))
    out, bad = [], 0
    for obj in data.get("objects", {}).get("object", []):
        for attr in obj.get("attributes", {}).get("attribute", []):
            if attr.get("name") != "aut-num":
                continue
            m = _AS_RE.fullmatch(str(attr.get("value", "")).strip().upper())
            if m and int(m.group(1)) <= _MAX_ASN:
                out.append(f"AS{int(m.group(1))}")
            else:
                bad += 1
    return Parsed(out, bad)


def parse_v2fly_dlc(raw: bytes) -> Parsed:
    """Pull CATEGORY-IR out of a v2fly dlc.dat.

    `domain` entries come out as the bare name and `full` entries as
    "full:<name>", so a later stage can tell a suffix from an exact match.
    Keywords and regexps cannot be expressed as a name and are skipped.
    """
    out, bad = [], 0
    for cat in geodat.decode_geosite(raw):
        if cat.code.upper() != "CATEGORY-IR":
            continue
        for kind, value in cat.domains:
            if kind not in (geodat.ROOT_DOMAIN, geodat.FULL):
                continue
            name = clean_domain(value)
            if name is None:
                bad += 1
            else:
                out.append(f"full:{name}" if kind == geodat.FULL else name)
    return Parsed(out, bad)


def parse_psl(raw: bytes) -> Parsed:
    """Read the Public Suffix List.

    ICANN rules come out as written and private-section rules as
    "private:<rule>", lower-cased, with any "*." or "!" kept as is. They are
    rules rather than hostnames, so they do not go through clean_domain, which
    would strip the wildcard and reject the exception marker.
    """
    out, bad = [], 0
    private = False
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("//"):
            # the section markers are comments, so they are read before the
            # comments are skipped
            if "===BEGIN PRIVATE DOMAINS===" in line:
                private = True
            elif "===END PRIVATE DOMAINS===" in line:
                private = False
            continue
        # a line is read only up to its first whitespace
        rule = line.split()[0].lower()
        body = rule[1:] if rule.startswith("!") else rule
        if body.startswith("*."):
            body = body[2:]
        labels = body.split(".")
        if not all(labels) or any(c in label for label in labels for c in "*!/"):
            bad += 1
            continue
        out.append(f"private:{rule}" if private else rule)
    return Parsed(out, bad)


def parse_hosts(raw: bytes) -> Parsed:
    names = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0]
        m = _HOSTS_RE.match(line)
        if m:
            names.append(m.group(1))
    return _domains(names)


def parse_domains(raw: bytes) -> Parsed:
    names = []
    for line in _text(raw).splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("!", "[")):
            continue
        # a few upstreams ship "0.0.0.0 domain" inside a "domains" file
        parts = line.split()
        names.append(parts[-1] if len(parts) > 1 else line)
    return _domains(names)


def parse_adblock(raw: bytes) -> Parsed:
    """Take only plain ||domain^ rules.

    Anything with options ($third-party), an exception (@@) or a path is not a
    whole-domain block and must not be turned into one.
    """
    names = []
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith(("!", "@@", "[")):
            continue
        if "$" in line or "/" in line.rstrip("^"):
            continue
        m = _ADBLOCK_RE.match(line)
        if m:
            names.append(m.group(1))
    return _domains(names)


def parse_adguard_allow(raw: bytes) -> Parsed:
    """Take the names from plain ||name^ and @@||name^ rules.

    AdGuard's allowlist files use both ||name^ and @@||name^| for "do not
    block this name", so both are read. A rule with options ($important) or a
    regexp is not a whole-name rule and is skipped.
    """
    names = []
    for line in _text(raw).splitlines():
        m = _ADGUARD_ALLOW_RE.match(line.strip())
        if m:
            names.append(m.group(1))
    return _domains(names)


PARSERS = {
    "cidr": parse_cidr, "rir": parse_rir,
    "aws_json": parse_aws_json, "google_json": parse_google_json,
    "fastly_json": parse_fastly_json, "gcore_json": parse_gcore_json,
    "ris": parse_ris, "ripe_org_asns": parse_ripe_org_asns,
    "v2fly_dlc": parse_v2fly_dlc, "psl": parse_psl,
    "hosts": parse_hosts, "domains": parse_domains,
    "adblock": parse_adblock, "adguard_allow": parse_adguard_allow,
}


if __name__ == "__main__":
    # every source against a throwaway state store: python3 build/sources.py [cache]
    import tempfile

    import fetch

    with tempfile.TemporaryDirectory() as tmp:
        try:
            h = fetch.harvest(SOURCES, fetch.StateStore(tmp),
                              cache_dir=sys.argv[1] if len(sys.argv) > 1 else None)
        except fetch.SourceUnavailable as exc:
            sys.exit(f"ERROR: {exc}")
    print(f"\n{len(h.values)} sources ok, {len(h.failed)} failed")
