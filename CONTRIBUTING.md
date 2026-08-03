# Contributing

Thanks for helping out. There are two useful ways to contribute, and picking
the right one matters — one of them fixes the problem for everyone using this
kind of data, and the other only fixes it here.

## 1. Fix it upstream (preferred)

This repository **generates nothing of its own**. Every domain and every IP
prefix comes from a source listed in the README. If a domain is wrong, the
fix belongs upstream, where it also reaches everyone else consuming that list.

| What you found | Where it belongs |
|---|---|
| An Iranian site missing from the `ir` domain set | [bootmortis/iran-hosted-domains](https://github.com/bootmortis/iran-hosted-domains/issues) |
| A Persian ad or tracker not blocked | [MasterKia/PersianBlocker](https://github.com/MasterKia/PersianBlocker/issues) |
| A false positive in the ads list | [HaGeZi](https://github.com/hagezi/dns-blocklists/issues) or [AdGuard](https://github.com/AdguardTeam/AdGuardSDNSFilter/issues) |
| A wrong malware / phishing entry | [URLhaus](https://urlhaus.abuse.ch), [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database/issues) |
| An IP prefix wrongly attributed to Iran | See below — this one is usually ours |

Once upstream merges it, the next daily build picks it up automatically. No
action needed here.

## 2. IP attribution problems

IP data is different: it comes from the Regional Internet Registries' own
delegation records, so a genuine misattribution is either a registry error or
a bug in our parsing.

Open an issue with:

- the exact prefix or address
- what you believe it should be
- evidence — `whois`, the RIR record, or a traceroute

Check first whether the address is in `ir` or in `ir-cdn`. Those are different
sets on purpose: `ir-cdn` carries ranges published by Iranian CDN providers,
and some of those are foreign edge nodes. That is expected, not a bug.

## 3. Code

```bash
git clone https://github.com/Arman2122/IR-Geo-DB && cd IR-Geo-DB
python3 build/test_units.py     # offline, fast
python3 build/geodat.py         # protobuf round-trip self-test
python3 build/build.py --outdir dist --cache .cache
python3 build/verify.py dist
```

Python 3.10+, standard library only. **Please keep it that way** — this has to
run on a bare GitHub Actions runner with no install step, and a dependency
that breaks takes the daily build down with it.

`sing-box` and `mihomo` on `PATH` (or `$SING_BOX` / `$MIHOMO`) enable the
`.srs` and `.mrs` outputs. Without them everything else still builds.

### Adding a source

1. Add a `Source(...)` entry in `build/sources.py`.
2. Reuse an existing `parser`, or add one and cover it in `build/test_units.py`.
3. Mark it `optional=True` unless the build is worthless without it — a
   required source that goes offline stops the daily release for everyone.
4. Wire it into a dataset in `build/build.py`.
5. Add the attribution row to the README table. This is not optional; several
   sources require it by licence.

### Adding an output format

Add one function to `build/emitters.py` and register it in the relevant list.
Emitters must not mutate the dataset.

If the format cannot express a match type — keywords and regexes have no
meaning in a hosts file — **drop what you cannot represent and record the
count** via the `note=` argument. Never emit a rule that means something
different from what the source said.

### Before opening a PR

- `python3 build/test_units.py` passes
- `python3 build/geodat.py` passes
- A full build followed by `python3 build/verify.py dist` passes

CI runs the first two on every push. The third needs network access, so it
runs on the schedule.

## Style

Match what is already there. Comments explain *why* a thing is the way it is,
not what the line does — the non-obvious constraint, the format quirk, the
reason an approach that looks simpler is wrong.
