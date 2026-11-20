## What this changes

<!-- One or two sentences. If it adds a source or a format, say which. -->

## Checks

- [ ] `( for t in build/test_*.py; do python3 -W error::ResourceWarning "$t" || exit 1; done )` passes
- [ ] `python3 -W error::ResourceWarning build/geodat.py` passes
- [ ] A full build followed by `python3 build/verify.py dist` passes

## If this adds a curated domain (`data/ir-domains-add.txt` / `data/ir-domains-exclude.txt`)

- [ ] Verified active DNS resolution and hosting / origin ASN
- [ ] Not under `.ir` / `.ایران` (already covered by collapsed TLD rules) and not a PSL private shared-hosting suffix
- [ ] Also reported upstream where applicable (`bootmortis/iran-hosted-domains` or `v2fly/domain-list-community`)

## If this adds a source

- [ ] Its licence allows redistribution and derivative works
- [ ] Marked `optional=True` unless the build is worthless without it
- [ ] Floors (`min_entries`, `min_bytes`) set to about 70 % of what it returned, with the figure in a comment
- [ ] `max_stale_days` chosen for how fast the data goes stale
- [ ] Parser covered in `build/test_units.py`
- [ ] Attribution row added to the README table

## If this adds an Iranian provider

- [ ] Added by RIPE organisation handle in `PROVIDERS`, with an entry in `_RIPE_ORG_FLOOR` and `domestic` flag verified against BGP upstream transit

## If this adds an output format

- [ ] The emitter does not mutate the dataset
- [ ] Anything the format cannot represent is dropped and counted via `note=`
