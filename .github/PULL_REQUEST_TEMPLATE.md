## What this changes

<!-- One or two sentences. If it adds a source or a format, say which. -->

## Checks

- [ ] `for t in build/test_*.py; do python3 "$t" || exit 1; done` passes
- [ ] `python3 build/geodat.py` passes
- [ ] A full build followed by `python3 build/verify.py dist` passes

## If this adds a source

- [ ] Its licence allows redistribution and derivative works
- [ ] Marked `optional=True` unless the build is worthless without it
- [ ] Floors (`min_entries`, `min_bytes`) set to about 70 % of what it returned, with the figure in a comment
- [ ] `max_stale_days` chosen for how fast the data goes stale
- [ ] Parser covered in `build/test_units.py`
- [ ] Attribution row added to the README table

## If this adds an Iranian provider

- [ ] Added by RIPE organisation handle in `PROVIDERS`, with an entry in `_RIPE_ORG_FLOOR`

## If this adds an output format

- [ ] The emitter does not mutate the dataset
- [ ] Anything the format cannot represent is dropped and counted via `note=`
