## What this changes

<!-- One or two sentences. If it adds a source or a format, say which. -->

## Checks

- [ ] `python3 build/test_units.py` passes
- [ ] `python3 build/geodat.py` passes
- [ ] A full build followed by `python3 build/verify.py dist` passes

## If this adds a source

- [ ] Marked `optional=True` unless the build is worthless without it
- [ ] Parser covered in `build/test_units.py`
- [ ] Attribution row added to the README table

## If this adds an output format

- [ ] The emitter does not mutate the dataset
- [ ] Anything the format cannot represent is dropped and counted via `note=`
