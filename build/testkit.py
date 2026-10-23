"""Assertion helpers shared by the plain-script tests.

    from testkit import eq, ok, done
    eq(got, want, "label")
    done()      # prints the tally and exits non-zero on any failure
"""

from __future__ import annotations

import sys

_passed = 0
_failed = 0


def eq(got, want, label: str) -> None:
    global _passed, _failed
    if got == want:
        _passed += 1
    else:
        _failed += 1
        print(f"  FAIL {label}\n       got:  {got!r}\n       want: {want!r}")


def ok(cond, label: str) -> None:
    eq(bool(cond), True, label)


def done() -> None:
    print(f"{_passed}/{_passed + _failed} checks passed")
    sys.exit(1 if _failed else 0)
