#!/usr/bin/env python3
"""
test_fetch.py — offline tests for acquiring and trusting a source.

    python3 build/test_fetch.py

No network: every request goes to a fake opener, and backoff sleeps are
recorded instead of slept.
"""

from __future__ import annotations

import dataclasses
import email.message
import gzip
import hashlib
import http.client
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fetch  # noqa: E402
from fetch import FetchError, Response, StateStore  # noqa: E402
from sources import Source  # noqa: E402
from testkit import done, eq, ok  # noqa: E402

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)
STAMP = "2026-10-23T12:00:00Z"
PRIMARY, MIRROR = "https://p/x", "https://m/x"

GOOD = b"1.0.0.0/24\n2.0.0.0/24\n3.0.0.0/24\n"
GOOD_VALUES = ["1.0.0.0/24", "2.0.0.0/24", "3.0.0.0/24"]

BASE = Source(key="t", name="T", url=PRIMARY, parser="cidr", kind="ip", tier="t",
              mirrors=(MIRROR,), min_entries=2, optional=True, max_stale_days=7)

_TMP = tempfile.TemporaryDirectory()


def src(**changes) -> Source:
    return dataclasses.replace(BASE, **changes)


def new_store() -> StateStore:
    return StateStore(tempfile.mkdtemp(dir=_TMP.name))


def resp(body: bytes, headers: dict | None = None, status: int = 200) -> Response:
    return Response(status, headers or {}, body)


def body(n: int) -> bytes:
    """n distinct /24s."""
    return "".join(f"10.{i // 256}.{i % 256}.0/24\n" for i in range(n)).encode()


def noop(_seconds) -> None:
    pass


class Opener:
    """A fake http_get. Each URL maps to a Response or an exception to raise;
    an unknown URL is unreachable. Calls and request headers are recorded."""

    def __init__(self, routes: dict, delay: dict | None = None):
        self.routes, self.delay = routes, delay or {}
        self.calls: dict[str, int] = {}
        self.headers: dict[str, dict] = {}
        self.lock = threading.Lock()

    def __call__(self, url: str, headers: dict, timeout: int = 120) -> Response:
        with self.lock:
            self.calls[url] = self.calls.get(url, 0) + 1
            self.headers[url] = dict(headers)
        time.sleep(self.delay.get(url, 0))
        route = self.routes.get(url, FetchError(0, "connection refused"))
        if isinstance(route, Exception):
            raise route
        return route


def seed(st: StateStore, s: Source, raw: bytes, at: datetime,
         headers: dict | None = None) -> None:
    """Put a validated copy in the store, the way a past run would have."""
    o = fetch.acquire(s, st, opener=Opener({s.url: resp(raw, headers)}),
                      now=at, sleep=noop)
    assert o.status == "fresh", o


# ------------------------------------------- 1 primary 5xx, mirror serves it

st = new_store()
op = Opener({PRIMARY: FetchError(500, "Internal Server Error"),
             MIRROR: resp(GOOD, {"etag": '"v1"',
                                 "last-modified": "Thu, 22 Oct 2026 00:00:00 GMT"})})
slept: list = []
o = fetch.acquire(src(), st, opener=op, now=NOW, sleep=slept.append)
eq(o.status, "fresh", "1 mirror fallback: fresh")
eq(o.served_by, "mirror-1", "1 mirror fallback: served_by")
eq(o.url_used, MIRROR, "1 mirror fallback: url_used")
eq(o.values, GOOD_VALUES, "1 mirror fallback: values parsed")
eq((o.bytes, o.sha256), (len(GOOD), hashlib.sha256(GOOD).hexdigest()),
   "1 mirror fallback: size and digest of the raw body")
eq((o.fetched_at, o.validated_at), (STAMP, STAMP), "1 timestamps are ISO-8601 UTC")
eq(op.calls[PRIMARY], 4, "1 a 5xx is retried, 4 attempts in all")
eq(slept, [2, 4, 8], "1 backoff between attempts, none after the last")
ok("primary" in o.error and "500" in o.error, "1 the primary's failure is recorded")
saved = st.load("t")
eq(saved and saved[0], GOOD_VALUES, "1 state saved: values")
eq(saved and {k: saved[1][k] for k in ("url_used", "etag", "validated_at", "entries")},
   {"url_used": MIRROR, "etag": '"v1"', "validated_at": STAMP, "entries": 3},
   "1 state saved: metadata")

# ------------------------------------------ 2 everything down, copy 3 days old

st = new_store()
seed(st, src(), GOOD, NOW - timedelta(days=3))
o = fetch.acquire(src(), st, opener=Opener({}), now=NOW, sleep=noop)
eq(o.status, "stale", "2 all down, recent copy: stale")
eq(o.served_by, "state", "2 stale: served_by state")
eq(o.stale_days, 3.0, "2 stale: age in days")
eq(o.values, GOOD_VALUES, "2 stale: stored values used")
eq(o.validated_at, "2026-10-20T12:00:00Z", "2 stale: validated_at is the copy's")
ok("primary" in o.error and "mirror-1" in o.error, "2 stale: every URL's failure kept")

# ---------------------------------------- 3 everything down, copy 8 days old

st = new_store()
seed(st, src(), GOOD, NOW - timedelta(days=8))
o = fetch.acquire(src(), st, opener=Opener({}), now=NOW, sleep=noop)
eq((o.status, o.values, o.served_by), ("dropped", [], ""),
   "3 all down, copy too old: dropped")
ok("max_stale_days" in o.error, "3 dropped: the reason names the stale limit")
eq(fetch.acquire(src(max_stale_days=14), st, opener=Opener({}), now=NOW,
                 sleep=noop).status, "stale", "3 max_stale_days is per source")

lines: list = []
try:
    fetch.harvest([src(optional=False)], st, log=lines.append,
                  opener=Opener({}), now=NOW, sleep=noop)
    msg = None
except fetch.SourceUnavailable as exc:
    msg = str(exc)
ok(msg and "t" in msg, "3 a required source with no usable copy raises")
eq(len(lines), 1, "3 the source is logged before the raise")
ok(lines and "ERROR" in lines[0] and "dropped" in lines[0], "3 logged as an error")

# ----------------------------------------------------------- 4 not modified

st = new_store()
LM = "Wed, 21 Oct 2026 08:00:00 GMT"
seed(st, src(), GOOD, NOW - timedelta(days=2), {"etag": '"v1"', "last-modified": LM})
op = Opener({PRIMARY: resp(b"", status=304)})
o = fetch.acquire(src(), st, opener=op, now=NOW, sleep=noop)
eq(o.status, "not-modified", "4 304: not-modified")
eq((o.served_by, o.values), ("primary", GOOD_VALUES), "4 304: stored values reused")
eq(op.headers[PRIMARY].get("If-None-Match"), '"v1"', "4 304: If-None-Match sent")
eq(op.headers[PRIMARY].get("If-Modified-Since"), LM, "4 304: If-Modified-Since sent")
eq(o.bytes, len(GOOD), "4 304: size of the stored body")
eq(st.load("t")[1]["validated_at"], STAMP, "4 304: the stored copy is revalidated")

# validators belong to the URL that served the copy, not to its mirror
op = Opener({PRIMARY: FetchError(404, "Not Found"), MIRROR: resp(GOOD)})
fetch.acquire(src(), st, opener=op, now=NOW, sleep=noop)
eq(op.headers[MIRROR], {}, "4 no validators sent to a different URL")

# a 304 to a request that asked for nothing is that URL failing
op = Opener({PRIMARY: resp(b"", status=304), MIRROR: resp(GOOD)})
o = fetch.acquire(src(), new_store(), opener=op, now=NOW, sleep=noop)
eq((o.status, o.served_by), ("fresh", "mirror-1"), "4 304 without a stored copy: next URL")

# --------------------------------------------------------- 5 an HTML page

for page in (b"<!DOCTYPE html><html><body>1.2.3.0/24</body></html>",
             b"\n  <HTML><head><title>Just a moment...</title>"):
    op = Opener({PRIMARY: resp(page), MIRROR: resp(GOOD)})
    o = fetch.acquire(src(), new_store(), opener=op, now=NOW, sleep=noop)
    eq((o.status, o.served_by), ("fresh", "mirror-1"), f"5 HTML rejected: {page[:12]!r}")
    ok("HTML" in o.error, "5 the HTML rejection is recorded")
    eq(op.calls[PRIMARY], 1, "5 a rejected body is not retried")

# ------------------------------------------------------------ 6 the floors

op = Opener({PRIMARY: resp(b"1.0.0.0/24\n"), MIRROR: resp(GOOD)})
o = fetch.acquire(src(), new_store(), opener=op, now=NOW, sleep=noop)
eq(o.served_by, "mirror-1", "6 fewer than min_entries: rejected")
ok("min_entries" in o.error, "6 the min_entries rejection is recorded")

op = Opener({PRIMARY: resp(GOOD), MIRROR: resp(body(100))})
o = fetch.acquire(src(min_bytes=1000), new_store(), opener=op, now=NOW, sleep=noop)
eq(o.served_by, "mirror-1", "6 under min_bytes: rejected")
ok("min_bytes" in o.error, "6 the min_bytes rejection is recorded")

op = Opener({PRIMARY: resp(b"")})
eq(fetch.acquire(src(min_entries=0, mirrors=()), new_store(), opener=op, now=NOW,
                 sleep=noop).status, "fresh", "6 zero floors accept an empty body")

# ------------------------------------------------------------- 7 shrinkage

st = new_store()
seed(st, src(mirrors=()), body(1000), NOW - timedelta(days=1))
o = fetch.acquire(src(mirrors=()), st, opener=Opener({PRIMARY: resp(body(400))}),
                  now=NOW, sleep=noop)
eq(o.status, "stale", "7 1000 -> 400 entries with max_shrink 0.5: rejected")
ok("shrank" in o.error, "7 the shrink rejection is recorded")
o = fetch.acquire(src(mirrors=()), st, opener=Opener({PRIMARY: resp(body(600))}),
                  now=NOW, sleep=noop)
eq((o.status, len(o.values)), ("fresh", 600), "7 1000 -> 600 entries: accepted")

st = new_store()
seed(st, src(mirrors=()), body(50), NOW - timedelta(days=1))
o = fetch.acquire(src(mirrors=()), st, opener=Opener({PRIMARY: resp(GOOD)}),
                  now=NOW, sleep=noop)
eq(o.status, "fresh", "7 no shrink check against a stored copy under 100 entries")

# ----------------------------------------------------------- 8 404 and 410

for code in (404, 410):
    op = Opener({PRIMARY: FetchError(code, "gone"), MIRROR: resp(GOOD)})
    slept = []
    o = fetch.acquire(src(), new_store(), opener=op, now=NOW, sleep=slept.append)
    eq(op.calls[PRIMARY], 1, f"8 {code}: no retry")
    eq(slept, [], f"8 {code}: no backoff")
    eq(o.served_by, "mirror-1", f"8 {code}: the mirror is tried")

# ------------------------------------------- 9 first run, source unreachable

st = new_store()
o = fetch.acquire(src(), st, opener=Opener({}), now=NOW, sleep=noop)
eq((o.status, o.values), ("dropped", []), "9 nothing stored, all down: dropped")
ok("nothing stored" in o.error, "9 dropped: the reason says nothing was stored")
h = fetch.harvest([src()], st, log=lambda _m: None, opener=Opener({}), now=NOW,
                  sleep=noop)
eq(("t" in h.values, list(h.failed)), (False, ["t"]),
   "9 an optional source is dropped without an exception")

# ------------------------------------------------------- 10 http_get itself

eq(fetch._decode(gzip.compress(b"1.2.3.0/24\n"), {"content-encoding": "gzip"}),
   b"1.2.3.0/24\n", "10 _decode unpacks Content-Encoding: gzip")
eq(fetch._decode(b"plain", {}), b"plain", "10 _decode leaves an identity body alone")


class FakeHTTPResponse:
    def __init__(self, status: int, headers: dict, payload):
        self.status, self._payload = status, payload
        self.headers = email.message.Message()
        for k, v in headers.items():
            self.headers[k] = v

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def read(self) -> bytes:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


def http_get_with(answer, headers: dict | None = None):
    """Run fetch.http_get with urlopen answering `answer`; return the result
    (or the FetchError raised) and the request that was sent."""
    sent = {}

    def fake_urlopen(req, timeout=None):
        sent["req"] = req
        if isinstance(answer, Exception):
            raise answer
        return answer

    real, urllib.request.urlopen = urllib.request.urlopen, fake_urlopen
    try:
        return fetch.http_get("https://x/y", headers or {}), sent["req"]
    except FetchError as exc:
        return exc, sent["req"]
    finally:
        urllib.request.urlopen = real


r, req = http_get_with(FakeHTTPResponse(200, {"Content-Encoding": "gzip", "ETag": '"e1"'},
                                        gzip.compress(b"1.2.3.0/24\n")),
                       {"If-None-Match": '"e0"'})
eq((r.status, r.body), (200, b"1.2.3.0/24\n"), "10 http_get decodes a gzip body")
eq(r.headers.get("etag"), '"e1"', "10 response header keys are lower-cased")
eq(req.get_header("If-none-match"), '"e0"', "10 request headers are sent")
ok(req.get_header("User-agent", "").startswith("IR-Geo-DB"), "10 User-Agent is sent")

r, _ = http_get_with(urllib.error.HTTPError("https://x/y", 304, "Not Modified",
                                            email.message.Message(), None))
eq(r, Response(304, {}, b""), "10 a 304 is a Response with an empty body")
r, _ = http_get_with(urllib.error.HTTPError("https://x/y", 404, "Not Found",
                                            email.message.Message(), None))
eq((type(r), getattr(r, "status", None)), (FetchError, 404), "10 a 404 raises FetchError(404)")
for err in (urllib.error.URLError("no route"), TimeoutError("timed out")):
    r, _ = http_get_with(err)
    eq((type(r), getattr(r, "status", None)), (FetchError, 0),
       f"10 {type(err).__name__} raises FetchError(0)")
r, _ = http_get_with(FakeHTTPResponse(200, {}, http.client.IncompleteRead(b"x", 10)))
eq((type(r), getattr(r, "status", None)), (FetchError, 0), "10 IncompleteRead raises FetchError(0)")

# ------------------------------------------------ 11 harvest, in parallel

srcs = [src(key=k, url=f"https://{k}/x", mirrors=()) for k in ("a", "b", "c")]
st = new_store()
seed(st, srcs[2], GOOD, NOW - timedelta(days=3))
# a is slowest, so completion order is not registry order
op = Opener({"https://a/x": resp(GOOD), "https://b/x": resp(GOOD + b"4.0.0.0/24\n")},
            delay={"https://a/x": 0.3})
lines = []
h = fetch.harvest(srcs, st, log=lines.append, workers=2, opener=op, now=NOW, sleep=noop)
eq(list(h.outcomes), ["a", "b", "c"], "11 outcomes keyed in registry order")
eq(list(h.values), ["a", "b", "c"], "11 values keyed in registry order")
eq([ln.split()[1] for ln in lines], ["a", "b", "c"], "11 log lines in registry order")
eq(h.get("b"), GOOD_VALUES + ["4.0.0.0/24"], "11 get() returns a source's values")
eq(h.get("nope"), [], "11 get() of an unknown key is empty")
eq(len(h.any_of("")), 3 + 4 + 3, "11 any_of() concatenates matching sources")
eq(list(h.failed), ["c"], "11 failed lists only sources that are not fresh")
ok(h.failed["c"], "11 a stale source carries its error")
ok("ok" in lines[0] and "3 entries" in lines[0] and "0 invalid" in lines[0]
   and lines[0].rstrip().endswith("fresh"), "11 log line for a fresh source")
ok("warn" in lines[2] and "stale (3.0d)" in lines[2], "11 log line for a stale source")
eq({o.fetched_at for o in h.outcomes.values()}, {STAMP}, "11 one `now` for the run")

# ---------------------------------------------------- parser exceptions

st = new_store()
aws = src(parser="aws_json", min_entries=1)
seed(st, aws, b'{"prefixes": [{"ip_prefix": "9.9.9.0/24"}]}', NOW - timedelta(days=1))
for bad, why in ((b'{"prefixes": [', "corrupt JSON"),
                 (b'{"prefixes": [{"region": "x"}]}', "missing key")):
    op = Opener({PRIMARY: resp(bad), MIRROR: resp(b'{"prefixes": [{"ip_prefix": "8.8.8.0/24"}]}')})
    o = fetch.acquire(aws, st, opener=op, now=NOW, sleep=noop)
    eq((o.status, o.served_by, o.values), ("fresh", "mirror-1", ["8.8.8.0/24"]),
       f"parser exception ({why}): falls to the mirror")
    ok("parse error" in o.error, f"parser exception ({why}): recorded")
o = fetch.acquire(aws, st, opener=Opener({PRIMARY: resp(b"{"), MIRROR: resp(b"[")}),
                  now=NOW, sleep=noop)
eq((o.status, o.values), ("stale", ["8.8.8.0/24"]), "parser exception everywhere: stored copy")

ris = src(parser="ris", min_entries=0, mirrors=())
o = fetch.acquire(ris, new_store(), opener=Opener({PRIMARY: resp(gzip.compress(b"x" * 500)[:-20])}),
                  now=NOW, sleep=noop)
eq(o.status, "dropped", "parser exception: a truncated .gz is rejected")

# ------------------------------------------------------------ max_age_days

op = Opener({PRIMARY: resp(GOOD, {"last-modified": "Mon, 01 Jun 2026 00:00:00 GMT"}),
             MIRROR: resp(GOOD)})
o = fetch.acquire(src(max_age_days=30), new_store(), opener=op, now=NOW, sleep=noop)
eq(o.served_by, "mirror-1", "max_age_days: an old Last-Modified is rejected")
ok("max_age_days" in o.error, "max_age_days: the rejection is recorded")

# a 304 cannot keep a feed that stopped updating alive past max_age_days
st = new_store()
old = src(max_age_days=30, max_stale_days=30, mirrors=())
seed(st, old, GOOD, NOW - timedelta(days=15),
     {"etag": '"v1"', "last-modified": "Fri, 11 Sep 2026 00:00:00 GMT"})
o = fetch.acquire(old, st, opener=Opener({PRIMARY: resp(b"", status=304)}), now=NOW,
                  sleep=noop)
eq(o.status, "stale", "max_age_days: applies to a 304 too")

# ------------------------------------------------------------- state store

st = new_store()
st.save("empty", [], {"validated_at": STAMP})
eq(st.load("empty"), ([], {"validated_at": STAMP}), "store: an empty list round-trips")
eq(st.load("absent"), None, "store: an unknown key loads as None")
st.save("x", ["b", "a"], {"validated_at": STAMP, "url_used": "u"})
raw = open(os.path.join(st.root, "x.values.gz"), "rb").read()
eq(gzip.decompress(raw), b"b\na", "store: values are newline-joined UTF-8, gzipped")
eq(sorted(os.listdir(st.root)), ["empty.json", "empty.values.gz", "x.json", "x.values.gz"],
   "store: two files per key, no temp files left behind")
# bytes 4-7 of a gzip header are its MTIME; zero keeps unchanged values
# byte-identical, so the state branch shows no diff for them
eq(raw[4:8], b"\0\0\0\0", "store: the gzip header carries no timestamp")
eq(open(os.path.join(st.root, "x.json"), encoding="utf-8").read(),
   json.dumps({"url_used": "u", "validated_at": STAMP}, indent=2, sort_keys=True) + "\n",
   "store: metadata is pretty-printed with sorted keys")
with open(os.path.join(st.root, "x.values.gz"), "wb") as fh:
    fh.write(raw[:-5])
eq(st.load("x"), None, "store: a corrupt copy loads as None")
with open(os.path.join(st.root, "empty.json"), "w", encoding="utf-8") as fh:
    fh.write("{}")
eq(st.load("empty"), None, "store: a copy with no validated_at loads as None")

# ------------------------------------------------------------- local cache

cache = tempfile.mkdtemp(dir=_TMP.name)
op = Opener({PRIMARY: resp(b"<html>"), MIRROR: resp(GOOD)})
fetch.acquire(src(), new_store(), opener=op, cache_dir=cache, now=NOW, sleep=noop)
eq(sorted(os.listdir(cache)), ["https___m_x"], "cache: only a validated body is kept")
op = Opener({PRIMARY: resp(GOOD)})
o = fetch.acquire(src(mirrors=(MIRROR,), url="https://gone/x"), new_store(), opener=op,
                  cache_dir=cache, now=NOW, sleep=noop)
eq((o.status, o.served_by, op.calls.get(MIRROR)), ("fresh", "mirror-1", None),
   "cache: a cached body skips the network")

# ------------------------------------------------------------------ report

o = fetch.acquire(src(), new_store(), opener=Opener({PRIMARY: resp(GOOD)}), now=NOW,
                  sleep=noop)
rep = o.report()
ok("values" not in rep and rep["entries"] == 3 and rep["status"] == "fresh",
   "report(): everything but the values, plus the entry count")
eq(json.loads(json.dumps(rep)), rep, "report(): JSON-serialisable")

_TMP.cleanup()
done()
