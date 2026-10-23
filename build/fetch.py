#!/usr/bin/env python3
"""Acquiring and trusting one upstream source, and harvesting them all.

For each source the primary URL is tried, then each mirror. The stored copy's
validators go with the request to the URL that served it, so an unchanged
file costs a 304. A body is believed only after it passes validation; one that
fails is treated exactly like a URL that is down. When every URL fails, the
copy in the state store stands in for up to `max_stale_days`. After that an
optional source is dropped and a required one stops the build.

Standard library only.
"""

from __future__ import annotations

import gzip
import hashlib
import http.client
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.request
import zlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import NamedTuple

import sources

USER_AGENT = "IR-Geo-DB/1.0 (+https://github.com/Arman2122/IR-Geo-DB)"
TIMEOUT = 120
ATTEMPTS = 4
# the shrink check needs a stored copy at least this big to mean anything
SHRINK_MIN_STORED = 100
SERVED = ("fresh", "not-modified")


class Response(NamedTuple):
    status: int
    headers: dict[str, str]   # keys lower-cased
    body: bytes


class FetchError(Exception):
    """A URL that could not be read: an HTTP status, or 0 for the network."""

    def __init__(self, status: int, msg: str):
        super().__init__(f"HTTP {status} {msg}" if status else msg)
        self.status = status


class SourceUnavailable(Exception):
    """A required source with no usable copy, fresh or stored."""


class _Rejected(Exception):
    """A body that arrived but cannot be trusted."""


# ------------------------------------------------------------------ HTTP


def _decode(body: bytes, headers: dict[str, str]) -> bytes:
    if headers.get("content-encoding", "").lower() == "gzip":
        return gzip.decompress(body)
    return body


def http_get(url: str, headers: dict[str, str], timeout: int = TIMEOUT) -> Response:
    """One GET. A 304 is a Response; every other failure is a FetchError."""
    req = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept-Encoding": "gzip, identity", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            return Response(resp.status, hdrs, _decode(resp.read(), hdrs))
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            hdrs = {k.lower(): v for k, v in (exc.headers or {}).items()}
            return Response(304, hdrs, b"")
        raise FetchError(exc.code, str(exc.reason)) from exc
    # a gzip stream cut short raises EOFError or zlib.error, not OSError
    except (urllib.error.URLError, http.client.HTTPException, OSError,
            EOFError, zlib.error) as exc:
        raise FetchError(0, str(exc) or type(exc).__name__) from exc


def _get(url: str, headers: dict[str, str], opener, sleep) -> Response:
    """Retry network errors and 5xx; any other status goes to the next URL."""
    for attempt in range(ATTEMPTS):
        try:
            return opener(url, headers)
        except FetchError as exc:
            if 0 < exc.status < 500 or attempt == ATTEMPTS - 1:
                raise
            sleep(2 ** attempt * 2)
    raise AssertionError("unreachable")


# ------------------------------------------------------------ validation


def _check_age(src, last_modified: str, now: datetime) -> None:
    if src.max_age_days is None or not last_modified:
        return
    try:
        when = parsedate_to_datetime(last_modified)
    except (TypeError, ValueError):
        return
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    age = (now - when).total_seconds() / 86400
    if age > src.max_age_days:
        raise _Rejected(f"Last-Modified {age:.1f} days ago, "
                        f"over max_age_days {src.max_age_days}")


def _validate(src, parser, body: bytes, headers: dict[str, str],
              stored: list[str] | None, now: datetime) -> sources.Parsed:
    head = body[:512].lower()
    if b"<!doctype html" in head or b"<html" in head:
        raise _Rejected("HTML page")
    if len(body) < src.min_bytes:
        raise _Rejected(f"{len(body)} bytes, under min_bytes {src.min_bytes}")
    try:
        parsed = parser(body)
    except Exception as exc:                            # noqa: BLE001
        # a truncated .gz, corrupt JSON or a missing key: a bad body
        raise _Rejected(f"parse error: {type(exc).__name__}: {exc}") from exc
    n = len(parsed.values)
    if n < src.min_entries:
        raise _Rejected(f"{n} entries, under min_entries {src.min_entries}")
    if (stored is not None and len(stored) >= SHRINK_MIN_STORED
            and n < (1 - src.max_shrink) * len(stored)):
        raise _Rejected(f"shrank from {len(stored)} to {n} entries, "
                        f"over max_shrink {src.max_shrink}")
    _check_age(src, headers.get("last-modified", ""), now)
    return parsed


# ----------------------------------------------------------- state store


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_iso(text: str) -> datetime:
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _write_atomic(path: str, data: bytes) -> None:
    # a unique temp name, so two writers can never interleave in one file
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", suffix=".tmp")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


class StateStore:
    """The last validated copy of each source: `<key>.values.gz` (one value
    per line) and `<key>.json` (where it came from and when)."""

    def __init__(self, root: str):
        self.root = root

    def _path(self, key: str, suffix: str) -> str:
        return os.path.join(self.root, key + suffix)

    def load(self, key: str) -> tuple[list[str], dict] | None:
        """The stored copy, or None if there is none or it is unreadable."""
        try:
            with open(self._path(key, ".json"), encoding="utf-8") as fh:
                meta = json.load(fh)
            with open(self._path(key, ".values.gz"), "rb") as fh:
                text = gzip.decompress(fh.read()).decode("utf-8")
            _parse_iso(meta["validated_at"])
        except (OSError, ValueError, KeyError, TypeError, AttributeError,
                EOFError, zlib.error):
            return None
        return (text.split("\n") if text else []), meta

    def save(self, key: str, values: list[str], meta: dict) -> None:
        os.makedirs(self.root, exist_ok=True)
        # mtime=0: unchanged values give unchanged bytes, so no state-branch diff
        _write_atomic(self._path(key, ".values.gz"),
                      gzip.compress("\n".join(values).encode("utf-8"), mtime=0))
        _write_atomic(self._path(key, ".json"),
                      (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode("utf-8"))


# ----------------------------------------------------------- acquisition


@dataclass
class Outcome:
    key: str
    status: str               # fresh | not-modified | stale | dropped
    served_by: str = ""       # primary | mirror-N | state; "" when dropped
    url_used: str = ""
    values: list[str] = field(default_factory=list)
    invalid: int = 0
    fetched_at: str = ""      # when this run tried the source
    validated_at: str = ""    # when the values served were last validated
    last_modified: str = ""
    etag: str = ""
    bytes: int = 0            # size of the raw body the values came from
    sha256: str = ""          # of that raw body
    stale_days: float = 0.0
    error: str = ""           # every URL that failed and why

    def report(self) -> dict:
        out = {f.name: getattr(self, f.name) for f in fields(self)
               if f.name != "values"}
        out["entries"] = len(self.values)
        return out


def _from_meta(key: str, status: str, served_by: str, values: list[str],
               meta: dict, fetched_at: str, **extra) -> Outcome:
    return Outcome(key=key, status=status, served_by=served_by,
                   url_used=meta.get("url_used", ""), values=values,
                   invalid=meta.get("invalid", 0), fetched_at=fetched_at,
                   validated_at=meta.get("validated_at", ""),
                   last_modified=meta.get("last_modified", ""),
                   etag=meta.get("etag", ""), bytes=meta.get("bytes", 0),
                   sha256=meta.get("sha256", ""), **extra)


def _validators(meta: dict, url: str) -> dict[str, str]:
    # an ETag or a date belongs to the server that issued it
    if meta.get("url_used") != url:
        return {}
    out = {}
    if meta.get("etag"):
        out["If-None-Match"] = meta["etag"]
    if meta.get("last_modified"):
        out["If-Modified-Since"] = meta["last_modified"]
    return out


def _cache_path(cache_dir: str, url: str) -> str:
    return os.path.join(cache_dir, re.sub(r"[^A-Za-z0-9._-]", "_", url)[-150:])


def acquire(src, store: StateStore, *, opener=http_get, cache_dir: str | None = None,
            now: datetime | None = None, sleep=time.sleep) -> Outcome:
    """Fetch, validate and store one source, falling back to the stored copy.

    Never raises for a source that cannot be had: it comes back `dropped`,
    and harvest() decides whether that stops the build. `cache_dir` is for
    local iteration only: a cached body skips the network.
    """
    now = now or datetime.now(timezone.utc)
    stamp = _iso(now)
    parser = sources.PARSERS[src.parser]
    stored = store.load(src.key)
    old_values, meta = stored if stored else (None, {})
    age = (max(0.0, (now - _parse_iso(meta["validated_at"])).total_seconds() / 86400)
           if stored else 0.0)
    usable = stored is not None and age <= src.max_stale_days
    # a copy too old to stand in must not veto a new body either, or one
    # real shrink would drop the source on every run from then on
    baseline = old_values if usable else None
    errors = []

    for i, url in enumerate((src.url, *src.mirrors)):
        served_by = f"mirror-{i}" if i else "primary"
        cache = _cache_path(cache_dir, url) if cache_dir else None
        cached = bool(cache) and os.path.isfile(cache) and os.path.getsize(cache) > 0
        # with a cache, ask for a full body so there is something to cache
        validators = {} if cache else _validators(meta, url)
        try:
            if cached:
                with open(cache, "rb") as fh:
                    resp = Response(200, {}, fh.read())
            else:
                resp = _get(url, validators, opener, sleep)
            if resp.status == 304:
                if not validators:
                    raise _Rejected("304 to an unconditional request")
                last_modified = (resp.headers.get("last-modified")
                                 or meta.get("last_modified", ""))
                _check_age(src, last_modified, now)
            else:
                parsed = _validate(src, parser, resp.body, resp.headers,
                                   baseline, now)
        except (FetchError, _Rejected) as exc:
            errors.append(f"{served_by}: {exc}")
            continue

        if resp.status == 304:
            meta = {**meta, "validated_at": stamp, "last_modified": last_modified,
                    "etag": resp.headers.get("etag") or meta.get("etag", "")}
            store.save(src.key, old_values, meta)
            return _from_meta(src.key, "not-modified", served_by, old_values,
                              meta, stamp, error="; ".join(errors))

        meta = {"url_used": url, "validated_at": stamp,
                "etag": resp.headers.get("etag", ""),
                "last_modified": resp.headers.get("last-modified", ""),
                "sha256": hashlib.sha256(resp.body).hexdigest(),
                "bytes": len(resp.body), "entries": len(parsed.values),
                "invalid": parsed.invalid}
        store.save(src.key, parsed.values, meta)
        if cache and not cached:
            os.makedirs(cache_dir, exist_ok=True)
            _write_atomic(cache, resp.body)
        return _from_meta(src.key, "fresh", served_by, parsed.values, meta,
                          stamp, error="; ".join(errors))

    error = "; ".join(errors)
    if stored is None:
        return Outcome(key=src.key, status="dropped", fetched_at=stamp,
                       error=f"{error}; nothing stored")
    if usable:
        return _from_meta(src.key, "stale", "state", old_values, meta, stamp,
                          stale_days=round(age, 1), error=error)
    return Outcome(key=src.key, status="dropped", fetched_at=stamp,
                   stale_days=round(age, 1),
                   error=f"{error}; stored copy is {age:.1f} days old, "
                         f"over max_stale_days {src.max_stale_days}")


# --------------------------------------------------------------- harvest


@dataclass
class Harvest:
    values: dict[str, list[str]] = field(default_factory=dict)
    outcomes: dict[str, Outcome] = field(default_factory=dict)

    def get(self, key: str) -> list[str]:
        return self.values.get(key, [])

    def any_of(self, prefix: str) -> list[str]:
        out = []
        for key, vals in self.values.items():
            if key.startswith(prefix):
                out.extend(vals)
        return out

    @property
    def failed(self) -> dict[str, str]:
        """Every source not served fresh or not-modified, with its error."""
        return {k: o.error for k, o in self.outcomes.items()
                if o.status not in SERVED}


def _log_line(src, out: Outcome) -> str:
    if out.status in SERVED:
        level = "ok   "
    elif src.optional or out.status == "stale":
        level = "warn "
    else:
        level = "ERROR"
    detail = out.status
    if out.status == "stale":
        detail += f" ({out.stale_days:.1f}d)"
    if out.served_by.startswith("mirror"):
        detail += f" ({out.served_by})"
    if out.error:
        detail += f": {out.error}"
    return (f"  {level} {src.key:<22} {len(out.values):>7} entries  "
            f"{out.invalid} invalid  ({out.bytes / 1024:.0f} KiB)  {detail}")


def harvest(srcs, store: StateStore, *, cache_dir: str | None = None, log=print,
            workers: int = 8, opener=http_get, now: datetime | None = None,
            sleep=time.sleep) -> Harvest:
    """Acquire every source in parallel; log and collect in registry order.

    Raises SourceUnavailable, after logging every source, if a required
    source has no usable copy.
    """
    srcs = list(srcs)
    now = now or datetime.now(timezone.utc)

    def one(src) -> Outcome:
        try:
            return acquire(src, store, opener=opener, cache_dir=cache_dir,
                           now=now, sleep=sleep)
        except Exception as exc:                        # noqa: BLE001
            # a bug in one source must not cost every other source's log line
            return Outcome(key=src.key, status="dropped", fetched_at=_iso(now),
                           error=f"{type(exc).__name__}: {exc}")

    with ThreadPoolExecutor(max_workers=workers) as pool:
        outcomes = list(pool.map(one, srcs))

    result, missing = Harvest(), []
    for src, out in zip(srcs, outcomes):
        result.outcomes[src.key] = out
        if out.status != "dropped":
            result.values[src.key] = out.values
        log(_log_line(src, out))
        if out.status == "dropped" and not src.optional:
            missing.append(f"{src.key} ({out.error})")
    if missing:
        raise SourceUnavailable("required source unavailable: " + "; ".join(missing))
    return result
