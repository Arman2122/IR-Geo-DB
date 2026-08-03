#!/usr/bin/env python3
"""
geodat.py — read and write V2Ray/Xray ``geoip.dat`` and ``geosite.dat``.

Both files are bare protobuf: no length prefix, no compression, no framing.
The schema lives in v2fly/v2ray-core ``app/router/routercommon/common.proto``
and Xray-core mirrors it byte for byte:

    message CIDR      { bytes ip = 1; uint32 prefix = 2; }
    message GeoIP     { string country_code = 1; repeated CIDR cidr = 2;
                        bool inverse_match = 3; bytes resource_hash = 4;
                        string code = 5; }
    message GeoIPList { repeated GeoIP entry = 1; }

    message Domain      { Type type = 1; string value = 2;
                          repeated Attribute attribute = 3; }
                        // Type: Plain=0 Regex=1 RootDomain=2 Full=3
    message GeoSite     { string country_code = 1; repeated Domain domain = 2;
                          bytes resource_hash = 3; string code = 4; }
    message GeoSiteList { repeated GeoSite entry = 1; }

Category codes are written upper-cased. That is what
v2fly/domain-list-community and Loyalsoldier/geoip emit, and what the
``geosite:ir`` / ``geoip:ir`` lookups in both cores compare against.

Fields holding a proto3 default (``prefix = 0``, ``type = Plain``) are omitted
rather than written as an explicit zero, so output is byte-identical to what
the Go generators produce for the same input.

No third-party dependencies — the slice of the wire format needed here is
small enough to hand-roll, and vendoring `protobuf` for four messages is not
worth the build-time cost.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable, Iterator, NamedTuple

# Domain.Type
PLAIN = 0       # substring / keyword match
REGEX = 1       # regular expression
ROOT_DOMAIN = 2  # the domain itself and every subdomain
FULL = 3        # exact match, subdomains excluded

TYPE_NAMES = {PLAIN: "keyword", REGEX: "regexp", ROOT_DOMAIN: "domain", FULL: "full"}


# --------------------------------------------------------------- wire format


def _varint(value: int) -> bytes:
    if value < 0:
        raise ValueError(f"negative varint: {value}")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _tag(field: int, wire: int) -> bytes:
    return _varint((field << 3) | wire)


def _len_field(field: int, payload: bytes) -> bytes:
    """A length-delimited field: string, bytes, or an embedded message."""
    return _tag(field, 2) + _varint(len(payload)) + payload


def _varint_field(field: int, value: int) -> bytes:
    return _tag(field, 0) + _varint(value)


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _iter_fields(buf: bytes) -> Iterator[tuple[int, int, bytes | int]]:
    """Yield ``(field_number, wire_type, value)`` for one message body."""
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field, wire = key >> 3, key & 0x07
        if wire == 0:
            value, pos = _read_varint(buf, pos)
            yield field, wire, value
        elif wire == 2:
            length, pos = _read_varint(buf, pos)
            yield field, wire, buf[pos:pos + length]
            pos += length
        elif wire == 5:
            yield field, wire, buf[pos:pos + 4]
            pos += 4
        elif wire == 1:
            yield field, wire, buf[pos:pos + 8]
            pos += 8
        else:
            raise ValueError(f"unsupported wire type {wire}")


# ------------------------------------------------------------------- geoip


def encode_geoip(categories: dict[str, Iterable]) -> bytes:
    """Build a ``geoip.dat`` body.

    ``categories`` maps a code to an iterable of ``ip_network`` objects (or
    anything ``ipaddress.ip_network`` accepts).
    """
    out = bytearray()
    for code, networks in categories.items():
        entry = bytearray()
        entry += _len_field(1, code.upper().encode())
        for net in networks:
            if isinstance(net, str):
                net = ipaddress.ip_network(net, strict=False)
            cidr = _len_field(1, net.network_address.packed)
            if net.prefixlen:                      # proto3 omits a zero
                cidr += _varint_field(2, net.prefixlen)
            entry += _len_field(2, cidr)
        out += _len_field(1, bytes(entry))
    return bytes(out)


class GeoIPCategory(NamedTuple):
    code: str
    networks: list


def decode_geoip(blob: bytes) -> list[GeoIPCategory]:
    """Parse a ``geoip.dat`` body. Used by the self-test and by `verify`."""
    result = []
    for field, _wire, value in _iter_fields(blob):
        if field != 1 or not isinstance(value, bytes):
            continue
        code, networks = "", []
        for sub, _w, sval in _iter_fields(value):
            if sub == 1 and isinstance(sval, bytes):
                code = sval.decode()
            elif sub == 2 and isinstance(sval, bytes):
                raw, prefix = b"", 0
                for c, _cw, cval in _iter_fields(sval):
                    if c == 1 and isinstance(cval, bytes):
                        raw = cval
                    elif c == 2 and isinstance(cval, int):
                        prefix = cval
                addr = ipaddress.ip_address(raw)
                networks.append(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
        result.append(GeoIPCategory(code, networks))
    return result


# ------------------------------------------------------------------ geosite


def encode_geosite(categories: dict[str, Iterable[tuple[int, str]]]) -> bytes:
    """Build a ``geosite.dat`` body.

    ``categories`` maps a code to an iterable of ``(type, value)`` pairs where
    type is one of PLAIN / REGEX / ROOT_DOMAIN / FULL.
    """
    out = bytearray()
    for code, domains in categories.items():
        entry = bytearray()
        entry += _len_field(1, code.upper().encode())
        for dtype, value in domains:
            dom = bytearray()
            if dtype:                              # proto3 omits Plain (= 0)
                dom += _varint_field(1, dtype)
            dom += _len_field(2, value.encode())
            entry += _len_field(2, bytes(dom))
        out += _len_field(1, bytes(entry))
    return bytes(out)


class GeoSiteCategory(NamedTuple):
    code: str
    domains: list[tuple[int, str]]


def decode_geosite(blob: bytes) -> list[GeoSiteCategory]:
    result = []
    for field, _wire, value in _iter_fields(blob):
        if field != 1 or not isinstance(value, bytes):
            continue
        code, domains = "", []
        for sub, _w, sval in _iter_fields(value):
            if sub == 1 and isinstance(sval, bytes):
                code = sval.decode()
            elif sub == 2 and isinstance(sval, bytes):
                dtype, dvalue = PLAIN, ""
                for d, _dw, dval in _iter_fields(sval):
                    if d == 1 and isinstance(dval, int):
                        dtype = dval
                    elif d == 2 and isinstance(dval, bytes):
                        dvalue = dval.decode(errors="replace")
                domains.append((dtype, dvalue))
        result.append(GeoSiteCategory(code, domains))
    return result


# --------------------------------------------------------------- self-test


def _self_test() -> None:
    """Round-trip both formats. Run with ``python3 build/geodat.py``."""
    ips = {
        "ir": [ipaddress.ip_network("2.144.0.0/14"),
               ipaddress.ip_network("2001:790::/32")],
        "private": [ipaddress.ip_network("10.0.0.0/8")],
    }
    back = {c.code: c.networks for c in decode_geoip(encode_geoip(ips))}
    assert list(back) == ["IR", "PRIVATE"], back
    assert back["IR"] == ips["ir"], back["IR"]
    assert back["PRIVATE"] == ips["private"]

    sites = {
        "ir": [(ROOT_DOMAIN, "ir"), (FULL, "digikala.com"),
               (PLAIN, "irancell"), (REGEX, r".*\.ir$")],
    }
    back2 = {c.code: c.domains for c in decode_geosite(encode_geosite(sites))}
    assert back2["IR"] == sites["ir"], back2["IR"]

    # a /0 and a Plain type both encode to proto3 defaults; make sure the
    # omitted-field path still decodes back to the same value
    edge = decode_geoip(encode_geoip({"x": [ipaddress.ip_network("0.0.0.0/0")]}))
    assert str(edge[0].networks[0]) == "0.0.0.0/0", edge

    print("geodat self-test OK")


if __name__ == "__main__":
    _self_test()
