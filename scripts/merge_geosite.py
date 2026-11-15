#!/usr/bin/env python3
"""Merge Anti-AD domains into a V2Fly GeoSiteList protobuf without dropping upstream data."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import re
import sys
from pathlib import Path

TARGET_CODE = "CATEGORY-ADS-EXTENDED"
MIN_ANTIDAD_DOMAINS = 10_000


def read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while pos < len(buf) and shift < 70:
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7
    raise ValueError("invalid/truncated protobuf varint")


def put_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative varint")
    out = bytearray()
    while value > 0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def fields(buf: bytes):
    pos = 0
    while pos < len(buf):
        start = pos
        tag, pos = read_varint(buf, pos)
        number, wire = tag >> 3, tag & 7
        if number == 0:
            raise ValueError("protobuf field number 0")
        if wire == 0:
            _, pos = read_varint(buf, pos)
        elif wire == 1:
            pos += 8
        elif wire == 2:
            size, pos = read_varint(buf, pos)
            pos += size
        elif wire == 5:
            pos += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        if pos > len(buf):
            raise ValueError("truncated protobuf field")
        yield number, wire, buf[start:pos], buf[start:pos]  # raw field retained byte-for-byte


def length_delimited(raw: bytes) -> bytes:
    _, pos = read_varint(raw, 0)
    size, pos = read_varint(raw, pos)
    value = raw[pos:pos + size]
    if len(value) != size:
        raise ValueError("truncated length-delimited field")
    return value


def encode_bytes_field(number: int, value: bytes) -> bytes:
    return put_varint((number << 3) | 2) + put_varint(len(value)) + value


def get_geosite_code(message: bytes) -> str:
    found = []
    for number, wire, raw, _ in fields(message):
        if number == 1 and wire == 2:
            found.append(length_delimited(raw).decode("utf-8"))
    if len(found) != 1:
        raise ValueError(f"GeoSite entry must have exactly one code field; got {len(found)}")
    return found[0]


def get_domain_key(message: bytes):
    dtype = None
    value = None
    for number, wire, raw, _ in fields(message):
        if number == 1 and wire == 0:
            _, p = read_varint(raw, 0)
            dtype, _ = read_varint(raw, p)
        elif number == 2 and wire == 2:
            value = length_delimited(raw).decode("utf-8").lower()
    if dtype is None or value is None:
        raise ValueError("malformed Domain protobuf entry")
    return dtype, value


def parse_geosite_list(data: bytes):
    entries = []
    other_fields = []
    for number, wire, raw, _ in fields(data):
        if number == 1 and wire == 2:
            entries.append(length_delimited(raw))
        else:
            other_fields.append(raw)
    if not entries:
        raise ValueError("input is not a non-empty GeoSiteList")
    return entries, other_fields


def parse_domain_list(path: Path) -> list[str]:
    result = set()
    for raw_line in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "!", ";")):
            continue
        # Accept common hosts-file and adblock list prefixes as well as plain domains.
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        candidate = parts[-1] if len(parts) > 1 and parts[0] in ("0.0.0.0", "127.0.0.1", "::", "::1") else parts[0]
        candidate = candidate.strip().lower().rstrip(".")
        if candidate.startswith("||"):
            candidate = candidate[2:]
        candidate = candidate.rstrip("^|/")
        if candidate.startswith("*."):
            candidate = candidate[2:]
        if candidate.startswith("."):
            candidate = candidate[1:]
        if not candidate or "/" in candidate or ":" in candidate or "*" in candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
            continue
        except ValueError:
            pass
        try:
            ascii_domain = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if len(ascii_domain) > 253:
            continue
        labels = ascii_domain.split(".")
        if len(labels) < 2 or any(
            not label or len(label) > 63 or
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
            for label in labels
        ):
            continue
        result.add(ascii_domain)
    domains = sorted(result)
    if len(domains) < MIN_ANTIDAD_DOMAINS:
        raise ValueError(
            f"only {len(domains)} valid domains parsed; refusing to publish "
            f"(minimum safety threshold: {MIN_ANTIDAD_DOMAINS})"
        )
    return domains


def encode_root_domain(domain: str) -> bytes:
    # v2fly.com/core/app/router/routercommon/common.proto:
    # Domain.type = 2 (RootDomain), Domain.value = domain.
    return put_varint(1 << 3) + put_varint(2) + encode_bytes_field(2, domain.encode("ascii"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--geosite", required=True, type=Path)
    parser.add_argument("--domains", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    upstream = args.geosite.read_bytes()
    entries, other_fields = parse_geosite_list(upstream)
    by_code = {}
    for entry in entries:
        code = get_geosite_code(entry)
        if code in by_code:
            raise ValueError(f"upstream contains duplicate GeoSite code: {code}")
        by_code[code] = entry

    anti_domains = parse_domain_list(args.domains)
    existing = by_code.get(TARGET_CODE)
    retained = []
    seen = set()
    if existing is not None:
        for number, wire, raw, _ in fields(existing):
            if number == 2 and wire == 2:
                domain_msg = length_delimited(raw)
                key = get_domain_key(domain_msg)
                if key not in seen:
                    seen.add(key)
                    retained.append(domain_msg)

    added = 0
    for domain in anti_domains:
        key = (2, domain)
        if key not in seen:
            seen.add(key)
            retained.append(encode_root_domain(domain))
            added += 1

    # Keep the existing category's other protobuf fields, if any, and append
    # the de-duplicated domain records. Otherwise create a new GeoSite entry.
    if existing is not None:
        merged_entry = b"".join(
            raw for number, wire, raw, _ in fields(existing)
            if not (number == 2 and wire == 2)
        ) + b"".join(encode_bytes_field(2, item) for item in retained)
        entries = [merged_entry if get_geosite_code(e) == TARGET_CODE else e for e in entries]
    else:
        merged_entry = encode_bytes_field(1, TARGET_CODE.encode("ascii")) + b"".join(
            encode_bytes_field(2, item) for item in retained
        )
        entries.append(merged_entry)

    output = b"".join(encode_bytes_field(1, item) for item in entries) + b"".join(other_fields)
    # Round-trip structural checks and ensure every upstream category remains present.
    check_entries, _ = parse_geosite_list(output)
    check_codes = [get_geosite_code(item) for item in check_entries]
    if len(check_codes) != len(set(check_codes)):
        raise ValueError("duplicate category codes after merge")
    if set(by_code) - set(check_codes):
        raise ValueError("one or more upstream categories were lost")
    if TARGET_CODE not in check_codes:
        raise ValueError("extended ad category missing after merge")

    final_entry = next(item for item in check_entries if get_geosite_code(item) == TARGET_CODE)
    final_count = sum(1 for n, w, r, _ in fields(final_entry) if n == 2 and w == 2)
    if final_count != len(seen):
        raise ValueError(f"domain count mismatch: expected {len(seen)}, got {final_count}")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    print(f"Upstream categories: {len(by_code)}")
    print(f"Anti-AD unique valid domains: {len(anti_domains)}")
    print(f"New domains added: {added}")
    print(f"{TARGET_CODE} total domains: {final_count}")
    print(f"Output bytes: {len(output)}")
    print(f"SHA256: {hashlib.sha256(output).hexdigest()}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
