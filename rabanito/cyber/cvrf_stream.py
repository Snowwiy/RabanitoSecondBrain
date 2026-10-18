"""Strict, bounded CVRF JSON decoding without retaining the vulnerability array.

Transport and publication are separate. Callbacks can observe provisional items;
callers must not publish them until the entire envelope has validated.
"""
from __future__ import annotations

import codecs
import json
import math
import time

from .model import InvalidFeed


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidFeed("duplicate_cvrf_json_key")
        result[key] = value
    return result


def _finite(value):
    result = float(value)
    if not math.isfinite(result):
        raise InvalidFeed("nonfinite_cvrf_json")
    return result


class _Reader:
    def __init__(self, stream, maximum, seconds, monotonic):
        self.stream, self.maximum, self.seconds, self.monotonic = stream, maximum, seconds, monotonic
        self.started, self.bytes_read, self.buffer, self.eof = monotonic(), 0, "", False
        self.utf8 = codecs.getincrementaldecoder("utf-8-sig")("strict")
        self.decoder = json.JSONDecoder(object_pairs_hook=_unique, parse_float=_finite,
            parse_constant=lambda _: (_ for _ in ()).throw(InvalidFeed("nonfinite_cvrf_json")))

    def more(self):
        if self.monotonic() - self.started > self.seconds:
            raise InvalidFeed("cvrf_read_deadline")
        if self.eof:
            return False
        # HTTPResponse.read(n) can internally wait for n bytes over many socket
        # reads. read1 performs one buffered read, allowing deadline checks
        # between incoming fragments even when a provider trickles its body.
        read = getattr(self.stream, "read1", self.stream.read)
        raw = read(min(65536, self.maximum - self.bytes_read + 1))
        if not isinstance(raw, bytes):
            raise InvalidFeed("cvrf_binary_stream_required")
        self.bytes_read += len(raw)
        if self.bytes_read > self.maximum:
            raise InvalidFeed("cvrf_document_byte_limit")
        try:
            self.buffer += self.utf8.decode(raw, final=not raw)
        except UnicodeError:
            raise InvalidFeed("invalid_cvrf_utf8") from None
        if not raw:
            self.eof = True
        return bool(raw)

    def space(self):
        while True:
            # JSON whitespace only; str.isspace() accepts non-JSON characters.
            self.buffer = self.buffer.lstrip(" \t\r\n")
            if self.buffer or self.eof:
                return
            self.more()

    def token(self, expected):
        self.space()
        if not self.buffer.startswith(expected):
            raise InvalidFeed("invalid_cvrf_json_structure")
        self.buffer = self.buffer[len(expected):]

    def value(self, maximum, *, key=False):
        self.space()
        while True:
            try:
                value, end = self.decoder.raw_decode(self.buffer)
            except (json.JSONDecodeError, RecursionError, ValueError) as exc:
                if isinstance(exc, InvalidFeed):
                    raise
                if isinstance(exc, RecursionError):
                    raise InvalidFeed("cvrf_json_depth_limit") from None
                if len(self.buffer.encode("utf-8")) > maximum:
                    raise InvalidFeed("cvrf_value_byte_limit") from None
                if not self.more():
                    raise InvalidFeed("incomplete_or_invalid_cvrf_json") from None
                continue
            if len(self.buffer[:end].encode("utf-8")) > maximum:
                raise InvalidFeed("cvrf_value_byte_limit")
            # A number split between chunks is not complete at buffer end.
            # Look ahead before accepting any value, including true/null.
            if end == len(self.buffer) and not self.eof:
                self.more()
                continue
            separators = " \t\r\n:" if key else " \t\r\n,]}"
            if end < len(self.buffer) and self.buffer[end] not in separators:
                # raw_decode accepts the integer prefix of an incomplete 1e-5.
                if (not key and self.buffer[:1] in "-0123456789" and not self.eof
                        and not any(char in self.buffer for char in " \t\r\n,]}")):
                    if len(self.buffer.encode("utf-8")) > maximum:
                        raise InvalidFeed("cvrf_value_byte_limit")
                    self.more()
                    continue
                raise InvalidFeed("invalid_cvrf_value_separator")
            self.buffer = self.buffer[end:]
            return value


def read_cvrf(stream, on_vulnerability, *, max_bytes=64 * 1024 * 1024, max_records=5000,
              max_record_bytes=2 * 1024 * 1024, max_header_bytes=8 * 1024 * 1024,
              max_seconds=120, monotonic=time.monotonic) -> dict:
    """Decode an entire CVRF envelope; no network, files, writes or execution.

    Memory retains headers plus one raw item, not all raw vulnerability items.
    Byte limits are not a hard Python-object RAM cap. Deadline is cooperative.
    """
    for value, ceiling in ((max_bytes, 64 * 1024 * 1024), (max_records, 10000),
                            (max_record_bytes, 4 * 1024 * 1024), (max_header_bytes, 16 * 1024 * 1024),
                            (max_seconds, 120)):
        if type(value) is not int or not 1 <= value <= ceiling:
            raise ValueError("invalid_cvrf_stream_budget")
    if not callable(on_vulnerability):
        raise ValueError("cvrf_callback_required")
    reader = _Reader(stream, max_bytes, max_seconds, monotonic)
    headers, seen, count, header_bytes = {}, set(), 0, 0
    reader.token("{")
    first = True
    while True:
        reader.space()
        if reader.buffer.startswith("}"):
            reader.token("}")
            break
        if not first:
            reader.token(",")
        first = False
        key = reader.value(512, key=True)
        if not isinstance(key, str) or len(key) > 100 or key in seen or len(seen) >= 32:
            raise InvalidFeed("invalid_or_duplicate_cvrf_field")
        seen.add(key)
        reader.token(":")
        if key == "Vulnerability":
            reader.token("[")
            first_item = True
            while True:
                reader.space()
                if reader.buffer.startswith("]"):
                    reader.token("]")
                    break
                if not first_item:
                    reader.token(",")
                first_item = False
                item = reader.value(max_record_bytes)
                if not isinstance(item, dict):
                    raise InvalidFeed("invalid_cvrf_vulnerability")
                count += 1
                if count > max_records:
                    raise InvalidFeed("cvrf_record_count_limit")
                on_vulnerability(item)
        else:
            value = reader.value(max_header_bytes)
            header_bytes += len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
            if header_bytes > max_header_bytes:
                raise InvalidFeed("cvrf_header_byte_limit")
            headers[key] = value
    reader.space()
    if reader.buffer or not reader.eof:
        raise InvalidFeed("trailing_cvrf_json")
    if not {"DocumentTracking", "ProductTree", "Vulnerability"} <= seen:
        raise InvalidFeed("missing_cvrf_fields")
    if not isinstance(headers["DocumentTracking"], dict) or not isinstance(headers["ProductTree"], dict):
        raise InvalidFeed("invalid_cvrf_headers")
    return {"headers": headers, "vulnerability_count": count, "bytes_read": reader.bytes_read}
