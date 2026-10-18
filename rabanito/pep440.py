"""Bounded PEP 440 version ordering, not pip specifiers or package resolution.

Own staged parser from the PyPA version specification. No external code, cache,
I/O or dependency. Local build ordering does not establish patch applicability.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


MAX_VERSION_CHARS = 200
_PUBLIC = re.compile(r"v?(?:([0-9]+)!)?([0-9]+(?:\.[0-9]+)*)(.*)", re.ASCII)
_PRE = re.compile(r"[._-]?(alpha|beta|preview|pre|rc|a|b|c)[._-]?([0-9]+)?", re.ASCII)
_POST = re.compile(r"(?:-([0-9]+)|[._-]?(post|rev|r)[._-]?([0-9]+)?)", re.ASCII)
_DEV = re.compile(r"[._-]?dev[._-]?([0-9]+)?", re.ASCII)
_LOCAL = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", re.ASCII)
_PRE_NAMES = {"alpha": "a", "a": "a", "beta": "b", "b": "b", "c": "rc", "rc": "rc", "pre": "rc", "preview": "rc"}


@dataclass(frozen=True)
class Version:
    normalized: str
    key: tuple
    has_local: bool
    numeric_final: bool


def parse_version(value: object) -> Version | None:
    """Return a normalized, totally ordered key or None, with no input echoed.

    The 200-character raw-input budget also bounds all integer conversions and
    segment counts. ASCII outer whitespace is normalized; internal whitespace,
    non-ASCII, specifiers, URLs and arbitrary legacy versions are not versions.
    """
    if not isinstance(value, str) or not value or len(value) > MAX_VERSION_CHARS or not value.isascii():
        return None
    text = value.strip(" \t\n\r\f\v").lower()
    public, separator, local = text.partition("+")
    if separator and not _LOCAL.fullmatch(local):
        return None
    match = _PUBLIC.fullmatch(public)
    if not match:
        return None
    epoch = int(match[1] or "0")
    release = tuple(int(n) for n in match[2].split("."))
    suffix = match[3]
    pre, post, dev = None, None, None
    part = _PRE.match(suffix)
    if part:
        pre = (_PRE_NAMES[part[1]], int(part[2] or "0")); suffix = suffix[part.end():]
    part = _POST.match(suffix)
    if part:
        post = int(part[1] or part[3] or "0"); suffix = suffix[part.end():]
    part = _DEV.match(suffix)
    if part:
        dev = int(part[1] or "0"); suffix = suffix[part.end():]
    if suffix:
        return None
    # Removing trailing zero release segments is equivalent to right padding
    # for comparisons, without a fixed maximum number of release components.
    trimmed = list(release)
    while len(trimmed) > 1 and trimmed[-1] == 0:
        trimmed.pop()
    pre_key = (({"a": 0, "b": 1, "rc": 2}[pre[0]], pre[1]) if pre else
               (-1, 0) if dev is not None and post is None else (3, 0))
    local_parts = re.split(r"[._-]", local) if separator else []
    local_key = tuple((1, int(p)) if p.isdecimal() else (0, p) for p in local_parts)
    key = (epoch, tuple(trimmed), pre_key, -1 if post is None else post,
           (1, 0) if dev is None else (0, dev), local_key)
    normalized = (str(epoch) + "!" if epoch else "") + ".".join(map(str, release))
    if pre: normalized += pre[0] + str(pre[1])
    if post is not None: normalized += ".post" + str(post)
    if dev is not None: normalized += ".dev" + str(dev)
    if separator: normalized += "+" + ".".join(str(int(p)) if p.isdecimal() else p for p in local_parts)
    if len(normalized) > MAX_VERSION_CHARS:
        return None
    return Version(normalized, key, bool(separator), epoch == 0 and pre is None and post is None and dev is None and not separator)


def public_version_key(value: object) -> tuple | None:
    """OSV automatic assessment remains conservative for downstream builds."""
    parsed = parse_version(value)
    return parsed.key if parsed is not None and not parsed.has_local else None
