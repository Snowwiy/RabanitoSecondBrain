"""Common bounded TOML loading for offline inventory readers, never a resolver."""
from __future__ import annotations

import hashlib
import json
import math
import re
import tomllib


TOKEN = re.compile(r"(?:gh[pousr]_|github_pat_|sk-(?:proj-|ant-api\d+-)?|AKIA|ASIA|eyJ)[A-Za-z0-9_-]{20,}")
PUBLIC_PYPI = {"https://pypi.org/simple", "https://pypi.org/simple/"}


def digest(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True, default=str, allow_nan=False).encode()).hexdigest()


def _float(value):
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("nonfinite_inventory_value")
    return parsed


def load_inventory(raw: str, cap: int, kind: str) -> dict:
    if kind not in {"uv", "pylock"}:
        raise ValueError("unsupported_inventory_toml_kind")
    if not isinstance(raw, str) or len(raw) > 16 * 1024 * 1024 or type(cap) is not int or not 1 <= cap <= 10000:
        raise ValueError(kind + "_inventory_budget")
    try:
        payload = tomllib.loads(raw, parse_float=_float)
    except (ValueError, RecursionError, OverflowError):
        # Newer TOMLDecodeError may include a private source line.
        raise ValueError("malformed_" + ("uv_lock" if kind == "uv" else "pylock")) from None
    stack, nodes = [(payload, 0)], 0
    while stack:
        item, depth = stack.pop(); nodes += 1
        if nodes > 100000 or depth > 64:
            raise ValueError(kind + "_inventory_structure_limit")
        if isinstance(item, (dict, list)):
            if nodes + len(stack) + len(item) > 100000:
                raise ValueError(kind + "_inventory_structure_limit")
            stack.extend((v, depth + 1) for v in (item.values() if isinstance(item, dict) else item))
    return payload
