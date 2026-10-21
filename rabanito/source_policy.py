"""Metadata-only document eligibility. No file opens, discovery or index writes."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from .config import Settings


def document_eligibility(settings: Settings):
    """Bind a caller-owned settings snapshot to a bounded pure SQL predicate."""
    # Local import avoids making indexer initialization depend on read predicates.
    from .indexer import DEFAULT_EXCLUDED_DIRS, _excluded_directory, _is_document_candidate, _policy

    contexts = settings.raw.get('excluded_memory_contexts', [])
    if not isinstance(contexts, list) or any(not isinstance(value, str) for value in contexts):
        raise ValueError('invalid_document_policy_contexts')
    excluded_contexts = {value.casefold() for value in contexts}
    policies = {}

    @lru_cache(maxsize=4096)
    def selected(kind: str, value: str) -> int:
        parts = value.replace('\\', '/').split('/')
        if any(not part or part in {'.', '..'} or part[-1:] in {' ', '.'}
               or re.search(r'[<>:"|?*\x00-\x1f\x7f\ud800-\udfff]', part)
               or re.fullmatch(r'(?i)(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?', part)
               for part in parts):
            return 0
        if kind not in policies:
            policy = _policy(settings, kind)
            policies[kind] = (
                policy, DEFAULT_EXCLUDED_DIRS | {str(v).casefold() for v in policy.get('exclude_dirs', [])},
                {str(v).casefold() for v in policy.get('exclude_extensions', [])},
            )
        policy, directories, extensions = policies[kind]
        path = Path(*parts)
        if (any(_excluded_directory(part, directories) for part in parts[:-1])
                or path.suffix.casefold() in extensions or not _is_document_candidate(path, policy)):
            return 0
        if (kind == 'internal' and len(parts) > 2
                and [part.casefold() for part in parts[:2]] == ['decisions', 'environments']
                and parts[2].casefold() in excluded_contexts):
            return 0
        return 1

    def eligible(kind, value):
        if not isinstance(kind, str) or not 1 <= len(kind) <= 80 or not isinstance(value, str) or not 1 <= len(value) <= 4000:
            return 0
        return selected(kind, value)
    return eligible
