"""Pure preview for human review. No storage, approval, indexing or evidence execution."""
from __future__ import annotations

import json
import re
from datetime import date

from .documented_memory import HEADINGS, _metadata
from .utils import redact_sensitive_lines, sha256_text

MAX_INPUT_BYTES = 65_536
FIELDS = {"scope_id", "project", "recorded_date", "validation", "current_state_validation", "technologies"}


def _text(value, maximum, *, single=False):
    if (not isinstance(value, str) or not value.strip() or len(value) > maximum
            or any(ord(c) < 32 and c not in "\n\t" or 0xD800 <= ord(c) <= 0xDFFF for c in value)
            or single and any(c in value for c in "\n\t")):
        raise ValueError("invalid_documented_draft_text")
    return value


def preview_documented_experience(payload: dict, *, reviewed_on: str) -> dict:
    """Return exact candidate Markdown + domain-separated digest, never approval.

    Dates, observations and historical claims are supplied by the author, not
    independently verified here. reviewed_on is a proposed review date in the
    candidate; the envelope explicitly says it has NOT been approved or saved.
    """
    if (not isinstance(payload, dict) or set(payload) != {"title", "metadata", "sections"}
            or not isinstance(payload["metadata"], dict) or set(payload["metadata"]) != FIELDS
            or not isinstance(payload["sections"], dict) or set(payload["sections"]) != set(HEADINGS)):
        raise ValueError("invalid_documented_draft_fields")
    title = _text(payload["title"], 200, single=True)
    if not isinstance(reviewed_on, str) or date.fromisoformat(reviewed_on).isoformat() != reviewed_on:
        raise ValueError("invalid_documented_draft_review_date")
    metadata = {**payload["metadata"], "kind": "documented-experience", "record_type": "fact", "scope": "environment",
                "status": "documented", "review_status": "approved", "reviewed_on": reviewed_on,
                "historical_validation": "pending"}
    _metadata(metadata, "decisions/environments/" + str(metadata["scope_id"]) + "/candidate.md")
    if metadata["recorded_date"] > reviewed_on:
        raise ValueError("documented_draft_review_precedes_record")
    lines = ["---", *(key + ": " + json.dumps(value, ensure_ascii=False) for key, value in sorted(metadata.items())),
             "---", "", "# " + title, ""]
    for heading in HEADINGS:
        text = _text(payload["sections"][heading], 8000)
        if re.search(r"(?m)^##\s", text):
            raise ValueError("documented_draft_section_heading_collision")
        lines.extend(["## " + heading, "", text, ""])
    markdown = "\n".join(lines)
    if len(markdown.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("documented_draft_size_limit")
    if redact_sensitive_lines(markdown).splitlines() != markdown.splitlines():
        raise ValueError("documented_draft_sensitive_content")
    return {"mode": "preview_only_not_approved", "approval_required": True, "persisted": False, "indexed": False,
            "fully_verified": False, "historical_validation": "pending", "content_markdown": markdown,
            "approval_digest": sha256_text("rabanito-documented-preview-v1\0" + markdown),
            "limitations": ["Candidate reviewed_on and approved metadata describe the proposed final note, not an approval already granted.",
                            "This preview does not verify historical causes or rerun any reported observation.",
                            "No writer or automatic confirmation is exposed by this command."]}


def read_draft_payload(stream):
    raw = stream.read(MAX_INPUT_BYTES + 1)
    if isinstance(raw, bytes):
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("documented_draft_input_size_limit")
        raw = raw.decode("utf-8-sig")
    if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError("documented_draft_input_size_limit")
    def unique_fields(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_documented_draft_field")
            result[key] = value
        return result
    try:
        payload = json.loads(raw, object_pairs_hook=unique_fields)
    except (json.JSONDecodeError, RecursionError):
        raise ValueError("invalid_documented_draft_json") from None
    return payload


def preview_from_stream(stream, *, reviewed_on):
    return preview_documented_experience(read_draft_payload(stream), reviewed_on=reviewed_on)
