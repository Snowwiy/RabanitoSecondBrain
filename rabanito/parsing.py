from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .utils import redact_sensitive_lines, sha256_text


WIKILINK_RE = re.compile(r"(!?)\[\[([^\]]+)\]\]")
MARKDOWN_LINK_START_RE = re.compile(r"(?P<embed>!)?\[(?P<label>[^\]]*)\]\(")
TAG_RE = re.compile(r"(?<![\w])#([\w][\w/-]*)", re.UNICODE)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
INLINE_CODE_RE = re.compile(r"(`+).*?\1")
YAML_DOUBLE_QUOTED_ESCAPES = {
    "0": "\0", "a": "\a", "b": "\b", "t": "\t", "n": "\n", "v": "\v",
    "f": "\f", "r": "\r", "e": "\x1b", " ": "\u00a0", '"': '"', "/": "/",
    "\\": "\\", "N": "\u0085", "_": "\u00a0", "L": "\u2028", "P": "\u2029",
}


@dataclass
class ParsedDocument:
    title: str
    frontmatter: dict[str, Any]
    tags: list[str]
    links: list[dict[str, Any]]
    text: str
    chunks: list[dict[str, Any]]
    content_hash: str
    parse_error: str | None = None


def _decode_yaml_double_quoted(value: str) -> str:
    decoded: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "\\" or index + 1 >= len(value):
            decoded.append(value[index])
            index += 1
            continue
        escape = value[index + 1]
        if escape in YAML_DOUBLE_QUOTED_ESCAPES:
            decoded.append(YAML_DOUBLE_QUOTED_ESCAPES[escape])
            index += 2
            continue
        if escape in {"x", "u", "U"}:
            digits_count = {"x": 2, "u": 4, "U": 8}[escape]
            digits = value[index + 2:index + 2 + digits_count]
            if len(digits) == digits_count and re.fullmatch(r"[0-9A-Fa-f]+", digits):
                codepoint = int(digits, 16)
                if codepoint <= 0x10FFFF and not 0xD800 <= codepoint <= 0xDFFF:
                    decoded.append(chr(codepoint))
                    index += 2 + digits_count
                    continue
            decoded.append(value[index:index + 2 + len(digits)])
            index += 2 + len(digits)
            continue
        # Preserve malformed/unknown escapes as literal text rather than dropping data.
        decoded.extend(("\\", escape))
        index += 2
    return "".join(decoded)


def _scalar(value: str) -> Any:
    value = _strip_yaml_comment(value).strip()
    if not value:
        return ""
    if value.startswith("\"") and value.endswith("\""):
        return _decode_yaml_double_quoted(value[1:-1])
    if value.startswith("'") and value.endswith("'"):
        return value[1:-1].replace("''", "'")
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "~"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_scalar(item) for item in _split_flow_sequence(inner)]
    if re.fullmatch(r"-?\d+", value):
        try:
            return int(value)
        except ValueError:
            pass
    return value


def _yaml_block_header(value: str) -> tuple[str, str, int | None] | None:
    header = _strip_yaml_comment(value).strip()
    if not re.fullmatch(r"[|>](?:(?:[+-][1-9]?)|(?:[1-9][+-]?))?", header):
        return None
    suffix = header[1:]
    chomp = next((char for char in suffix if char in "+-"), "")
    indentation = next((int(char) for char in suffix if char.isdigit()), None)
    return header[0], chomp, indentation


def _fold_yaml_block_lines(lines: list[str]) -> str:
    parts: list[str] = []
    index = 0
    while index < len(lines):
        if not lines[index]:
            start = index
            while index < len(lines) and not lines[index]:
                index += 1
            blank_count = index - start
            if start == 0:
                parts.append("\n" * blank_count)
            elif index < len(lines):
                more_indented = lines[start - 1].startswith(" ") or lines[index].startswith(" ")
                parts.append("\n" * (blank_count + 1 if more_indented else max(1, blank_count)))
            continue

        parts.append(lines[index])
        if index + 1 < len(lines) and lines[index + 1]:
            more_indented = lines[index].startswith(" ") or lines[index + 1].startswith(" ")
            parts.append("\n" if more_indented else " ")
        index += 1
    return "".join(parts)


def _yaml_block_scalar(
    lines: list[str], end: int, start: int, key_indent: int, header: tuple[str, str, int | None],
) -> tuple[str, int]:
    style, chomp, explicit_indent = header
    cursor = start + 1
    content_indent = key_indent + explicit_indent if explicit_indent is not None else None
    if content_indent is None:
        probe = cursor
        while probe < end:
            candidate = lines[probe]
            if not candidate.strip():
                probe += 1
                continue
            indentation = len(candidate) - len(candidate.lstrip(" "))
            if indentation <= key_indent:
                break
            content_indent = indentation
            break

    if content_indent is None:
        while cursor < len(lines) and not lines[cursor].strip():
            cursor += 1
        return "", cursor

    content: list[str] = []
    while cursor < end:
        line = lines[cursor]
        if not line.strip():
            content.append(line[content_indent:] if len(line) > content_indent else "")
            cursor += 1
            continue
        indentation = len(line) - len(line.lstrip(" "))
        if indentation < content_indent:
            break
        content.append(line[content_indent:])
        cursor += 1

    trailing_empty = 0
    while content and not content[-1].strip():
        content.pop()
        trailing_empty += 1
    if style == ">":
        value = _fold_yaml_block_lines(content)
    else:
        value = "\n".join(content)

    if content:
        if chomp == "+":
            value += "\n" * (trailing_empty + 1)
        elif chomp != "-":
            value += "\n"
    elif chomp == "+" and trailing_empty:
        value = "\n" * trailing_empty
    return value, cursor


def _strip_yaml_comment(value: str) -> str:
    """Remove a YAML line comment without treating quoted or embedded # as comments."""
    quote: str | None = None
    index = 0
    while index < len(value):
        char = value[index]
        if quote == "'":
            if char == "'" and index + 1 < len(value) and value[index + 1] == "'":
                index += 2
                continue
            if char == "'":
                quote = None
        elif quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = None
        elif char in ("'", '"'):
            quote = char
        elif char == "#" and (index == 0 or value[index - 1].isspace()):
            return value[:index].rstrip()
        index += 1
    return value


def _split_flow_sequence(value: str) -> list[str]:
    """Split a YAML flow sequence at commas outside quoted/nested values."""
    items: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(value):
        if quote:
            if escaped:
                escaped = False
            elif quote == '"' and char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in ("'", '"'):
            quote = char
        elif char in ("[", "{"):
            depth += 1
        elif char in ("]", "}"):
            depth = max(0, depth - 1)
        elif char == "," and depth == 0:
            item = value[start:index].strip()
            if item:
                items.append(item)
            start = index + 1
    item = value[start:].strip()
    if item:
        items.append(item)
    return items


def parse_frontmatter(lines: list[str]) -> tuple[dict[str, Any], int]:
    if not lines or lines[0].strip() != "---":
        return {}, 0
    # YAML document delimiters are top-level markers. An indented `---` inside a
    # literal/folded block scalar is content and must not terminate frontmatter.
    end = next((index for index in range(1, len(lines)) if lines[index] == "---"), None)
    if end is None:
        return {}, 0
    result: dict[str, Any] = {}
    current_key: str | None = None
    index = 1
    while index < end:
        raw_line = lines[index]
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            index += 1
            continue
        stripped = raw_line.strip()
        if stripped.startswith("-") and current_key:
            current_value = result.get(current_key)
            if current_value in (None, ""):
                result[current_key] = []
            elif not isinstance(current_value, list):
                result[current_key] = [current_value]
            result[current_key].append(_scalar(stripped[1:].strip()))
            index += 1
            continue
        if ":" not in raw_line:
            index += 1
            continue
        key, raw_value = raw_line.split(":", 1)
        current_key = key.strip()
        block_header = _yaml_block_header(raw_value)
        if block_header:
            key_indent = len(raw_line) - len(raw_line.lstrip(" "))
            result[current_key], index = _yaml_block_scalar(lines, end, index, key_indent, block_header)
            continue
        result[current_key] = _scalar(raw_value)
        index += 1
    return result, end + 1


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item is not None and str(item).strip()]
    return [str(value)]


def _link_parts(raw: str) -> tuple[str, str | None]:
    target, _, label = raw.partition("|")
    target, _, _heading = target.partition("#")
    return target.strip(), label.strip() or None


def _markdown_destination(raw: str) -> str:
    """Extract a Markdown destination, preserving unescaped spaces in local paths."""
    value = raw.strip()
    if value.startswith("<"):
        closing = value.find(">")
        if closing >= 0:
            value = value[1:closing]
    else:
        # A quoted title is unambiguous; spaces before it belong to the title boundary,
        # while spaces earlier in the target remain part of an Obsidian local path.
        title = re.match(r"^(.*?)(?:\s+[\"'].*[\"'])\s*$", value, re.DOTALL)
        if title:
            value = title.group(1).rstrip()
    return value.replace(r"\(", "(").replace(r"\)", ")").strip()


def _markdown_links(line: str, line_number: int) -> list[dict[str, Any]]:
    """Parse inline Markdown links with balanced parentheses and optional titles."""
    links: list[dict[str, Any]] = []
    position = 0
    while match := MARKDOWN_LINK_START_RE.search(line, position):
        cursor = match.end()
        depth = 1
        in_angle_destination = False
        escaped = False
        while cursor < len(line):
            char = line[cursor]
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == "<" and depth == 1:
                in_angle_destination = True
            elif char == ">" and in_angle_destination:
                in_angle_destination = False
            elif not in_angle_destination and char == "(":
                depth += 1
            elif not in_angle_destination and char == ")":
                depth -= 1
                if depth == 0:
                    target = _markdown_destination(line[match.end():cursor])
                    if target:
                        links.append({
                            "target_raw": target,
                            "label": match.group("label").strip() or None,
                            "line_number": line_number,
                            "relation_type": "embed" if match.group("embed") else "markdown",
                        })
                    position = cursor + 1
                    break
            cursor += 1
        else:
            # Malformed link: do not consume the rest of the line or invent a destination.
            position = match.end()
    return links


def _visible_markdown_lines(lines: list[str]) -> list[str]:
    """Remove fenced/inline code and HTML comments while preserving physical lines."""
    visible: list[str] = []
    fence_char: str | None = None
    fence_size = 0
    in_comment = False
    for line in lines:
        fence = FENCE_RE.match(line)
        if fence_char:
            if fence and fence.group(1)[0] == fence_char and len(fence.group(1)) >= fence_size:
                fence_char = None
                fence_size = 0
            visible.append("")
            continue
        if fence:
            fence_char = fence.group(1)[0]
            fence_size = len(fence.group(1))
            visible.append("")
            continue
        current = line
        while current:
            if in_comment:
                end = current.find("-->")
                if end < 0:
                    current = ""
                    break
                current = current[end + 3:]
                in_comment = False
                continue
            start = current.find("<!--")
            if start < 0:
                break
            end = current.find("-->", start + 4)
            if end < 0:
                current = current[:start]
                in_comment = True
                break
            current = current[:start] + current[end + 3:]
        visible.append(INLINE_CODE_RE.sub("", current))
    return visible


def _make_chunks(text: str, max_chars: int = 1600, line_offset: int = 0) -> list[dict[str, Any]]:
    lines = text.splitlines()
    chunks: list[dict[str, Any]] = []
    heading = ""
    buffer: list[str] = []
    start = 1 + line_offset
    buffered_chars = 0

    def flush(end_line: int) -> None:
        nonlocal buffer, start, buffered_chars
        content = "\n".join(buffer).strip()
        if content:
            chunks.append({"heading": heading, "line_start": start, "line_end": end_line, "text": content})
        buffer = []
        buffered_chars = 0
        start = end_line + 1

    for number, line in enumerate(lines, 1):
        physical_number = number + line_offset
        match = HEADING_RE.match(line)
        if match:
            if buffer:
                flush(physical_number - 1)
            heading = match.group(2).strip()
            start = physical_number
            buffer = [line]
            buffered_chars = len(line) + 1
            continue
        buffer.append(line)
        buffered_chars += len(line) + 1
        if buffered_chars >= max_chars:
            flush(physical_number)
    if buffer:
        flush((len(lines) or 1) + line_offset)
    return chunks


def parse_markdown(path: Path, redact: bool = True, raw_text: str | None = None) -> ParsedDocument:
    try:
        raw = raw_text if raw_text is not None else path.read_text(encoding="utf-8-sig", errors="replace")
        safe_raw = redact_sensitive_lines(raw) if redact else raw
        lines = safe_raw.splitlines()
        frontmatter, body_start = parse_frontmatter(lines)
        body = "\n".join(lines[body_start:]) if body_start else safe_raw
        visible_lines = _visible_markdown_lines(lines)
        heading = next((HEADING_RE.match(line) for line in lines[body_start:] if HEADING_RE.match(line)), None)
        title = str(frontmatter.get("title") or (heading.group(2).strip() if heading else path.stem))
        tags = _as_list(frontmatter.get("tags"))
        visible_body = "\n".join(visible_lines[body_start:] if body_start else visible_lines)
        tags.extend(match.group(1) for match in TAG_RE.finditer(visible_body))
        tags = sorted({tag.lstrip("#") for tag in tags if tag.strip()})
        links: list[dict[str, Any]] = []
        for number, line in enumerate(visible_lines, 1):
            for match in WIKILINK_RE.finditer(line):
                target, label = _link_parts(match.group(2))
                links.append({"target_raw": target, "label": label, "line_number": number,
                              "relation_type": "embed" if match.group(1) else "wikilink"})
            links.extend(_markdown_links(line, number))
        return ParsedDocument(
            title=title,
            frontmatter=frontmatter,
            tags=tags,
            links=links,
            text=body,
            chunks=_make_chunks(body, line_offset=body_start),
            content_hash=sha256_text(raw),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        return ParsedDocument(
            title=path.stem,
            frontmatter={},
            tags=[],
            links=[],
            text="",
            chunks=[],
            content_hash="",
            parse_error=f"{type(exc).__name__}: {exc}",
        )


def json_frontmatter(value: dict[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
