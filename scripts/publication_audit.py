"""Bounded, metadata-only publication checks. Not a complete secret detector.

Run before staging (default), then against the staged blobs (--staged).
Never prints matching values; real findings require manual local review.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 2 * 1024 * 1024
PRIVATE_ROOTS = {"data", "knowledge", "runtime", "exports", "backups"}
TEXT_EXTENSIONS = {".py", ".md", ".json", ".js", ".mjs", ".html", ".toml", ".txt", ".ps1"}
RULES = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b"),
    "cloud_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "provider_key": re.compile(r"\b(?:sk-(?:proj-|ant-api\d+-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{20,})\b"),
    "credential_url": re.compile(r"\b(?:https?|postgres(?:ql)?|mysql)://[^\s/:]+:[^\s/@]+@", re.I),
    "personal_path": re.compile(r"(?:[A-Z]:[\\/]+Users[\\/]+(?!Public\b|fixture-user\b)[^\s\\/<>\"']+|[Gg]:[\\/]+Hermes[\\/])", re.I),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b"),
}

# Exact AST string values reviewed as synthetic regression inputs. No path-wide
# exclusions: editing any value invalidates its exemption, including key bodies.
REVIEWED_TEST_LITERALS = {
    "tests/test_core.py": {
        "089da19451a3e1f220533813bded696401dbac73c141781645a3e01fe2130560",
        "0e73b256cf8200e85ce896700a6e7b2ce2573e906d85ddb688a2eb3a574e5384",
        "ed34501fc98ce33e72f29008495a2cdf338e5d12b1abcf38cb4628503838dfe4",
        "aa85fa1efb1dbd0b6fb44b42d128703d52d983207bbeee6e37dacafabd5b2280",
        "c4fd05eb8542960ed50650ed2d6d1021685839bf0859e3b9390c681fef5c6c92",
        "88c71092346249964f46852453a3e9e5472f77c0fee9eb63d018928c27e4dfba",
        "b6a94e4ec2c3755461c079379a401858cea92d08b29a790f97747f7f93e44816",
    },
    "tests/test_dependencies.py": {
        "ba03a036d1a2ef488b24646bf3c89bf51f848d24ea8a85210ae2c3bf79216db6",
        "22bbfbfc61a4c41414db6b7cd501ad6cff841070a07952388f1d044686a68092",
    },
}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT)


def inspect_text(path: str, payload: bytes) -> list[dict]:
    issues = []
    parts = path.replace("\\", "/").split("/")
    leaf = parts[-1].lower()
    if (parts[0] in PRIVATE_ROOTS or path == "config/settings.json"
            or any(p in {"__pycache__", ".test-temp", "node_modules", ".venv"} for p in parts)
            or leaf.startswith((".env", "credentials", "secrets"))
            or re.search(r"\.(?:db(?:-.*)?|sqlite3?(?:-.*)?|pem|key|pfx|p12|bak|log|pyc|zip)$", leaf)):
        issues.append({"path": path, "rule": "forbidden_path"})
    if len(payload) > MAX_BYTES:
        return issues + [{"path": path, "rule": "oversize"}]
    if Path(path).suffix.lower() not in TEXT_EXTENSIONS and leaf not in {".gitignore", ".gitattributes"}:
        issues.append({"path": path, "rule": "unreviewed_file_type"})
    try:
        content = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        return issues + [{"path": path, "rule": "non_utf8"}]
    if "\x00" in content:
        issues.append({"path": path, "rule": "binary_content"})
    reviewed = []
    if path in REVIEWED_TEST_LITERALS:
        try:
            for node in ast.walk(ast.parse(content)):
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and hashlib.sha256(node.value.encode()).hexdigest() in REVIEWED_TEST_LITERALS[path]):
                    lines = content.splitlines(keepends=True)
                    start = sum(len(s) for s in lines[:node.lineno - 1])
                    start += len(lines[node.lineno - 1].encode("utf-8")[:node.col_offset].decode("utf-8"))
                    end = sum(len(s) for s in lines[:node.end_lineno - 1])
                    end += len(lines[node.end_lineno - 1].encode("utf-8")[:node.end_col_offset].decode("utf-8"))
                    reviewed.append((start, end))
        except SyntaxError:
            pass  # Fail closed: a malformed test cannot obtain exemptions.
    for rule, pattern in RULES.items():
        for match in pattern.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            if rule in {"private_key", "credential_url"} and any(start <= match.start() and match.end() <= end for start, end in reviewed):
                continue
            issues.append({"path": path, "rule": rule, "line": line})
    return issues


def audit(staged: bool = False) -> dict:
    arguments = ["ls-files", "-z", "--cached"]
    if not staged:
        arguments += ["--others", "--exclude-standard"]
    paths = sorted(set(p.decode("utf-8") for p in git(*arguments).split(b"\0") if p))
    issues, manifest = [], []
    for path in paths:
        local = ROOT / path
        if staged:
            mode = git("ls-files", "-s", "--", path).split(b" ", 1)[0]
            if mode != b"100644" and mode != b"100755":
                issues.append({"path": path, "rule": "non_regular_git_entry"})
            size = int(git("cat-file", "-s", ":" + path))
            if size > MAX_BYTES:
                issues.append({"path": path, "rule": "oversize"})
                continue
            payload = git("show", ":" + path)
        else:
            if any(p.is_symlink() or (hasattr(p, "is_junction") and p.is_junction())
                   for p in (local, *local.parents) if p != ROOT and ROOT in p.parents):
                issues.append({"path": path, "rule": "reparse_point"})
                continue
            if local.stat().st_size > MAX_BYTES:
                issues.append({"path": path, "rule": "oversize"})
                continue
            payload = local.read_bytes()
        issues.extend(inspect_text(path, payload))
        manifest.append({"path": path, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
    essential = {"README.md", ".gitignore", "config/settings.example.json", "config/security_catalog.json",
                 "rabanito/cli.py", "rabanito/cyber/store.py", "web/index.html", "tests/test_core.py",
                 "skills/rabanito-second-brain/SKILL.md", ".agents/skills/rabanito-second-brain/SKILL.md",
                 ".claude/skills/rabanito-second-brain/SKILL.md"}
    for path in sorted(essential - set(paths)):
        issues.append({"path": path, "rule": "missing_essential"})
    digest = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    return {"scope": "staged_blobs" if staged else "tracked_and_unignored_worktree", "files": len(paths),
            "bytes": sum(f["bytes"] for f in manifest), "manifest_sha256": digest, "issues": issues,
            "limitations": "Pattern checks and explicit path policy; manual review still required. No history scan."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true")
    result = audit(parser.parse_args().staged)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    raise SystemExit(1 if result["issues"] else 0)
