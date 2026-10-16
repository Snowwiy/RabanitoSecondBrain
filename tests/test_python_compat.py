from __future__ import annotations

import ast
import os
import re
import shutil
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _hermes_runtime_candidates(output: str) -> list[tuple[str, Path]]:
    candidates = []
    for line in output.splitlines():
        fields = line.strip().split(maxsplit=1)
        if len(fields) != 2:
            continue
        match = re.match(r"^-V:(\d+)\.(\d+)|^-(\d+)\.(\d+)", fields[0])
        if not match:
            continue
        major = int(match.group(1) or match.group(3))
        minor = int(match.group(2) or match.group(4))
        if major != 3 or not 11 <= minor <= 14:
            continue
        executable = Path(fields[1].lstrip("* ").strip().strip('"'))
        candidates.append((f"3.{minor}", executable))
    return candidates


class PythonCompatibilityTests(unittest.TestCase):
    def test_declared_minimum_python_311_syntax_parses(self) -> None:
        metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(metadata["project"]["requires-python"], ">=3.11")
        self.assertEqual(metadata["project"]["dependencies"], [])

        source_roots = (PROJECT_ROOT / "rabanito", PROJECT_ROOT / "tests")
        files = sorted(
            path
            for root in source_roots
            for path in root.rglob("*.py")
            if "__pycache__" not in path.parts and ".test-temp" not in path.parts
        )
        self.assertTrue(files, "Expected Python source files to validate")
        failures: list[str] = []
        for path in files:
            try:
                ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path), feature_version=(3, 11))
            except SyntaxError as exc:
                failures.append(f"{path.relative_to(PROJECT_ROOT)}:{exc.lineno}: {exc.msg}")
        self.assertEqual(failures, [], "Python 3.11 grammar incompatibilities: " + "; ".join(failures))

    def test_windows_python_launcher_listing_parser_selects_only_hermes_range(self) -> None:
        listing = (
            " -V:3.11[-64] C:\\Python311\\python.exe\n"
            " -V:3.14[-64] * C:\\Program Files\\Python314\\python.exe\n"
            " -V:3.15[-64] * C:\\Python315\\python.exe\n"
        )
        parsed = _hermes_runtime_candidates(listing)
        self.assertEqual(
            [(version, str(path)) for version, path in parsed],
            [("3.11", "C:\\Python311\\python.exe"),
             ("3.14", "C:\\Program Files\\Python314\\python.exe")],
        )

    def test_hermes_compatible_python_runtimes_import_core_and_support_fts5(self) -> None:
        if os.name != "nt":
            self.skipTest("Hermes runtime discovery uses the Windows py launcher")
        interpreters: list[tuple[str, Path]] = []
        current_version = sys.version_info[:2]
        if current_version[0] == 3 and 11 <= current_version[1] <= 14 and Path(sys.executable).is_file():
            interpreters.append((
                f"{current_version[0]}.{current_version[1]} (current interpreter)", Path(sys.executable),
            ))
        launcher = shutil.which("py")
        if launcher:
            listing = subprocess.run(
                [launcher, "-0p"], cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(listing.returncode, 0, listing.stderr)
            interpreters.extend(
                (version, executable)
                for version, executable in _hermes_runtime_candidates(listing.stdout)
                if executable.is_file()
            )
        elif not interpreters:
            self.skipTest("No compatible current Python or Windows py launcher is available")
        unique_interpreters: dict[str, tuple[str, Path]] = {}
        for version, executable in interpreters:
            key = os.path.normcase(os.path.normpath(str(executable)))
            unique_interpreters.setdefault(key, (version, executable))
        interpreters = list(unique_interpreters.values())
        if not interpreters:
            self.skipTest("No Python 3.11–3.14 runtime is active or listed by py -0p")

        smoke = "\n".join((
            "import sqlite3",
            "import rabanito.capabilities, rabanito.cli, rabanito.decisions, rabanito.graph, rabanito.indexer, rabanito.server",
            "connection = sqlite3.connect(':memory:')",
            "connection.execute('CREATE VIRTUAL TABLE fts_probe USING fts5(content)')",
            "connection.execute('INSERT INTO fts_probe(content) VALUES (?)', ('ftsready',))",
            "if connection.execute(\"SELECT count(*) FROM fts_probe WHERE fts_probe MATCH 'ftsready'\").fetchone()[0] != 1: raise SystemExit('FTS5 query failed')",
            "connection.close()",
        ))
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        for version, executable in interpreters:
            with self.subTest(python=version, executable=str(executable)):
                result = subprocess.run(
                    [str(executable), "-c", smoke], cwd=PROJECT_ROOT, env=environment,
                    capture_output=True, text=True, timeout=20,
                )
                self.assertEqual(
                    result.returncode, 0,
                    f"Python {version} core/SQLite FTS5 smoke failed: {result.stderr or result.stdout}",
                )


if __name__ == "__main__":
    unittest.main()
