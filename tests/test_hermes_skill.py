from __future__ import annotations

import re
import sqlite3
import subprocess
import sys
import unittest
from pathlib import Path

from rabanito.parsing import parse_frontmatter


class HermesSkillTests(unittest.TestCase):
    def test_skill_has_hermes_loadable_frontmatter_and_safe_workflow(self) -> None:
        path = Path(__file__).resolve().parents[1] / "skills" / "rabanito-second-brain" / "SKILL.md"
        raw = path.read_text(encoding="utf-8")
        lines = raw.splitlines()
        frontmatter, body_start = parse_frontmatter(lines)
        self.assertEqual(lines[0], "---")
        self.assertGreater(body_start, 1)
        self.assertEqual(frontmatter["name"], "rabanito-second-brain")
        self.assertLessEqual(len(frontmatter["description"]), 60)
        self.assertTrue(frontmatter["description"].endswith("."))
        self.assertEqual(frontmatter["version"], "0.9.0")
        self.assertEqual(frontmatter["platforms"], "windows")
        self.assertTrue(frontmatter["author"].strip())
        self.assertTrue(frontmatter["license"].strip())
        self.assertNotIn("metadata", frontmatter, "the Hermes fallback parser must not need nested YAML")
        body = "\n".join(lines[body_start:])
        self.assertTrue(body.strip())
        self.assertIn("workdir=", body)
        self.assertIn("CREATE VIRTUAL TABLE probe USING fts5(body)", body)
        self.assertIn("(3, 11) <= sys.version_info[:2] < (3, 15)", body)
        self.assertIn("no instales Python, no cambies PATH", body)
        self.assertIn("--max-chars 6000", body, "the retrieval example must demonstrate a bounded context")
        self.assertIn("changes --project", body, "the skill should retrieve the bounded per-project change journal")
        self.assertIn("no explica por qué cambió", body, "mechanical change events must not be promoted to historical decisions")
        self.assertIn("Audit nunca sincroniza por sí mismo", body)
        self.assertIn("prune-search-cache", body)
        self.assertIn("--apply --yes", body)
        self.assertIn("única copia", body)
        self.assertIn("comprobación parcial", body)
        self.assertIn("decision add", body)
        self.assertIn("--technology", body)
        self.assertIn("--result", body)
        self.assertIn("rejected", body)
        self.assertIn("aprobación explícita", body)
        self.assertIn("no una memoria validada", body)

    def test_skill_preflight_command_is_valid_and_fails_closed_for_current_runtime(self) -> None:
        path = Path(__file__).resolve().parents[1] / "skills" / "rabanito-second-brain" / "SKILL.md"
        body = path.read_text(encoding="utf-8")
        match = re.search(r'`terminal\(command="(.*?)", workdir=', body)
        self.assertIsNotNone(match, "the documented terminal preflight command must be extractable")
        command = match.group(1).replace(r'\"', '"')
        prefix = "python -c "
        self.assertTrue(command.startswith(prefix))
        source_argument = command[len(prefix):]
        self.assertTrue(source_argument.startswith('"') and source_argument.endswith('"'))
        source = source_argument[1:-1]
        compile(source, "hermes-skill-preflight", "exec")
        self.assertNotIn("assert ", source, "the runtime guard must not be disabled by python -O")

        supports_version = (3, 11) <= sys.version_info[:2] < (3, 15)
        try:
            connection = sqlite3.connect(":memory:")
            connection.execute("CREATE VIRTUAL TABLE probe USING fts5(body)")
            connection.close()
            supports_fts5 = True
        except sqlite3.Error:
            supports_fts5 = False
        for optimization_flags in ([], ["-O"]):
            with self.subTest(optimization=optimization_flags):
                result = subprocess.run(
                    [sys.executable, *optimization_flags, "-c", source],
                    capture_output=True, text=True, check=False,
                )
                self.assertEqual(
                    result.returncode == 0,
                    supports_version and supports_fts5,
                    result.stderr,
                )


if __name__ == "__main__":
    unittest.main()
