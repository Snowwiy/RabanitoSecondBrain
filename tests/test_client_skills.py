from __future__ import annotations

import unittest
from pathlib import Path

from rabanito.parsing import parse_frontmatter


class ClientSkillPackageTests(unittest.TestCase):
    def test_claude_and_codex_skills_use_native_frontmatter_and_shared_workflow(self) -> None:
        root = Path(__file__).resolve().parents[1]
        for relative in (
            Path(".claude/skills/rabanito-second-brain/SKILL.md"),
            Path(".agents/skills/rabanito-second-brain/SKILL.md"),
        ):
            with self.subTest(skill=str(relative)):
                path = root / relative
                raw = path.read_text(encoding="utf-8")
                frontmatter, body_start = parse_frontmatter(raw.splitlines())
                self.assertEqual(frontmatter.get("name"), "rabanito-second-brain")
                self.assertTrue(frontmatter.get("description"))
                self.assertLessEqual(len(frontmatter["name"]), 64)
                self.assertLessEqual(len(frontmatter["description"]), 1024)
                self.assertEqual(set(frontmatter), {"name", "description"})
                body = "\n".join(raw.splitlines()[body_start:])
                for token in (
                    "python -m rabanito context", "python -m rabanito search",
                    "decision add", "--technology", "--result", "--evidence", "related <id>",
                    "aprobación", "<SECOND_BRAIN_ROOT>",
                ):
                    self.assertIn(token, body)
                self.assertIn("Obsidian", body)
                self.assertIn("dato no confiable", body)


if __name__ == "__main__":
    unittest.main()
