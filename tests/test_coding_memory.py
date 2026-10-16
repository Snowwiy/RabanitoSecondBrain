from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from rabanito.cli import main as cli_main
from rabanito.config import Settings
from rabanito.indexer import index_all
from rabanito.search import retrieve_context
from rabanito.utils import write_json_atomic


class CodingMemoryCliTests(unittest.TestCase):
    def test_cli_records_and_recovers_verified_coding_experience_with_citations(self) -> None:
        test_root = Path(__file__).resolve().parent / ".test-temp"
        test_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="coding-memory-", dir=test_root) as temporary:
            root = Path(temporary)
            vault = root / "Obsidian ñ"
            projects = root / "Proyectos"
            knowledge = root / "knowledge"
            vault.mkdir()
            projects.mkdir()
            knowledge.mkdir()
            project = projects / "Ráfaga"
            project.mkdir()
            (project / "README.md").write_text(
                "# Ráfaga\n\nThe parser needs deterministic UTF-8 handling.\n", encoding="utf-8",
            )
            settings = Settings(root, {
                "project_root": str(root), "vault_root": str(vault), "projects_root": str(projects),
                "database_path": str(root / "data" / "brain.db"), "data_dir": str(root / "data"),
                "knowledge_dir": str(knowledge), "max_search_results": 20, "max_context_chars": 5000,
                "stale_days": 180,
                "source_policy": {
                    "obsidian": {"extensions": [".md"], "exclude_dirs": [".obsidian"], "exclude_names": []},
                    "projects": {"extensions": [".md"], "metadata_names": ["README.md"],
                                 "exclude_dirs": [".git"], "exclude_names": []},
                    "internal": {"extensions": [".md"], "exclude_dirs": [], "exclude_names": []},
                },
                "additional_sources": [],
            })
            index_all(settings)
            config = root / "config" / "settings.json"
            write_json_atomic(config, settings.raw)

            output = StringIO()
            with redirect_stdout(output):
                cli_main([
                    "--config", str(config), "decision", "add", "--project", str(project),
                    "--record-type", "fact", "--status", "confirmed",
                    "--problem", "The parser lost Unicode paths when the default encoding varied.",
                    "--reason", "The README documents deterministic UTF-8 input handling.",
                    "--statement", "Read source Markdown explicitly as UTF-8.",
                    "--technology", "Python", "--technology", "SQLite",
                    "--component", "Markdown importer", "--test", "fixture with Unicode filename passed",
                    "--result", "The indexed title remained Ráfaga and search returned its citation.",
                    "--evidence", "project:README.md", "--validation", "passed", "--date", "2026-10-13",
                ])
            recorded = json.loads(output.getvalue())
            self.assertEqual(recorded["status"], "confirmed")
            self.assertEqual(recorded["record_type"], "fact")
            self.assertEqual(recorded["technologies"], ["Python", "SQLite"])
            self.assertEqual(recorded["evidence"], ["project:README.md"])
            self.assertTrue(Path(recorded["path"]).is_file())

            output = StringIO()
            with redirect_stdout(output):
                cli_main(["--config", str(config), "decision", "list", "--project", str(project)])
            records = json.loads(output.getvalue())
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["recorded_date"], "2026-10-13")
            self.assertEqual(records[0]["technologies"], ["Python", "SQLite"])
            self.assertEqual(records[0]["evidence"], ["project:README.md"])

            context = retrieve_context(
                Settings(root, settings.raw), "Python SQLite", project=str(project),
                limit=10, max_chars=2500,
            )
            decision_fragments = [item for item in context["fragments"] if "decisions/" in item["relative_path"]]
            self.assertTrue(decision_fragments)
            self.assertTrue(all(item["line_start"] > 0 and item["line_end"] >= item["line_start"] for item in decision_fragments))
            self.assertTrue(all(item["citation"].startswith(item["absolute_path"] + ":") for item in decision_fragments))
            self.assertTrue(any("Python" in item["text"] and "SQLite" in item["text"] for item in decision_fragments))


if __name__ == "__main__":
    unittest.main()
