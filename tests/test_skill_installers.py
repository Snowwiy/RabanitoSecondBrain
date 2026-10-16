from __future__ import annotations

import hashlib
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "integrations" / "scripts"
UNINSTALLER = ROOT / "integrations" / "scripts"


def _powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


class SkillInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shell = _powershell()

    def setUp(self) -> None:
        if not self.shell:
            self.skipTest("PowerShell is not available")
        self.test_root = Path(__file__).resolve().parent / ".test-temp"
        self.test_root.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="skill-install-ñ-", dir=self.test_root)
        self.addCleanup(self.temp.cleanup)
        self.skill_root = Path(self.temp.name) / "client skills"
        self.skill_root.mkdir()

    def run_script(self, script: Path, client: str, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [self.shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-File", str(script), "-SkillRoot", str(self.skill_root), *extra],
            cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        )

    def test_install_is_idempotent_and_uninstall_removes_only_unchanged_owned_copy(self) -> None:
        temporary_root = Path(self.temp.name)
        for client in ("Claude", "Codex", "Hermes"):
            with self.subTest(client=client):
                self.skill_root = temporary_root / client
                self.skill_root.mkdir()
                unrelated = self.skill_root / "keep-user-data.txt"
                unrelated.write_text("preserve", encoding="utf-8")
                installed = self.skill_root / "rabanito-second-brain"

                first = self.run_script(INSTALLER / f"Install-{client}Skill.ps1", client)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertTrue((installed / "SKILL.md").is_file())
                original_hash = hashlib.sha256((installed / "SKILL.md").read_bytes()).hexdigest()

                second = self.run_script(INSTALLER / f"Install-{client}Skill.ps1", client)
                self.assertEqual(second.returncode, 0, second.stderr)
                self.assertIn("Already installed", second.stdout)
                self.assertEqual(hashlib.sha256((installed / "SKILL.md").read_bytes()).hexdigest(), original_hash)

                removed = self.run_script(UNINSTALLER / f"Uninstall-{client}Skill.ps1", client)
                self.assertEqual(removed.returncode, 0, removed.stderr)
                self.assertFalse(installed.exists())
                self.assertEqual(unrelated.read_text(encoding="utf-8"), "preserve")
                unrelated.unlink()
                self.skill_root.rmdir()

    def test_existing_unmanaged_content_is_never_overwritten(self) -> None:
        installed = self.skill_root / "rabanito-second-brain"
        installed.mkdir()
        user_file = installed / "notes.txt"
        user_file.write_text("user-owned", encoding="utf-8")

        result = self.run_script(INSTALLER / "Install-CodexSkill.ps1", "Codex")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(user_file.is_file())
        self.assertEqual(user_file.read_text(encoding="utf-8"), "user-owned")

    def test_uninstall_refuses_an_edited_install_and_preserves_it(self) -> None:
        installed = self.skill_root / "rabanito-second-brain"
        installed_result = self.run_script(INSTALLER / "Install-HermesSkill.ps1", "Hermes")
        self.assertEqual(installed_result.returncode, 0, installed_result.stderr)
        skill = installed / "SKILL.md"
        skill.write_text(skill.read_text(encoding="utf-8") + "\nlocal edit\n", encoding="utf-8")

        result = self.run_script(UNINSTALLER / "Uninstall-HermesSkill.ps1", "Hermes")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(skill.is_file())
        self.assertIn("local edit", skill.read_text(encoding="utf-8"))

    def test_whatif_does_not_create_install_path(self) -> None:
        dry_run = self.run_script(INSTALLER / "Install-HermesSkill.ps1", "Hermes", "-WhatIf")
        self.assertEqual(dry_run.returncode, 0, dry_run.stderr)
        self.assertFalse((self.skill_root / "rabanito-second-brain").exists())

    def test_missing_skillroot_is_not_created(self) -> None:
        missing = self.skill_root / "not-created"
        self.skill_root.rmdir()
        self.skill_root = missing
        result = self.run_script(INSTALLER / "Install-ClaudeSkill.ps1", "Claude")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()
