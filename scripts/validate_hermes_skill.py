"""Opt-in test of an inspected local Hermes Skill loader, not a Hermes launch.

No bootstrap, CLI, package activation, .pth files, credentials or models. Uses
the existing PM-selected dependencies and a disposable home inside this repo.
The Python audit hook is defense in depth, NOT an OS sandbox against native code.
Review the local Hermes imports before running this against another revision.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT / "skills/rabanito-second-brain/SKILL.md"
OS_ENVIRONMENT = frozenset({
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
    "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "USERPROFILE",
    "HOMEDRIVE", "HOMEPATH", "LOCALAPPDATA",
})


def child_environment(original: dict[str, str], home: Path) -> dict[str, str]:
    """Do not pass provider keys, PATH overrides or Python startup variables."""
    result = {key: value for key, value in original.items() if key.upper() in OS_ENVIRONMENT}
    result["HERMES_HOME"] = str(home)
    return result


def selected_environment(repo: Path, version: tuple[int, int, int]):
    """Read PM selection only. Never run ensure, uv, activation or an installer."""
    key = hashlib.sha256(str(repo).encode()).hexdigest()[:16]
    facts = repo.parent / "installs" / key / "facts.json"
    if facts.is_symlink() or facts.stat().st_size > 1024 * 1024:
        raise ValueError("invalid_runtime_facts")
    raw = facts.read_bytes()
    install = facts.parent.resolve()
    venv = Path(json.loads(raw)["packages"]["venv"]["environment"]).resolve(strict=True)
    environments = (install / "environments").resolve(strict=True)
    if venv == environments or not venv.is_relative_to(environments):
        raise ValueError("runtime_environment_outside_install")
    values = dict(
        (key.strip(), value.strip())
        for line in (venv / "pyvenv.cfg").read_text(encoding="utf-8").splitlines()
        if "=" in line for key, _, value in [line.partition("=")]
    )
    recorded = values.get("version") or values.get("version_info", "")
    if recorded != ".".join(map(str, version)):
        raise ValueError("runtime_dependency_version_mismatch")
    site = (venv / "Lib/site-packages").resolve(strict=True)
    if not site.is_relative_to(environments):
        raise ValueError("runtime_packages_outside_install")
    return facts, raw, site


def accepted(report: dict) -> bool:
    """A subprocess exit code alone cannot certify the library test."""
    required = (
        "full_module_imported", "guard_write_rejected", "home_isolated",
        "skill_view_success", "exact_skill_body", "native_yaml_parser",
        "preprocessed_view_success", "preprocessed_plain_body_equal",
        "temporary_cleaned", "runtime_selection_unchanged",
    )
    return (
        all(report.get(key) is True for key in required)
        and report.get("readiness_status") == "available"
        and report.get("setup_needed") is False
        and report.get("native_traversal_rejections") == [True, True, True]
        and report.get("bootstrap_modules") == []
        and report.get("child_exit_code") == 0
        and "error" not in report
    )


def probe_child(settings: dict) -> dict:
    temporary = Path(settings["temporary"]).resolve(strict=True)
    repo = Path(settings["repo"]).resolve(strict=True)
    site = Path(settings["site"]).resolve(strict=True)
    runtime = Path(sys.base_prefix).resolve(strict=True)
    source = SKILL.parent.resolve(strict=True)
    denied: dict[str, int] = {}

    def reject(kind):
        denied[kind] = denied.get(kind, 0) + 1
        raise PermissionError("isolated_probe_policy_" + kind)

    def check(value, *, write):
        if isinstance(value, int):
            return  # Already-open descriptors; inherited stdio carries no source data.
        path = Path.cwd() if value is None else Path(os.fsdecode(value))
        path = path.resolve()
        if write:
            if not path.is_relative_to(temporary):
                reject("external_write")
            return
        leaf = path.name.casefold()
        sensitive = leaf.startswith((".env", "credentials", "secrets")) or leaf in {
            "config.yaml", "auth.json", "token.json", "tokens.json",
        }
        if sensitive and not path.is_relative_to(temporary):
            reject("external_sensitive_read")
        if not any(path.is_relative_to(root) for root in (temporary, repo, site, runtime, source)):
            reject("external_read")

    def audit(event, args):
        if event == "open":
            name, _mode, flags = args
            write = bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
            check(name, write=write)
        elif event in {"os.mkdir", "os.remove", "os.rmdir", "os.chmod", "os.utime", "os.truncate"}:
            check(args[0], write=True)
        elif event in {"os.rename", "os.link"}:
            check(args[0], write=True)
            check(args[1], write=True)
        elif event == "os.symlink":
            reject("symlink_creation")
        elif event in {"os.listdir", "os.scandir"}:
            check(args[0], write=False)
        elif event.startswith(("socket.connect", "socket.getaddrinfo")) or event == "socket.bind":
            reject("network")
        elif event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
            reject("process")

    sys.addaudithook(audit)
    # Deliberate rejection uses a generated path in OUR repo, not a user file.
    marker = ROOT / "tests/.test-temp/hermes-probe-outside-policy.marker"
    try:
        marker.write_text("synthetic guard probe", encoding="utf-8")
    except PermissionError:
        guard_rejected = True
    else:
        raise RuntimeError("write_guard_failed")
    sys.path[:0] = [str(repo), str(site)]  # Not site.addsitedir: never execute .pth.
    report = {"runtime": sys.version.split()[0], "guard_write_rejected": guard_rejected}
    log = io.StringIO()
    try:
        with contextlib.redirect_stdout(log), contextlib.redirect_stderr(log):
            import tools.skills_tool as tool

            report["full_module_imported"] = True
            report["home_isolated"] = tool.get_hermes_home().resolve() == temporary / "home"
            if not report["home_isolated"]:
                raise RuntimeError("home_isolation_failed")
            original = SKILL.read_text(encoding="utf-8")
            plain = json.loads(tool.skill_view("rabanito-second-brain", preprocess=False))
            rendered = json.loads(tool.skill_view("rabanito-second-brain", preprocess=True))
            report.update(
                skill_view_success=plain.get("success") is True,
                exact_skill_body=plain.get("content") == original,
                native_yaml_parser="hermes_yaml" in sys.modules,
                readiness_status=plain.get("readiness_status"),
                setup_needed=plain.get("setup_needed"),
                preprocessed_view_success=rendered.get("success") is True,
                preprocessed_plain_body_equal=rendered.get("content") == original,
            )
            rejected = []
            for name, linked in (
                ("../outside", None), ("C:\\outside", None),
                ("rabanito-second-brain", "../outside.md"),
            ):
                response = json.loads(tool.skill_view(name, file_path=linked, preprocess=False))
                rejected.append(response.get("success") is False)
            report["native_traversal_rejections"] = rejected
    except Exception as exc:
        report["error"] = type(exc).__name__  # Never print exception text/content.
    report.update(
        denied_events=denied, captured_log_chars=len(log.getvalue()),
        bootstrap_modules=[name for name in ("hermes_bootstrap", "hermes_cli.main") if name in sys.modules],
    )
    return report


def validate(repo: Path) -> dict:
    if os.name != "nt" or not ((3, 11) <= sys.version_info[:2] < (3, 15)):
        raise ValueError("validation_requires_compatible_native_windows_python")
    started = time.perf_counter()
    repo = repo.resolve(strict=True)
    facts, original_facts, site = selected_environment(repo, sys.version_info[:3])
    parent = ROOT / "tests/.test-temp"
    parent.mkdir(exist_ok=True)
    # This script does not install in the real profile, nor trust the project there.
    with tempfile.TemporaryDirectory(prefix="hermes-native-loader-", dir=parent) as folder:
        temporary = Path(folder)
        home = temporary / "home"
        target = home / "skills/rabanito-second-brain/SKILL.md"
        target.parent.mkdir(parents=True)
        shutil.copyfile(SKILL, target)
        # Preserve default native project discovery; empty external roots only.
        (home / "config.yaml").write_text("skills:\n  external_dirs: []\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-B", "-S", "-X", "utf8", str(Path(__file__).resolve()), "--_probe-child"],
            input=json.dumps({"temporary": str(temporary), "repo": str(repo), "site": str(site)}),
            cwd=ROOT, env=child_environment(dict(os.environ), home),
            capture_output=True, encoding="utf-8", timeout=30,
        )
        try:
            report = json.loads(result.stdout) if result.returncode == 0 else {}
            if not isinstance(report, dict):
                raise ValueError("invalid_child_report")
        except (ValueError, TypeError):
            report = {"error": "invalid_child_report"}
        report["child_exit_code"] = result.returncode
    report.update(
        mode="real_library_temporary_profile_not_live_agent",
        temporary_cleaned=not temporary.exists(),
        runtime_selection_unchanged=facts.read_bytes() == original_facts,
        runtime_facts_sha256=hashlib.sha256(original_facts).hexdigest(),
        skill_sha256=hashlib.sha256(SKILL.read_bytes()).hexdigest(),
        seconds=round(time.perf_counter() - started, 3),
    )
    report["accepted"] = accepted(report)
    return report


def main() -> int:
    if sys.argv[1:] == ["--_probe-child"]:
        print(json.dumps(probe_child(json.loads(sys.stdin.read())), ensure_ascii=True))
        return 0
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hermes-repo", type=Path, required=True, help="inspected local source checkout; read only")
    args = parser.parse_args()
    try:
        report = validate(args.hermes_repo)
    except Exception as exc:
        report = {"accepted": False, "error": type(exc).__name__}
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report.get("accepted") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
