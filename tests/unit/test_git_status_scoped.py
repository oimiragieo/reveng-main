"""DF-4: scoped git status excludes reports/; lists other dirty tracked paths."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "git_status_scoped.sh"


def test_script_exists():
    assert SCRIPT.is_file()
    assert os.access(SCRIPT, os.X_OK)


def test_script_excludes_reports_and_analysis_trees():
    text = SCRIPT.read_text(encoding="utf-8")
    assert ":(exclude)reports/" in text
    assert ":(exclude)analysis_*" in text


def test_script_never_runs_a_bare_git_status():
    lines = [
        ln.strip()
        for ln in SCRIPT.read_text(encoding="utf-8").splitlines()
        if ln.strip().startswith("git status")
    ]
    assert lines, "expected at least one git status invocation"
    for line in lines:
        assert "--" in line, f"unscoped git status would hang on DrvFS: {line}"


def test_behavioral_temp_repo_excludes_reports_includes_readme(tmp_path: Path):
    """Dirty reports/huge.bin must not appear; dirty README.md must."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "README.md").write_text("clean\n", encoding="utf-8")
    reports = repo / "reports"
    reports.mkdir()
    (reports / "huge.bin").write_bytes(b"\0" * 64)
    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=repo,
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "add", "README.md", "reports/huge.bin"], cwd=repo, check=True)
    subprocess.run(
        ["git", "commit", "-m", "seed"],
        cwd=repo,
        check=True,
        capture_output=True,
    )

    (repo / "README.md").write_text("dirty\n", encoding="utf-8")
    (reports / "huge.bin").write_bytes(b"\xff" * 128)

    proc = subprocess.run(
        ["bash", str(SCRIPT)],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    out = proc.stdout
    assert "README.md" in out, f"expected README.md in scoped status, got:\n{out}"
    assert "huge.bin" not in out, f"reports/huge.bin must be excluded, got:\n{out}"
    assert "reports/" not in out, f"reports/ paths must be excluded, got:\n{out}"
