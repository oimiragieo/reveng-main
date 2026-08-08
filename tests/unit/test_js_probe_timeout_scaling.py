"""Size-scaled JS probe timeouts (P3-BP-4)."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.capability_report import resolve_javascript_probe_timeout_sec


def test_resolve_timeout_small_tree_uses_base(tmp_path: Path) -> None:
    for i in range(3):
        (tmp_path / f"f{i}.js").write_text("1;\n", encoding="utf-8")
    assert resolve_javascript_probe_timeout_sec(tmp_path) == 25.0
    assert resolve_javascript_probe_timeout_sec(tmp_path, for_npm=True) == 90.0


def test_resolve_timeout_mid_tree(tmp_path: Path) -> None:
    for i in range(60):
        (tmp_path / f"f{i}.js").write_text("1;\n", encoding="utf-8")
    assert resolve_javascript_probe_timeout_sec(tmp_path) == 60.0


def test_resolve_timeout_explicit_wins(tmp_path: Path) -> None:
    (tmp_path / "a.js").write_text("1;\n", encoding="utf-8")
    assert resolve_javascript_probe_timeout_sec(tmp_path, explicit=12.5) == 12.5


def test_resolve_timeout_skips_node_modules(tmp_path: Path) -> None:
    nm = tmp_path / "node_modules" / "pkg"
    nm.mkdir(parents=True)
    for i in range(200):
        (nm / f"x{i}.js").write_text("1;\n", encoding="utf-8")
    (tmp_path / "app.js").write_text("1;\n", encoding="utf-8")
    assert resolve_javascript_probe_timeout_sec(tmp_path) == 25.0
