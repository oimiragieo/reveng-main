"""Unit tests for filename-set JS oracle scorecard helper."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.js_oracle_scorecard import (
    compute_js_project_file_scorecard,
)


def test_relative_path_match_requires_recovered_root(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    (oracle / "src").mkdir(parents=True)
    (oracle / "src" / "a.js").write_text("a", encoding="utf-8")
    root = tmp_path / "recovered"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.js").write_text("x", encoding="utf-8")
    sc = compute_js_project_file_scorecard(
        oracle, [root / "src" / "a.js"], recovered_root=root
    )
    assert sc["match_mode"] == "relative_path"
    assert sc["project_file_recall"] == 1.0
    assert sc["reconstruction_mode"] == "filename_set"
    assert sc["overall_score"] == 1.0
    assert "token_signal_score" in sc
    assert sc["token_signal_mode"] == "filename_set_basename_jaccard_all"


def test_without_recovered_root_falls_back_to_basename(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    oracle.mkdir()
    (oracle / "a.js").write_text("a", encoding="utf-8")
    other = tmp_path / "elsewhere"
    other.mkdir()
    (other / "a.js").write_text("x", encoding="utf-8")
    sc = compute_js_project_file_scorecard(oracle, [other / "a.js"])
    assert sc["match_mode"] == "basename"
    assert "no_recovered_root" in str(sc.get("notes", ""))


def test_mixed_relative_and_basename(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    (oracle / "src").mkdir(parents=True)
    (oracle / "src" / "a.js").write_text("a", encoding="utf-8")
    (oracle / "b.js").write_text("b", encoding="utf-8")
    root = tmp_path / "rec"
    (root / "src").mkdir(parents=True)
    (root / "src" / "a.js").write_text("x", encoding="utf-8")
    loose = tmp_path / "loose"
    loose.mkdir()
    (loose / "b.js").write_text("y", encoding="utf-8")
    sc = compute_js_project_file_scorecard(
        oracle, [root / "src" / "a.js", loose / "b.js"], recovered_root=root
    )
    assert sc["matched_oracle_file_count"] == 2
    assert sc["match_mode"] == "relative_path"


def test_perfect_basename_match(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    oracle.mkdir()
    (oracle / "a.js").write_text("a", encoding="utf-8")
    (oracle / "b.js").write_text("b", encoding="utf-8")
    recovered = [tmp_path / "out" / "a.js", tmp_path / "out" / "b.js"]
    for path in recovered:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x", encoding="utf-8")
    sc = compute_js_project_file_scorecard(oracle, recovered)
    assert sc["project_file_recall"] == 1.0
    assert sc["project_file_precision"] == 1.0
    assert sc["matched_oracle_file_count"] == 2
    assert sc["overall_score"] == 1.0
    assert sc["token_signal_mode"] == "filename_set_basename_jaccard_all"
    assert sc["reconstruction_mode"] == "filename_set"


def test_empty_oracle_returns_zeros(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    oracle.mkdir()
    sc = compute_js_project_file_scorecard(oracle, [])
    assert sc["project_file_recall"] == 0.0
    assert sc["overall_score"] == 0.0
    assert sc["token_signal_score"] == 0.0
    assert "empty_oracle" in str(sc.get("notes", ""))


def test_basename_collision_is_one_to_one(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    (oracle / "dir1").mkdir(parents=True)
    (oracle / "dir1" / "dup.js").write_text("1", encoding="utf-8")
    (oracle / "dir2").mkdir(parents=True)
    (oracle / "dir2" / "dup.js").write_text("2", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    recovered = [out / "dup.js"]
    recovered[0].write_text("x", encoding="utf-8")
    sc = compute_js_project_file_scorecard(oracle, recovered)
    assert sc["matched_oracle_file_count"] == 1
    assert sc["oracle_file_count"] == 2
    assert "basename_collision" in str(sc.get("notes", ""))


def test_partial_match_recall_precision(tmp_path: Path) -> None:
    oracle = tmp_path / "oracle"
    oracle.mkdir()
    (oracle / "a.js").write_text("a", encoding="utf-8")
    (oracle / "b.js").write_text("b", encoding="utf-8")
    out = tmp_path / "out"
    out.mkdir()
    (out / "a.js").write_text("x", encoding="utf-8")
    (out / "c.js").write_text("y", encoding="utf-8")
    sc = compute_js_project_file_scorecard(oracle, [out / "a.js", out / "c.js"])
    assert sc["project_file_recall"] == 0.5
    assert sc["project_file_precision"] == 0.5
