"""JS adapter oracle_dir / scorecard wiring tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reveng.app_reverse_engineering.adapters.javascript import JavaScriptAppAdapter


def _fake_engine_result(tmp_path: Path):
    out = tmp_path / "out"
    out.mkdir(parents=True, exist_ok=True)
    specs = out / "specs"
    specs.mkdir(exist_ok=True)
    domains = out / "domains"
    domains.mkdir(exist_ok=True)
    artifacts = out / "artifacts"
    artifacts.mkdir(exist_ok=True)
    normalized = artifacts / "bundle.js"
    normalized.write_text("console.log(1)", encoding="utf-8")
    analysis = out / "analysis.json"
    analysis.write_text("{}", encoding="utf-8")
    return SimpleNamespace(
        input_path=tmp_path / "in.js",
        input_root=tmp_path,
        output_dir=out,
        specs_dir=specs,
        domains_dir=domains,
        artifacts_dir=artifacts,
        analysis_file=analysis,
        normalized_bundle=normalized,
        topic_files={},
        domain_files={},
        topic_match_counts={},
        bundler_signals={},
        obfuscation_types=[],
        dependency_candidates=[],
        cli_flags=[],
        slash_commands=[],
        warnings=[],
        deep_deobfuscation_output=None,
    )


@pytest.mark.asyncio
async def test_js_adapter_attaches_scorecard_when_oracle_dir_set(monkeypatch, tmp_path):
    engine_result = _fake_engine_result(tmp_path)
    project = engine_result.output_dir / "project"
    project.mkdir()
    (project / "a.js").write_text("a", encoding="utf-8")

    async def _fake_reverse(self, *args, **kwargs):
        return engine_result

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.adapters.javascript.JavaScriptBundleReverseEngineer.reverse_engineer_bundle",
        _fake_reverse,
    )

    oracle = tmp_path / "oracle"
    oracle.mkdir()
    (oracle / "a.js").write_text("a", encoding="utf-8")

    adapter = JavaScriptAppAdapter()
    result = await adapter.reverse_engineer(
        str(tmp_path / "in.js"),
        str(engine_result.output_dir),
        oracle_dir=str(oracle),
    )
    score = result.metadata.get("benchmark_scorecard") or {}
    assert "overall_score" in score
    assert "token_signal_score" in score
    assert result.primary_artifacts.get("reconstructed_project") == project


@pytest.mark.asyncio
async def test_js_adapter_no_scorecard_without_oracle_dir(monkeypatch, tmp_path):
    engine_result = _fake_engine_result(tmp_path)

    async def _fake_reverse(self, *args, **kwargs):
        return engine_result

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.adapters.javascript.JavaScriptBundleReverseEngineer.reverse_engineer_bundle",
        _fake_reverse,
    )
    adapter = JavaScriptAppAdapter()
    result = await adapter.reverse_engineer(
        str(tmp_path / "in.js"),
        str(engine_result.output_dir),
    )
    assert "benchmark_scorecard" not in result.metadata


@pytest.mark.asyncio
async def test_js_adapter_unsupported_ralph_knob_warning(monkeypatch, tmp_path):
    engine_result = _fake_engine_result(tmp_path)

    async def _fake_reverse(self, *args, **kwargs):
        return engine_result

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.adapters.javascript.JavaScriptBundleReverseEngineer.reverse_engineer_bundle",
        _fake_reverse,
    )
    adapter = JavaScriptAppAdapter()
    result = await adapter.reverse_engineer(
        str(tmp_path / "in.js"),
        str(engine_result.output_dir),
        run_webcrack=True,
    )
    assert any("unsupported_ralph_knob:run_webcrack" in w for w in result.warnings)
    assert result.metadata["ralph_knobs"]["run_webcrack"] == "unsupported"


@pytest.mark.asyncio
async def test_js_adapter_oracle_file_is_invalid(monkeypatch, tmp_path):
    engine_result = _fake_engine_result(tmp_path)

    async def _fake_reverse(self, *args, **kwargs):
        return engine_result

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.adapters.javascript.JavaScriptBundleReverseEngineer.reverse_engineer_bundle",
        _fake_reverse,
    )
    oracle_file = tmp_path / "not_a_dir.js"
    oracle_file.write_text("x", encoding="utf-8")
    adapter = JavaScriptAppAdapter()
    result = await adapter.reverse_engineer(
        str(tmp_path / "in.js"),
        str(engine_result.output_dir),
        oracle_dir=str(oracle_file),
    )
    assert "oracle_dir_invalid" in result.warnings
    assert "benchmark_scorecard" not in result.metadata


@pytest.mark.asyncio
async def test_js_adapter_missing_oracle_warns(monkeypatch, tmp_path):
    engine_result = _fake_engine_result(tmp_path)

    async def _fake_reverse(self, *args, **kwargs):
        return engine_result

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.adapters.javascript.JavaScriptBundleReverseEngineer.reverse_engineer_bundle",
        _fake_reverse,
    )
    adapter = JavaScriptAppAdapter()
    result = await adapter.reverse_engineer(
        str(tmp_path / "in.js"),
        str(engine_result.output_dir),
        oracle_dir=str(tmp_path / "missing_oracle"),
    )
    assert "oracle_dir_missing" in result.warnings
    assert "benchmark_scorecard" not in result.metadata
