"""Framework probe-flag forwarding tests."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from reveng.app_reverse_engineering.framework import AppReverseEngineeringFramework
from reveng.app_reverse_engineering.models import AppReverseEngineeringResult


class _StubJSAdapter:
    language = "javascript"
    adapter_name = "stub_js"
    supported_extensions = (".js",)

    def supports_path(self, path: Path) -> bool:
        return path.suffix.lower() == ".js"

    async def reverse_engineer(self, input_path, output_dir, **kwargs):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        analysis = out / "analysis.json"
        analysis.write_text("{}", encoding="utf-8")
        return AppReverseEngineeringResult(
            language=self.language,
            adapter_name=self.adapter_name,
            input_path=Path(input_path),
            input_root=Path(input_path).parent,
            output_dir=out,
            specs_dir=out / "specs",
            domains_dir=out / "domains",
            artifacts_dir=out / "artifacts",
            analysis_file=analysis,
            topic_files={},
            domain_files={},
            warnings=[],
            metadata={},
            primary_artifacts={},
            source_count=1,
            source_language="javascript",
        )


@pytest.mark.asyncio
async def test_framework_forwards_probe_flags(monkeypatch, tmp_path):
    captured = {}

    def _fake_enrich(payload, **kwargs):
        captured.update(kwargs)
        enriched = dict(payload)
        enriched.update(
            {
                "schema_version": "1.0",
                "result_type": "app_reverse_engineering_result",
                "validation": {"grade": "D", "summary": "stub"},
                "evidence": [],
                "provenance": {},
                "capability_report": {"schema_version": "1.0", "dimensions": {}},
            }
        )
        return enriched

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.framework.enrich_app_analysis_payload",
        _fake_enrich,
    )
    monkeypatch.setattr(
        "reveng.app_reverse_engineering.framework.rewrite_analysis_file",
        lambda *a, **k: None,
    )

    fw = AppReverseEngineeringFramework()
    fw.register(_StubJSAdapter())
    inp = tmp_path / "x.js"
    inp.write_text("1", encoding="utf-8")
    await fw.reverse_engineer(
        str(inp),
        str(tmp_path / "out"),
        language="javascript",
        run_js_syntax_check=False,
        run_js_behavior_probe=False,
        run_js_npm_lifecycle_probe=True,
    )
    assert captured["run_js_syntax_check"] is False
    assert captured["run_js_behavior_probe"] is False
    assert captured["run_js_npm_lifecycle_probe"] is True


@pytest.mark.asyncio
async def test_framework_probe_defaults(monkeypatch, tmp_path):
    captured = {}

    def _fake_enrich(payload, **kwargs):
        captured.update(kwargs)
        enriched = dict(payload)
        enriched.update(
            {
                "schema_version": "1.0",
                "result_type": "app_reverse_engineering_result",
                "validation": {"grade": "D", "summary": "stub"},
                "evidence": [],
                "provenance": {},
                "capability_report": {"schema_version": "1.0", "dimensions": {}},
            }
        )
        return enriched

    monkeypatch.setattr(
        "reveng.app_reverse_engineering.framework.enrich_app_analysis_payload",
        _fake_enrich,
    )
    monkeypatch.setattr(
        "reveng.app_reverse_engineering.framework.rewrite_analysis_file",
        lambda *a, **k: None,
    )
    fw = AppReverseEngineeringFramework()
    fw.register(_StubJSAdapter())
    inp = tmp_path / "x.js"
    inp.write_text("1", encoding="utf-8")
    await fw.reverse_engineer(str(inp), str(tmp_path / "out"), language="javascript")
    assert captured["run_js_syntax_check"] is True
    assert captured["run_js_behavior_probe"] is True
    assert captured["run_js_npm_lifecycle_probe"] is False
