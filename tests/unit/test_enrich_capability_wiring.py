"""enrich_app_analysis_payload wires capability_report into validation."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reveng.app_reverse_engineering.contracts import enrich_app_analysis_payload


def test_enrich_attaches_capability_and_can_promote_grade(tmp_path: Path) -> None:
    recon = tmp_path / "rp"
    recon.mkdir()
    (recon / "package.json").write_text(
        json.dumps({"name": "t", "main": "cli.js"}),
        encoding="utf-8",
    )
    (recon / "cli.js").write_text("exports.x = 1;\n", encoding="utf-8")
    analysis = tmp_path / "analysis.json"
    analysis.write_text("{}", encoding="utf-8")

    def fake_which(name: str):
        return f"/fake/{name}"

    with patch("reveng.app_reverse_engineering.capability_report.which", side_effect=fake_which):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout="Usage: cli\n",
                stderr="",
            ),
        ):
            enriched = enrich_app_analysis_payload(
                {"topic_match_counts": {"cli": 2}},
                language="javascript",
                adapter_name="js",
                input_path=tmp_path / "in.js",
                input_root=tmp_path,
                output_dir=tmp_path / "out",
                analysis_file=analysis,
                topic_files={},
                domain_files={},
                primary_artifacts={"reconstructed_project": recon},
                source_count=2,
                warnings=[],
                run_js_syntax_check=True,
                run_js_behavior_probe=True,
            )

    assert "capability_report" in enriched
    assert enriched["validation"]["grade"] == "evidence_backed"
    assert enriched["validation"]["grade_promotion"]["reason"] == "behavior_tier_2+syntax_ok"
