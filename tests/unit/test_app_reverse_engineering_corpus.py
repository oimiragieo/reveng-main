"""Tests for app reverse-engineering corpus execution."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering import AppCorpusEntry, run_app_corpus_sync
from reveng.app_reverse_engineering.models import AppReverseEngineeringResult


class _FakeCorpusFramework:
    def __init__(self, results_by_name):
        self._results_by_name = results_by_name

    async def reverse_engineer(self, input_path, output_dir, **kwargs):
        name = Path(input_path).stem
        result = self._results_by_name[name]
        if isinstance(result, Exception):
            raise result
        return result


def _make_result(tmp_path: Path, stem: str, *, language: str, grade: str) -> AppReverseEngineeringResult:
    output_dir = tmp_path / f"{stem}_analysis"
    analysis_file = output_dir / "analysis.json"
    output_dir.mkdir(parents=True, exist_ok=True)
    return AppReverseEngineeringResult(
        language=language,
        adapter_name=f"{language}_adapter",
        input_path=tmp_path / f"{stem}.txt",
        input_root=tmp_path,
        output_dir=output_dir,
        specs_dir=output_dir / "SPECS",
        domains_dir=output_dir / "SPECS" / "domains",
        artifacts_dir=output_dir / "artifacts",
        analysis_file=analysis_file,
        topic_files={},
        domain_files={},
        warnings=[],
        metadata={"schema_version": "1.0", "result_type": "app_reverse_engineering_result"},
        primary_artifacts={},
        source_count=1,
        source_language=language,
        validation_grade=grade,
        validation_summary="summary",
    )


def test_app_corpus_report_preserves_row_metadata(tmp_path: Path):
    sample = tmp_path / "sample.py"
    sample.write_text("def main():\n    return 1\n", encoding="utf-8")
    framework = _FakeCorpusFramework(
        {"sample": _make_result(tmp_path, "sample", language="python", grade="evidence_backed")}
    )

    report = run_app_corpus_sync(
        [AppCorpusEntry(name="sample-row", input_path=str(sample), language="python", tags=["smoke"])],
        str(tmp_path / "corpus_out"),
        framework=framework,
    )

    assert report["schema_version"] == "1.0"
    assert report["result_type"] == "app_reverse_engineering_corpus_report"
    assert report["summary"]["matrix_status"] == "pass"
    row = report["rows"][0]
    assert row["name"] == "sample-row"
    assert row["requested_language"] == "python"
    assert row["validation_grade"] == "evidence_backed"
    assert row["tags"] == ["smoke"]


def test_app_corpus_required_failure_flips_matrix_status(tmp_path: Path):
    required_sample = tmp_path / "required.py"
    required_sample.write_text("print('required')\n", encoding="utf-8")
    optional_sample = tmp_path / "optional.py"
    optional_sample.write_text("print('optional')\n", encoding="utf-8")
    framework = _FakeCorpusFramework(
        {
            "required": RuntimeError("required failure"),
            "optional": _make_result(tmp_path, "optional", language="python", grade="partial_recovery"),
        }
    )

    report = run_app_corpus_sync(
        [
            AppCorpusEntry(name="required-row", input_path=str(required_sample), language="python", required=True),
            AppCorpusEntry(name="optional-row", input_path=str(optional_sample), language="python", required=False),
        ],
        str(tmp_path / "corpus_out"),
        framework=framework,
    )

    assert report["summary"]["failed_entries"] == 1
    assert report["summary"]["required_failed_entries"] == 1
    assert report["summary"]["matrix_status"] == "fail"
    failed_row = next(row for row in report["rows"] if row["name"] == "required-row")
    assert failed_row["status"] == "failed"
    assert "required failure" in failed_row["error"]
