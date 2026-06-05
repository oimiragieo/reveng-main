from __future__ import annotations

import importlib.util
from pathlib import Path

RUNNER_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "run_app_reverse_engineering_corpus.py"
)


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_load_app_corpus_config_resolves_relative_paths(tmp_path: Path):
    runner = _load_module("test_app_corpus_config", RUNNER_PATH)
    config_path = tmp_path / "app_corpus.json"
    sample = tmp_path / "sample.py"
    sample.write_text("print('hello')\n", encoding="utf-8")
    config_path.write_text(
        "{\n"
        '  "version": "1.0",\n'
        '  "entries": [\n'
        '    {"name": "sample", "input_path": "sample.py", "language": "python"}\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )

    config = runner.load_app_corpus_config(config_path)

    entry = config["entries"][0]
    assert Path(entry["input_path"]).is_absolute()
    assert entry["language"] == "python"
    assert entry["required"] is True


def test_build_report_runs_selected_entries_only(tmp_path: Path):
    runner = _load_module("test_app_corpus_build", RUNNER_PATH)
    config_path = tmp_path / "app_corpus.json"
    sample_a = tmp_path / "sample_a.py"
    sample_b = tmp_path / "sample_b.py"
    sample_a.write_text("print('a')\n", encoding="utf-8")
    sample_b.write_text("print('b')\n", encoding="utf-8")
    config_path.write_text(
        "{\n"
        '  "version": "1.0",\n'
        '  "entries": [\n'
        '    {"name": "sample-a", "input_path": "sample_a.py", "language": "python"},\n'
        '    {"name": "sample-b", "input_path": "sample_b.py", "language": "python"}\n'
        "  ]\n"
        "}\n",
        encoding="utf-8",
    )

    report = runner.build_report(
        config_path,
        selected_names=["sample-a"],
        output_dir=tmp_path / "corpus_out",
    )

    assert report["selected_entry_count"] == 1
    assert len(report["rows"]) == 1
    assert report["rows"][0]["name"] == "sample-a"


def test_checked_in_corpus_config_can_run_dotnet_entry():
    runner = _load_module("test_app_corpus_checked_in", RUNNER_PATH)
    config_path = (
        Path(__file__).resolve().parents[2] / ".reveng" / "app_reverse_engineering_corpus.json"
    )

    report = runner.build_report(
        config_path,
        selected_names=["dotnet-sample-app"],
        output_dir=Path(__file__).resolve().parents[2]
        / "reports"
        / "app_reverse_engineering_corpus_test",
    )

    assert report["selected_entry_count"] == 1
    assert report["summary"]["matrix_status"] == "pass"
    assert report["rows"][0]["name"] == "dotnet-sample-app"
    assert report["rows"][0]["language"] == "dotnet"


def test_checked_in_corpus_config_can_run_packaged_entries():
    runner = _load_module("test_app_corpus_packaged", RUNNER_PATH)
    config_path = (
        Path(__file__).resolve().parents[2] / ".reveng" / "app_reverse_engineering_corpus.json"
    )

    report = runner.build_report(
        config_path,
        selected_names=["java-helloworld-jar", "python-sample-zipapp", "python-sample-bytecode"],
        output_dir=Path(__file__).resolve().parents[2]
        / "reports"
        / "app_reverse_engineering_corpus_packaged_test",
    )

    assert report["selected_entry_count"] == 3
    assert report["summary"]["matrix_status"] == "pass"
    assert {row["name"] for row in report["rows"]} == {
        "java-helloworld-jar",
        "python-sample-zipapp",
        "python-sample-bytecode",
    }
