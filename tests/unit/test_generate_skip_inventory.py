from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "scripts" / "generate_skip_inventory.py"


def _load_module(name: str, path: Path):
    assert path.exists(), f"Expected module at {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_generate_skip_inventory_categorizes_skip_patterns(tmp_path: Path):
    runner = _load_module("test_generate_skip_inventory", RUNNER_PATH)
    tests_root = tmp_path / "tests"
    tests_root.mkdir()

    sample = tests_root / "test_sample.py"
    sample.write_text(
        "\n".join(
            [
                "import pytest",
                "",
                "@pytest.mark.skip(reason='Not implemented yet')",
                "def test_static_skip():",
                "    pass",
                "",
                "@pytest.mark.skipif(True, reason='requires ilspycmd')",
                "def test_skipif():",
                "    pass",
                "",
                "def test_runtime_skip():",
                "    pytest.skip('Ghidra service unavailable')",
            ]
        ),
        encoding="utf-8",
    )

    report = runner.build_skip_inventory_report(tests_root=tests_root)

    assert report["summary"]["total_skip_sites"] == 3
    assert report["summary"]["by_kind"]["skip"] == 1
    assert report["summary"]["by_kind"]["skipif"] == 1
    assert report["summary"]["by_kind"]["runtime_skip"] == 1
    assert report["summary"]["by_category"]["known_gap"] == 1
    assert report["summary"]["by_category"]["external_tooling"] == 2


def test_generate_skip_inventory_main_writes_json_and_markdown(tmp_path: Path):
    runner = _load_module("test_generate_skip_inventory_main", RUNNER_PATH)
    tests_root = tmp_path / "tests"
    tests_root.mkdir()
    (tests_root / "test_sample.py").write_text(
        "import pytest\n\n"
        "@pytest.mark.skip(reason='No sample fixture found')\n"
        "def test_example():\n    pass\n",
        encoding="utf-8",
    )
    json_output = tmp_path / "skip_inventory.json"
    markdown_output = tmp_path / "skip_inventory.md"

    exit_code = runner.main(
        [
            "--tests-root",
            str(tests_root),
            "--json-output",
            str(json_output),
            "--markdown-output",
            str(markdown_output),
        ]
    )

    assert exit_code == 0
    written = json.loads(json_output.read_text(encoding="utf-8"))
    assert written["result_type"] == "skip_inventory_report"
    assert written["summary"]["total_skip_sites"] == 1
    assert "REVENG Skip-Lane Inventory" in markdown_output.read_text(encoding="utf-8")


def test_generate_skip_inventory_can_exclude_internal_report_tests(tmp_path: Path):
    runner = _load_module("test_generate_skip_inventory_excludes_internal_tests", RUNNER_PATH)
    repo_root = tmp_path
    tests_root = repo_root / "tests" / "unit"
    tests_root.mkdir(parents=True)
    (tests_root / "test_generate_skip_inventory.py").write_text(
        "@pytest.mark.skip(reason='Not implemented yet')\n",
        encoding="utf-8",
    )
    (tests_root / "test_real.py").write_text(
        "import pytest\n\ndef test_real():\n    pytest.skip('Java not available (optional)')\n",
        encoding="utf-8",
    )

    report = runner.build_skip_inventory_report(
        tests_root=repo_root / "tests",
        repo_root=repo_root,
        excluded_relative_paths={"tests/unit/test_generate_skip_inventory.py"},
    )

    assert report["summary"]["total_skip_sites"] == 1
    assert report["entries"][0]["path"] == "tests\\unit\\test_real.py"
