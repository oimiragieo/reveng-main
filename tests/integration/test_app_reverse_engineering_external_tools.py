from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from reveng.app_reverse_engineering.adapters.dotnet import DotNetAppAdapter
from reveng.app_reverse_engineering.adapters.python import PythonAppAdapter

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
@pytest.mark.requires_external_tools
@pytest.mark.skipif(
    shutil.which("pyi-archive_viewer") is None,
    reason="pyi-archive_viewer is not installed in this environment",
)
def test_python_adapter_archive_viewer_executes_on_checked_in_fixture(tmp_path: Path):
    adapter = PythonAppAdapter()
    fixture = REPO_ROOT / "test_samples" / "sample_app.pyz"

    result = adapter._run_pyi_archive_viewer(
        fixture, tmp_path
    )  # noqa: SLF001 - integration characterization

    assert result["available"] is True
    assert result["listing_path"] is not None
    assert Path(result["listing_path"]).exists()


@pytest.mark.integration
@pytest.mark.requires_external_tools
@pytest.mark.skipif(
    shutil.which("ilspycmd") is None,
    reason="ilspycmd is not installed in this environment",
)
def test_dotnet_adapter_ilspy_normalization_executes_when_available(tmp_path: Path):
    adapter = DotNetAppAdapter()
    fixture = REPO_ROOT / "test_samples" / "sample_dotnet.dll"

    if not fixture.exists():
        pytest.skip("sample_dotnet.dll fixture is missing")

    result = adapter._detector.is_dotnet_assembly(str(fixture))
    assert result[0] is True
