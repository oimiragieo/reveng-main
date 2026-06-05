"""Import-direction / architecture contracts (enforced).

The ``ai`` <-> ``security`` import cycle was broken (shared models moved to
``reveng.core``); ``reveng.core`` is the foundation layer. These boundaries are now
enforced by import-linter contracts in ``.importlinter`` and must stay green.

When the package is not importable as a top-level package in the current environment
(e.g. not editable-installed), the enforcement test skips rather than fail.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_CONFIG = _REPO_ROOT / ".importlinter"


def test_importlinter_contract_config_exists():
    assert _CONFIG.is_file(), ".importlinter contract config must exist"
    text = _CONFIG.read_text(encoding="utf-8")
    assert "security-must-not-import-ai" in text
    assert "core-is-foundation" in text


@pytest.mark.skipif(shutil.which("lint-imports") is None, reason="import-linter not installed")
def test_import_contracts_are_enforced():
    """Run the import-linter contracts; every contract must be KEPT (0 broken)."""
    result = subprocess.run(
        ["lint-imports", "--no-cache"],
        capture_output=True,
        text=True,
        cwd=str(_REPO_ROOT),
    )
    combined = result.stdout + result.stderr
    if "does not exist" in combined or "Could not find" in combined:
        pytest.skip("reveng package not resolvable as top-level here (needs editable install)")
    assert "Contracts:" in combined, f"import-linter did not run contracts:\n{combined}"
    assert (
        result.returncode == 0 and "0 broken" in combined
    ), f"import-linter contracts BROKEN:\n{combined}"
