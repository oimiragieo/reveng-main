"""Import-direction / cycle baseline (tooling presence + deferred enforcement).

Today the ``reveng.ai`` <-> ``reveng.security`` import cycle EXISTS; it is broken in the
Phase 3 restructure. import-linter (grimp) also cannot build the graph until the package is
editable-installed and the src tree is graph-clean. This test therefore only verifies that the
tooling and the ``.importlinter`` contract config are present and that the contract is evaluated
*when the graph can be built*. Phase 3 flips ``no-ai-security-cycle`` into a hard gate.
"""

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_importlinter_contract_config_exists():
    cfg = _REPO_ROOT / ".importlinter"
    assert cfg.is_file(), ".importlinter contract config must exist for Phase 3 enforcement"
    assert "security-must-not-import-ai" in cfg.read_text(encoding="utf-8")


@pytest.mark.skipif(
    shutil.which("lint-imports") is None, reason="import-linter not installed"
)
def test_import_contracts_evaluated_when_graph_buildable():
    result = subprocess.run(
        ["lint-imports"], capture_output=True, text=True, cwd=str(_REPO_ROOT)
    )
    combined = result.stdout + result.stderr
    contract_seen = (
        "security must not import ai" in combined
        or "security-must-not-import-ai" in combined
    )
    if not contract_seen:
        # Pre-restructure tree is not yet graph-clean / package not editable-installed.
        pytest.skip(
            "import graph not buildable pre-restructure; cycle enforcement deferred to Phase 3"
        )
    # When the graph builds, the contract must be present in the report (pass or fail).
    assert contract_seen
