"""Guards for deferred tg-audit items (honesty, not capability)."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_fuzz_until_divergence_not_implemented():
    from reveng.verification.differential.oracle import DifferentialOracle

    oracle = DifferentialOracle.__new__(DifferentialOracle)
    with pytest.raises(NotImplementedError):
        oracle.fuzz_until_divergence([])


def test_deferred_ids_documented():
    receipt = Path("docs/architecture/tg-audit-fixups-2026-08-08.md")
    plan = Path("docs/superpowers/plans/2026-08-08-reveng-tg-audit-fixups.md")
    text = (receipt.read_text(encoding="utf-8") if receipt.exists() else "") + plan.read_text(
        encoding="utf-8"
    )
    for item in ("D1", "D2", "D3", "D4", "D5", "D6"):
        assert item in text


def test_enterprise_no_silent_f841_knobs():
    src = Path("src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py").read_text(
        encoding="utf-8"
    )
    assert "# noqa: F841" not in src or (
        "_quick_mode = args.get" not in src and "_enable_ai = args.get" not in src
    )
    assert "_quick_mode = args.get" not in src
    assert '_use_ai = args.get("use_ai_enhancement", True)  # noqa: F841' not in src
