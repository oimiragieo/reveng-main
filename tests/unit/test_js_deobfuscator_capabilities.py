"""JS deobfuscator capability honesty tests."""

from __future__ import annotations

import pytest

from reveng.javascript.deobfuscator import (
    DeobfuscationStage,
    JavaScriptDeobfuscator,
)


@pytest.mark.asyncio
async def test_placeholders_skipped_and_detection_applied(monkeypatch):
    deob = JavaScriptDeobfuscator(use_ml=False, use_llm=False)
    deob.tools_available = {"webcrack": False, "prettier": False, "unuglifyjs": False}

    result = await deob.deobfuscate("var a=1+2; console.log(a);", filename="t.js")
    assert DeobfuscationStage.DETECTION in result.stages_applied
    skipped_stages = {s["stage"] for s in result.stages_skipped}
    assert DeobfuscationStage.CONSTANT_FOLDING.value in skipped_stages
    assert DeobfuscationStage.DEAD_CODE_REMOVAL.value in skipped_stages
    assert DeobfuscationStage.CFG_UNFLATTENING.value in skipped_stages
    assert DeobfuscationStage.CONSTANT_FOLDING not in result.stages_applied
    assert result.capabilities_run == {
        "cfg_unflatten": False,
        "constant_folding": False,
        "dead_code_removal": False,
        "reason": "placeholder",
    }
    assert result.effectiveness_status == "no_substantive_transform"
    assert result.success is False


@pytest.mark.asyncio
async def test_webcrack_nonzero_exit_is_skipped(monkeypatch):
    deob = JavaScriptDeobfuscator(use_ml=False, use_llm=False)
    deob.tools_available = {"webcrack": True, "prettier": False, "unuglifyjs": False}

    async def boom(code):
        return {"status": "error", "code": code, "reason": "webcrack_failed"}

    monkeypatch.setattr(deob, "_run_webcrack", boom)
    result = await deob.deobfuscate("var a=1;", filename="t.js")
    assert DeobfuscationStage.UNPACKING not in result.stages_applied
    assert any(s["reason"] == "webcrack_failed" for s in result.stages_skipped)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "reason",
    ["webcrack_timeout", "webcrack_empty", "webcrack_unchanged"],
)
async def test_webcrack_failure_reasons_skipped(monkeypatch, reason):
    deob = JavaScriptDeobfuscator(use_ml=False, use_llm=False)
    deob.tools_available = {"webcrack": True, "prettier": False, "unuglifyjs": False}

    async def boom(code):
        return {"status": "error", "code": code, "reason": reason}

    monkeypatch.setattr(deob, "_run_webcrack", boom)
    result = await deob.deobfuscate("var a=1;", filename="t.js")
    assert DeobfuscationStage.UNPACKING not in result.stages_applied
    assert any(s["reason"] == reason for s in result.stages_skipped)


@pytest.mark.asyncio
async def test_webcrack_success_applies_unpacking_and_can_succeed(monkeypatch):
    deob = JavaScriptDeobfuscator(use_ml=False, use_llm=False)
    deob.tools_available = {"webcrack": True, "prettier": False, "unuglifyjs": False}

    async def ok(code):
        return {"status": "ok", "code": code + "\n/*unpacked*/", "reason": "ok"}

    monkeypatch.setattr(deob, "_run_webcrack", ok)
    monkeypatch.setattr(deob, "_validate_equivalence", lambda a, b: 0.9)
    result = await deob.deobfuscate("var a=1;", filename="t.js")
    assert DeobfuscationStage.UNPACKING in result.stages_applied
    assert DeobfuscationStage.UNBUNDLING not in result.stages_applied
    assert result.success is True
    assert result.effectiveness_status == "substantive_transform"


@pytest.mark.asyncio
async def test_ml_unchanged_is_skipped(monkeypatch):
    deob = JavaScriptDeobfuscator(use_ml=True, use_llm=False)
    deob.use_ml = True
    deob.tools_available = {"webcrack": False, "prettier": False, "unuglifyjs": True}

    async def unchanged(code):
        return {"status": "error", "code": code, "reason": "ml_rename_unchanged"}

    monkeypatch.setattr(deob, "_rename_variables_ml_outcome", unchanged)
    result = await deob.deobfuscate("var a=1;", filename="t.js")
    assert DeobfuscationStage.ML_RENAMING not in result.stages_applied
    assert any(s["reason"] == "ml_rename_unchanged" for s in result.stages_skipped)
