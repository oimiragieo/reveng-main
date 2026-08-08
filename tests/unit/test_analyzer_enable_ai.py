"""Tests for REVENGAnalyzer enable_ai whole-contract."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_enable_ai_false_skips_preflight_and_ai_steps(tmp_path, monkeypatch):
    sample = tmp_path / "bin.bin"
    sample.write_bytes(b"\x00" * 16)

    constructed = {"converter": 0, "inspector": 0, "preflight": 0}

    class BoomConverter:
        def __init__(self, *a, **k):
            constructed["converter"] += 1

        def run_ai_analysis(self):
            return "ok"

    class BoomInspector:
        def __init__(self, *a, **k):
            constructed["inspector"] += 1

        def analyze_binary(self, *a, **k):
            return "ok"

    class BoomPreflight:
        def __init__(self, *a, **k):
            constructed["preflight"] += 1

    monkeypatch.setattr(
        "reveng.tools.core.ai_recompiler_converter.AIRecompilerConverter",
        BoomConverter,
        raising=False,
    )
    # Patch at import sites used by analyzer methods
    import reveng.analysis.analyzer as analyzer_mod

    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_validate_environment", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_detect_file_type", lambda self: None)
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer,
        "_check_ollama_availability",
        lambda self: constructed.__setitem__("preflight", constructed["preflight"] + 1),
    )
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer,
        "_step2_disassembly",
        lambda self: self.results.__setitem__("step2", {"status": "ok"}),
    )
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step4_specifications", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step5_human_readable", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step6_deobfuscation", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step7_implementation", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step8_validation", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_generate_final_report", lambda self: None)
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer, "_calculate_pipeline_status", lambda self: "ok"
    )
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer,
        "_count_step_statuses",
        lambda self: (0, 0, 0),
    )
    for step in (
        "_step9_corporate_exposure",
        "_step10_vulnerability_discovery",
        "_step11_threat_intelligence",
        "_step12_enhanced_reconstruction",
        "_step13_demonstration_generation",
    ):
        monkeypatch.setattr(
            analyzer_mod.REVENGAnalyzer,
            step,
            lambda self, _s=step: (_ for _ in ()).throw(AssertionError(f"{_s} should not run")),
        )

    # Ensure AI step helpers would construct converters if called
    def fake_step1(self):
        from reveng.tools.core.ai_recompiler_converter import AIRecompilerConverter

        AIRecompilerConverter(self.binary_path)

    def fake_step3(self):
        from reveng.tools.core.ai_source_inspector import AISourceInspector

        AISourceInspector()

    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step1_ai_analysis", fake_step1)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step3_ai_inspection", fake_step3)
    monkeypatch.setitem(
        __import__("sys").modules,
        "reveng.tools.core.ai_recompiler_converter",
        type("m", (), {"AIRecompilerConverter": BoomConverter})(),
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "reveng.tools.core.ai_source_inspector",
        type("m", (), {"AISourceInspector": BoomInspector})(),
    )

    analyzer = analyzer_mod.REVENGAnalyzer(
        binary_path=str(sample),
        check_ollama=True,
        enable_ai=False,
        analysis_folder=str(tmp_path / "analysis"),
    )
    assert constructed["preflight"] == 0
    assert analyzer.enhanced_features.is_any_enhanced_enabled() is False
    analyzer.analyze_binary()
    assert analyzer.results["step1"] == {"status": "skipped", "reason": "enable_ai_false"}
    assert analyzer.results["step3"] == {"status": "skipped", "reason": "enable_ai_false"}
    assert constructed["converter"] == 0
    assert constructed["inspector"] == 0


def test_enable_ai_true_attempts_step1(tmp_path, monkeypatch):
    sample = tmp_path / "bin.bin"
    sample.write_bytes(b"\x00" * 16)
    constructed = {"converter": 0}

    class BoomConverter:
        def __init__(self, *a, **k):
            constructed["converter"] += 1

        def run_ai_analysis(self):
            return "ok"

    import reveng.analysis.analyzer as analyzer_mod

    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_validate_environment", lambda self: None)
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_detect_file_type", lambda self: None)
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer, "_check_ollama_availability", lambda self: None
    )
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer,
        "_step2_disassembly",
        lambda self: self.results.__setitem__("step2", {"status": "ok"}),
    )
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step3_ai_inspection", lambda self: None)
    for name in (
        "_step4_specifications",
        "_step5_human_readable",
        "_step6_deobfuscation",
        "_step7_implementation",
        "_step8_validation",
        "_generate_final_report",
    ):
        monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, name, lambda self: None)
    monkeypatch.setattr(
        analyzer_mod.REVENGAnalyzer, "_calculate_pipeline_status", lambda self: "ok"
    )
    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_count_step_statuses", lambda self: (0, 0, 0))

    def fake_step1(self):
        from reveng.tools.core.ai_recompiler_converter import AIRecompilerConverter

        AIRecompilerConverter(self.binary_path)
        self.results["step1"] = {"status": "success"}

    monkeypatch.setattr(analyzer_mod.REVENGAnalyzer, "_step1_ai_analysis", fake_step1)
    monkeypatch.setitem(
        __import__("sys").modules,
        "reveng.tools.core.ai_recompiler_converter",
        type("m", (), {"AIRecompilerConverter": BoomConverter})(),
    )

    analyzer = analyzer_mod.REVENGAnalyzer(
        binary_path=str(sample),
        check_ollama=False,
        enable_ai=True,
        analysis_folder=str(tmp_path / "analysis_on"),
    )
    analyzer.analyze_binary()
    assert constructed["converter"] == 1
    assert analyzer.results.get("step1", {}).get("status") == "success"
