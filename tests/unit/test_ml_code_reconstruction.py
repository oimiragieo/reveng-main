"""Unit tests for the current ML code reconstruction and recompilation APIs."""

import json
from pathlib import Path

import pytest

from reveng.ai.recompilation_engine import BinaryRecompilationEngine
from reveng.ml.code_reconstruction import (
    CodeFragment,
    MLCodeReconstruction,
    ModelType,
    ReconstructionTask,
)


@pytest.fixture
def reconstructor(monkeypatch: pytest.MonkeyPatch) -> MLCodeReconstruction:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    return MLCodeReconstruction()


def test_ml_code_reconstruction_loads_current_local_models(
    reconstructor: MLCodeReconstruction,
):
    assert set(reconstructor.models) == {
        ModelType.CODEBERT,
        ModelType.CODET5,
        ModelType.CODEGEN,
        ModelType.LOCAL_LLM,
    }
    assert reconstructor.model_configs[ModelType.CODEBERT]["model_name"] == (
        "microsoft/codebert-base"
    )
    assert ReconstructionTask.FUNCTION_RECONSTRUCTION.value == "function_reconstruction"


def test_reconstruct_code_returns_structured_result_for_function_task(
    reconstructor: MLCodeReconstruction,
):
    fragment = CodeFragment(
        address=0x401000,
        size=4,
        assembly_code="mov eax, 1\nret",
        hex_data=b"\xb8\x01\x00\x00",
    )

    result = reconstructor.reconstruct_code(
        fragment,
        ReconstructionTask.FUNCTION_RECONSTRUCTION,
        ModelType.CODEBERT,
    )

    assert result.task == ReconstructionTask.FUNCTION_RECONSTRUCTION
    assert result.input_fragment is fragment
    assert result.model_used == ModelType.CODEBERT
    assert result.processing_time >= 0.0
    assert "reconstructed_function" in result.reconstructed_code
    assert result.metadata["model_config"]["model_name"] == "microsoft/codebert-base"
    assert 0.0 < result.confidence <= 1.0


def test_select_best_model_prefers_current_available_fallbacks(
    reconstructor: MLCodeReconstruction,
):
    assert (
        reconstructor._select_best_model(ReconstructionTask.THREAT_INTELLIGENCE)
        == ModelType.CODEBERT
    )
    assert (
        reconstructor._select_best_model(ReconstructionTask.DECOMPILATION)
        == ModelType.CODEBERT
    )


def test_generate_threat_intelligence_uses_current_analysis_inputs(
    reconstructor: MLCodeReconstruction,
):
    threats = reconstructor.generate_threat_intelligence(
        {
            "api_analysis": {
                "suspicious_apis": [
                    {
                        "api": "CreateRemoteThread",
                        "category": "process_injection",
                    }
                ]
            },
            "network_connections": [
                {"foreign_address": "198.51.100.9:443"},
            ],
            "file_operations": [
                {"operation": "WriteFile"},
            ],
        }
    )

    threat_types = {threat.threat_type for threat in threats}

    assert threat_types == {
        "Process Injection",
        "Network Communication",
        "File System Manipulation",
    }
    process_injection = next(
        threat for threat in threats if threat.threat_type == "Process Injection"
    )
    assert process_injection.severity == "HIGH"
    assert process_injection.indicators == ["CreateRemoteThread"]
    assert "T1055" in process_injection.references[0]


def test_save_reconstruction_and_threat_results_write_current_json_shapes(
    reconstructor: MLCodeReconstruction,
    tmp_path: Path,
):
    fragment = CodeFragment(
        address=0x401000,
        size=4,
        assembly_code="call eax",
        hex_data=b"\xff\xd0",
        context={"function_name": "entry"},
    )
    reconstruction = reconstructor.reconstruct_code(
        fragment,
        ReconstructionTask.DECOMPILATION,
        ModelType.CODEBERT,
    )
    threats = reconstructor.generate_threat_intelligence(
        {
            "api_analysis": {
                "suspicious_apis": [
                    {"api": "CreateRemoteThread", "category": "process_injection"}
                ]
            }
        }
    )

    reconstruction_path = tmp_path / "reconstruction.json"
    threats_path = tmp_path / "threats.json"

    assert reconstructor.save_reconstruction_results([reconstruction], str(reconstruction_path))
    assert reconstructor.save_threat_intelligence(threats, str(threats_path))

    reconstruction_payload = json.loads(reconstruction_path.read_text(encoding="utf-8"))
    threats_payload = json.loads(threats_path.read_text(encoding="utf-8"))

    assert reconstruction_payload["summary"]["total_results"] == 1
    assert reconstruction_payload["reconstruction_results"][0]["task"] == "decompilation"
    assert reconstruction_payload["reconstruction_results"][0]["address"] == hex(
        fragment.address
    )
    assert threats_payload["summary"]["total_threats"] == 1
    assert threats_payload["threat_intelligence"][0]["threat_type"] == "Process Injection"


def test_binary_recompilation_engine_feedback_prompt_includes_cfg_context_and_history(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
        max_compilation_retries=3,
    )

    prompt = engine._create_compilation_feedback_prompt(
        "int main(void) { return 0 }",
        "gcc",
        "error: expected ';' before '}' token",
        2,
        [
            {
                "attempt": 1,
                "stderr": "error: missing semicolon before closing brace",
            },
            {
                "attempt": 2,
                "stderr": "error: expected ';' before '}' token",
            },
        ],
        {
            "imports": ["printf"],
            "strings": ["hello world"],
            "cfg_context_text": "Function main has one basic block and no outgoing calls.",
        },
    )

    assert "Compiler: gcc" in prompt
    assert "Retry attempt: 2 of 3" in prompt
    assert "error: expected ';' before '}' token" in prompt
    assert "Previous failed attempts" in prompt
    assert "error: missing semicolon before closing brace" in prompt
    assert "Imported functions: printf" in prompt
    assert "Observed strings: hello world" in prompt
    assert "Function main has one basic block and no outgoing calls." in prompt
