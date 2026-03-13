"""Tests for angr-based CFG preprocessing in the recompilation pipeline."""

import json
from pathlib import Path

import pytest

from reveng.ai.angr_cfg_preprocessor import AngrCFGPreprocessor
from reveng.ai.gemini_engine import GeminiEngine
from reveng.ai.recompilation_engine import BinaryRecompilationEngine


@pytest.fixture
def sample_pe_path() -> Path:
    sample_path = Path("test_samples/sample.exe")
    if not sample_path.exists():
        pytest.skip("PE sample missing from test_samples/sample.exe")
    return sample_path


def test_extract_cfg_payload_from_sample_pe(sample_pe_path: Path):
    preprocessor = AngrCFGPreprocessor()

    payload = preprocessor.extract_cfg_payload(str(sample_pe_path))

    assert payload["status"] == "success"
    assert payload["source"] == "angr"
    assert payload["binary_name"] == sample_pe_path.name
    assert payload["graph_metrics"]["node_count"] > 0
    assert payload["graph_metrics"]["edge_count"] > 0
    assert payload["function_count"] > 0
    assert payload["functions"]

    first_function = payload["functions"][0]
    assert first_function["name"]
    assert first_function["address"].startswith("0x")
    assert first_function["block_count"] == len(first_function["basic_blocks"])
    assert any(function["block_count"] > 0 for function in payload["functions"])

    llm_context = preprocessor.build_llm_context(payload)
    assert "Graph metrics" in llm_context
    assert sample_pe_path.name in llm_context

    json.dumps(payload)


def test_gemini_prompt_includes_cfg_context():
    engine = GeminiEngine(api_key=None)

    prompt = engine._create_reconstruction_prompt(
        "int main(void) { return 0; }",
        "main",
        {
            "imports": ["printf"],
            "strings": ["hello"],
            "cfg_context_text": "Function main has one basic block and no outgoing calls.",
        },
    )

    assert "Control-flow graph (angr summary)" in prompt
    assert "Function main has one basic block and no outgoing calls." in prompt


@pytest.mark.asyncio
async def test_phase1_decompilation_writes_cfg_artifacts(tmp_path: Path):
    class DummyGhidra:
        def analyze_binary(self, binary_path: str):
            return {
                "functions": [{"name": "main", "address": "0x401000"}],
                "decompiled_code": {"0x401000": "int main(void) { return 0; }"},
                "strings": ["hello"],
                "imports": ["printf"],
            }

    class DummyCFGPreprocessor:
        def extract_cfg_payload(self, binary_path: str):
            return {
                "status": "success",
                "source": "angr",
                "binary_name": Path(binary_path).name,
                "graph_metrics": {"node_count": 3, "edge_count": 2},
                "function_count": 1,
                "functions": [
                    {
                        "name": "main",
                        "address": "0x401000",
                        "block_count": 1,
                        "basic_blocks": [
                            {
                                "address": "0x401000",
                                "size": 5,
                                "successors": [],
                                "predecessors": [],
                            }
                        ],
                    }
                ],
            }

        def build_llm_context(self, payload):
            return "Function main contains one basic block."

    output_dir = tmp_path / "analysis"
    output_dir.mkdir()
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"MZ" + b"\x00" * 128)

    engine = BinaryRecompilationEngine(
        ghidra_engine=DummyGhidra(),
        gemini_engine=None,
        work_dir=tmp_path,
        cfg_preprocessor=DummyCFGPreprocessor(),
    )

    ghidra_data = await engine._phase1_decompilation(str(binary_path), output_dir)

    assert ghidra_data["cfg_payload"]["status"] == "success"
    assert ghidra_data["cfg_context_text"] == "Function main contains one basic block."
    assert Path(ghidra_data["cfg_artifacts"]["json"]).exists()
    assert Path(ghidra_data["cfg_artifacts"]["text"]).exists()
    assert (
        Path(ghidra_data["cfg_artifacts"]["text"]).read_text(encoding="utf-8")
        == "Function main contains one basic block."
    )
