"""Unit tests for the functional code generator."""

from pathlib import Path

import pytest

from reveng.tools.utils.functional_code_generator import FunctionalCodeGenerator


@pytest.fixture()
def sample_disassembly() -> str:
    return "MOV R0, #0\nBX LR"


@pytest.fixture()
def sample_analysis() -> dict:
    return {"purpose": "initialise register", "return_value": "0"}


def test_generator_initialises_without_ai(sample_disassembly, sample_analysis):
    generator = FunctionalCodeGenerator(use_ai=True)
    assert generator is not None
    assert isinstance(generator.use_ai, bool)

    code = generator.generate_functional_code("init_reg", sample_disassembly, sample_analysis)
    assert "init_reg" in code
    assert "TODO" in code or "return" in code


def test_generator_writes_output(tmp_path: Path, sample_disassembly, sample_analysis):
    generator = FunctionalCodeGenerator(use_ai=False)
    output_path = tmp_path / "generated.c"

    generator.generate_functional_code(
        function_name="init_reg",
        disassembly=sample_disassembly,
        analysis=sample_analysis,
        output_path=output_path,
    )

    assert output_path.exists()
    contents = output_path.read_text()
    assert "init_reg" in contents
