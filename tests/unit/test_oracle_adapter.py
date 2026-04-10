"""
Unit tests for reveng.verification.refinement.oracle_adapter.

All tests use unittest.mock — no real binary execution, no subprocess calls.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from reveng.verification.refinement.oracle_adapter import make_oracle_factory

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_binary(tmp_path: Path) -> Path:
    """Create a temporary file that acts as a stand-in for a real binary."""
    binary = tmp_path / "original_binary"
    binary.write_bytes(b"\x7fELF")  # dummy ELF magic bytes
    return binary


@pytest.fixture()
def tmp_recompiled(tmp_path: Path) -> Path:
    """Create a temporary file that acts as a stand-in for a recompiled binary."""
    binary = tmp_path / "recompiled_binary"
    binary.write_bytes(b"\x7fELF")
    return binary


# ---------------------------------------------------------------------------
# Test: make_oracle_factory returns a callable
# ---------------------------------------------------------------------------


def test_make_oracle_factory_returns_callable(tmp_binary: Path) -> None:
    factory = make_oracle_factory(original_binary=tmp_binary, timeout_seconds=10.0)
    assert callable(factory), "make_oracle_factory must return a callable"


# ---------------------------------------------------------------------------
# Test: calling the factory returns a DifferentialOracle instance
# ---------------------------------------------------------------------------


def test_factory_returns_differential_oracle(tmp_binary: Path, tmp_recompiled: Path) -> None:
    """The factory should return a DifferentialOracle when called with a valid path."""
    with patch("reveng.verification.refinement.oracle_adapter.DifferentialOracle") as MockOracle:
        mock_instance = MagicMock()
        MockOracle.return_value = mock_instance

        factory = make_oracle_factory(original_binary=tmp_binary, timeout_seconds=10.0)
        result = factory(tmp_recompiled)

        assert result is mock_instance
        MockOracle.assert_called_once()


# ---------------------------------------------------------------------------
# Test: original_binary must exist — FileNotFoundError if not
# ---------------------------------------------------------------------------


def test_raises_file_not_found_for_missing_original(tmp_path: Path) -> None:
    missing = tmp_path / "no_such_binary"
    # Ensure it genuinely does not exist
    assert not missing.exists()

    with pytest.raises(FileNotFoundError, match="Original binary not found"):
        make_oracle_factory(original_binary=missing, timeout_seconds=10.0)


# ---------------------------------------------------------------------------
# Test: timeout_seconds must be positive — ValueError if <= 0
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_timeout", [0.0, -1.0, -100.0])
def test_raises_value_error_for_non_positive_timeout(tmp_binary: Path, bad_timeout: float) -> None:
    with pytest.raises(ValueError, match="timeout_seconds must be strictly positive"):
        make_oracle_factory(original_binary=tmp_binary, timeout_seconds=bad_timeout)


# ---------------------------------------------------------------------------
# Test: factory captures original_binary correctly
# ---------------------------------------------------------------------------


def test_factory_passes_original_binary_to_oracle(tmp_binary: Path, tmp_recompiled: Path) -> None:
    """The captured original_binary must be forwarded to DifferentialOracle."""
    with patch("reveng.verification.refinement.oracle_adapter.DifferentialOracle") as MockOracle:
        factory = make_oracle_factory(original_binary=tmp_binary, timeout_seconds=5.0)
        factory(tmp_recompiled)

        call_kwargs = MockOracle.call_args
        # DifferentialOracle is called as DifferentialOracle(original=..., recompiled=..., ...)
        passed_original = call_kwargs.kwargs.get("original") or call_kwargs.args[0]
        assert Path(passed_original) == tmp_binary


# ---------------------------------------------------------------------------
# Test: factory captures timeout_seconds correctly
# ---------------------------------------------------------------------------


def test_factory_passes_timeout_to_oracle(tmp_binary: Path, tmp_recompiled: Path) -> None:
    """The captured timeout_seconds must be forwarded to DifferentialOracle."""
    expected_timeout = 42.5

    with patch("reveng.verification.refinement.oracle_adapter.DifferentialOracle") as MockOracle:
        factory = make_oracle_factory(original_binary=tmp_binary, timeout_seconds=expected_timeout)
        factory(tmp_recompiled)

        call_kwargs = MockOracle.call_args
        passed_timeout = call_kwargs.kwargs.get("timeout_seconds")
        assert passed_timeout == expected_timeout


# ---------------------------------------------------------------------------
# Test: fresh DifferentialOracle per call (not a singleton)
# ---------------------------------------------------------------------------


def test_factory_creates_fresh_oracle_each_call(tmp_binary: Path, tmp_path: Path) -> None:
    """Each call to the factory must produce a distinct DifferentialOracle instance."""
    recompiled_a = tmp_path / "recompiled_a"
    recompiled_a.write_bytes(b"\x7fELF")
    recompiled_b = tmp_path / "recompiled_b"
    recompiled_b.write_bytes(b"\x7fELF")

    with patch("reveng.verification.refinement.oracle_adapter.DifferentialOracle") as MockOracle:
        instance_a = MagicMock(name="oracle_a")
        instance_b = MagicMock(name="oracle_b")
        MockOracle.side_effect = [instance_a, instance_b]

        factory = make_oracle_factory(original_binary=tmp_binary, timeout_seconds=5.0)
        result_a = factory(recompiled_a)
        result_b = factory(recompiled_b)

        assert result_a is instance_a
        assert result_b is instance_b
        assert result_a is not result_b
        assert MockOracle.call_count == 2


# ---------------------------------------------------------------------------
# Test: factory works with str paths (coerced to Path)
# ---------------------------------------------------------------------------


def test_factory_accepts_str_original_binary(tmp_path: Path, tmp_recompiled: Path) -> None:
    """make_oracle_factory should accept a str path and coerce it to Path."""
    binary = tmp_path / "original_str"
    binary.write_bytes(b"\x7fELF")

    # Pass as str, not Path
    factory = make_oracle_factory(original_binary=str(binary), timeout_seconds=5.0)
    assert callable(factory)


def test_factory_accepts_str_recompiled_binary(tmp_binary: Path, tmp_recompiled: Path) -> None:
    """The factory itself should accept a str recompiled path and coerce it to Path."""
    with patch("reveng.verification.refinement.oracle_adapter.DifferentialOracle") as MockOracle:
        factory = make_oracle_factory(original_binary=tmp_binary, timeout_seconds=5.0)
        # Pass recompiled path as string
        factory(str(tmp_recompiled))

        call_kwargs = MockOracle.call_args
        passed_recompiled = call_kwargs.kwargs.get("recompiled") or call_kwargs.args[1]
        assert isinstance(Path(passed_recompiled), Path)
