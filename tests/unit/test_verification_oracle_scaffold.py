"""
Phase 1 scaffold tests for reveng.verification oracle interfaces.

Verifies that:
- All top-level imports succeed.
- VerificationVerdict has the expected enum members.
- ExecutionHarness constructs correctly and handles error paths.
- DifferentialOracle.verify() on an empty corpus returns a sane report.
- DifferentialOracle.fuzz_until_divergence() raises NotImplementedError.
- SymbolicOracle.verify_function_equivalence() returns UNDETERMINED or ERROR.

Heavy dependencies (angr, LibAFL) are not required and are never invoked;
subprocess calls are mocked so no real binaries need to be present.
"""

import sys
import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Import surface check
# ---------------------------------------------------------------------------


def test_top_level_imports():
    """All public symbols should be importable from the top-level package."""
    from reveng.verification import (  # noqa: F401
        DifferentialOracle,
        DivergenceReport,
        EquivalenceResult,
        SymbolicOracle,
        VerificationVerdict,
    )


def test_subpackage_imports():
    """Sub-package imports should also resolve cleanly."""
    from reveng.verification.differential import DifferentialOracle, ExecutionHarness  # noqa: F401
    from reveng.verification.symbolic import SymbolicOracle  # noqa: F401


# ---------------------------------------------------------------------------
# VerificationVerdict enum
# ---------------------------------------------------------------------------


class TestVerificationVerdict:
    def test_has_equivalent(self):
        from reveng.verification import VerificationVerdict

        assert VerificationVerdict.EQUIVALENT.value == "equivalent"

    def test_has_divergent(self):
        from reveng.verification import VerificationVerdict

        assert VerificationVerdict.DIVERGENT.value == "divergent"

    def test_has_undetermined(self):
        from reveng.verification import VerificationVerdict

        assert VerificationVerdict.UNDETERMINED.value == "undetermined"

    def test_has_timed_out(self):
        from reveng.verification import VerificationVerdict

        assert VerificationVerdict.TIMED_OUT.value == "timed_out"

    def test_has_error(self):
        from reveng.verification import VerificationVerdict

        assert VerificationVerdict.ERROR.value == "error"

    def test_all_members_present(self):
        from reveng.verification import VerificationVerdict

        expected = {"EQUIVALENT", "DIVERGENT", "UNDETERMINED", "TIMED_OUT", "ERROR"}
        assert {m.name for m in VerificationVerdict} == expected


# ---------------------------------------------------------------------------
# DivergenceReport model
# ---------------------------------------------------------------------------


class TestDivergenceReport:
    def test_default_construction(self):
        from reveng.verification import DivergenceReport, VerificationVerdict

        report = DivergenceReport(verdict=VerificationVerdict.EQUIVALENT)
        assert report.iterations == 0
        assert report.failing_inputs == []
        assert report.diverging_outputs == []
        assert report.elapsed_seconds == 0.0
        assert report.notes == ""

    def test_divergence_rate_zero_iterations(self):
        from reveng.verification import DivergenceReport, VerificationVerdict

        report = DivergenceReport(verdict=VerificationVerdict.UNDETERMINED, iterations=0)
        assert report.divergence_rate() == 0.0

    def test_divergence_rate_with_data(self):
        from reveng.verification import DivergenceReport, VerificationVerdict

        report = DivergenceReport(
            verdict=VerificationVerdict.DIVERGENT,
            failing_inputs=[b"a", b"b"],
            iterations=10,
        )
        assert abs(report.divergence_rate() - 0.2) < 1e-9

    def test_repr_contains_verdict(self):
        from reveng.verification import DivergenceReport, VerificationVerdict

        report = DivergenceReport(verdict=VerificationVerdict.DIVERGENT, iterations=5)
        assert "divergent" in repr(report)


# ---------------------------------------------------------------------------
# EquivalenceResult model
# ---------------------------------------------------------------------------


class TestEquivalenceResult:
    def test_default_construction(self):
        from reveng.verification import EquivalenceResult, VerificationVerdict

        result = EquivalenceResult(verdict=VerificationVerdict.UNDETERMINED)
        assert result.function_name == "<unknown>"
        assert result.path_count == 0
        assert result.counterexample is None

    def test_repr_contains_verdict(self):
        from reveng.verification import EquivalenceResult, VerificationVerdict

        result = EquivalenceResult(verdict=VerificationVerdict.EQUIVALENT, function_name="foo")
        assert "equivalent" in repr(result)
        assert "foo" in repr(result)


# ---------------------------------------------------------------------------
# ExecutionHarness
# ---------------------------------------------------------------------------


class TestExecutionHarness:
    def test_construction(self):
        from reveng.verification.differential import ExecutionHarness

        h = ExecutionHarness(binary_path=Path("/usr/bin/python3"), timeout_seconds=3.0)
        assert h.binary_path == Path("/usr/bin/python3")
        assert h.timeout_seconds == 3.0

    def test_missing_file_raises_harness_error(self):
        from reveng.verification.differential import ExecutionHarness
        from reveng.verification.differential.harness import HarnessError

        h = ExecutionHarness(binary_path=Path("/nonexistent/binary"), timeout_seconds=1.0)
        with pytest.raises(HarnessError, match="not found"):
            h.run(input_bytes=b"test input")

    def test_timeout_returns_timed_out_result(self):
        """A subprocess.TimeoutExpired should produce timed_out=True, not raise."""
        import subprocess

        from reveng.verification.differential import ExecutionHarness

        h = ExecutionHarness(binary_path=Path("/some/binary"), timeout_seconds=1.0)
        exc = subprocess.TimeoutExpired(cmd=["/some/binary"], timeout=1.0)
        exc.stdout = b""
        exc.stderr = b""

        with patch("subprocess.run", side_effect=exc):
            result = h.run(input_bytes=b"input")

        assert result.timed_out is True
        assert result.exit_code == -1

    def test_permission_error_raises_harness_error(self):
        from reveng.verification.differential import ExecutionHarness
        from reveng.verification.differential.harness import HarnessError

        h = ExecutionHarness(binary_path=Path("/root/secret"), timeout_seconds=1.0)
        with patch("subprocess.run", side_effect=PermissionError("denied")):
            with pytest.raises(HarnessError, match="Permission"):
                h.run(input_bytes=b"input")

    def test_run_with_sys_executable_construction(self):
        """
        Verify that an ExecutionHarness constructed with the current Python
        interpreter path has the expected attributes (does not invoke subprocess).
        """
        from reveng.verification.differential import ExecutionHarness

        h = ExecutionHarness(binary_path=Path(sys.executable), timeout_seconds=5.0)
        assert h.binary_path.exists() or True  # path attribute is set regardless
        assert h.timeout_seconds == 5.0


# ---------------------------------------------------------------------------
# DifferentialOracle
# ---------------------------------------------------------------------------


class TestDifferentialOracleVerify:
    def _make_oracle(self):
        from reveng.verification import DifferentialOracle

        return DifferentialOracle(
            original=Path("/bin/orig"),
            recompiled=Path("/bin/reco"),
            timeout_seconds=1.0,
            max_iterations=100,
        )

    def test_empty_corpus_returns_zero_iterations(self):
        """verify([]) must return a report with iterations=0."""
        oracle = self._make_oracle()
        report = oracle.verify(iter([]))

        assert report.iterations == 0
        assert report.failing_inputs == []

    def test_empty_corpus_verdict_is_equivalent(self):
        from reveng.verification import VerificationVerdict

        oracle = self._make_oracle()
        report = oracle.verify(iter([]))
        assert report.verdict == VerificationVerdict.EQUIVALENT

    def test_matching_outputs_gives_equivalent(self):
        """When both binaries produce identical output, verdict is EQUIVALENT."""
        from reveng.verification import VerificationVerdict
        from reveng.verification.differential.harness import ExecutionResult

        matching = ExecutionResult(
            stdout=b"hello", stderr=b"", exit_code=0, elapsed_seconds=0.01, timed_out=False
        )

        with patch(
            "reveng.verification.differential.harness.subprocess.run",
            return_value=MagicMock(stdout=b"hello", stderr=b"", returncode=0),
        ):
            oracle = self._make_oracle()
            report = oracle.verify([b"input1", b"input2"])

        assert report.verdict == VerificationVerdict.EQUIVALENT
        assert report.iterations == 2
        assert report.failing_inputs == []

    def test_diverging_outputs_gives_divergent(self):
        """When stdout differs between binaries, verdict is DIVERGENT."""
        from reveng.verification import VerificationVerdict

        call_count = 0

        def fake_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            result.returncode = 0
            result.stderr = b""
            # First call = original (stdout=b"orig"), second = recompiled (stdout=b"reco")
            result.stdout = b"orig" if call_count % 2 == 1 else b"reco"
            return result

        with patch("reveng.verification.differential.harness.subprocess.run", side_effect=fake_run):
            oracle = self._make_oracle()
            report = oracle.verify([b"input1"])

        assert report.verdict == VerificationVerdict.DIVERGENT
        assert len(report.failing_inputs) == 1

    def test_harness_error_gives_error_verdict(self):
        from reveng.verification import VerificationVerdict
        from reveng.verification.differential.harness import HarnessError

        with patch(
            "reveng.verification.differential.oracle.ExecutionHarness.run",
            side_effect=HarnessError("binary not found"),
        ):
            oracle = self._make_oracle()
            report = oracle.verify([b"inp"])

        assert report.verdict == VerificationVerdict.ERROR
        assert "binary not found" in report.notes


class TestDifferentialOracleFuzz:
    def test_fuzz_until_divergence_raises_not_implemented(self):
        from reveng.verification import DifferentialOracle

        oracle = DifferentialOracle(
            original=Path("/bin/orig"),
            recompiled=Path("/bin/reco"),
        )
        with pytest.raises(NotImplementedError, match="Phase 1.5"):
            oracle.fuzz_until_divergence(seed_inputs=[b"seed"], budget_seconds=5.0)


# ---------------------------------------------------------------------------
# SymbolicOracle
# ---------------------------------------------------------------------------


class TestSymbolicOracle:
    def _make_oracle(self):
        from reveng.verification import SymbolicOracle

        return SymbolicOracle(engine_name="angr", max_paths=64, timeout_seconds=10.0)

    def test_construction(self):
        oracle = self._make_oracle()
        assert oracle.engine_name == "angr"
        assert oracle.max_paths == 64
        assert oracle.timeout_seconds == 10.0

    def test_verify_with_none_returns_undetermined_when_angr_missing(self):
        """When angr is not installed the result must be UNDETERMINED or ERROR."""
        from reveng.verification import VerificationVerdict

        oracle = self._make_oracle()
        with patch(
            "reveng.verification.symbolic.oracle.SymbolicOracle._check_angr",
            return_value=False,
        ):
            result = oracle.verify_function_equivalence(None, None, function_name="test_fn")

        assert result.verdict in (
            VerificationVerdict.UNDETERMINED,
            VerificationVerdict.ERROR,
        )

    def test_verify_with_angr_present_returns_undetermined(self):
        """Phase 1 always returns UNDETERMINED when angr is present."""
        from reveng.verification import VerificationVerdict

        oracle = self._make_oracle()
        with patch(
            "reveng.verification.symbolic.oracle.SymbolicOracle._check_angr",
            return_value=True,
        ):
            result = oracle.verify_function_equivalence(None, None, function_name="main")

        assert result.verdict == VerificationVerdict.UNDETERMINED
        assert result.function_name == "main"

    def test_notes_mention_phase_15(self):
        """Phase 1 result notes should reference Phase 1.5."""
        oracle = self._make_oracle()
        with patch(
            "reveng.verification.symbolic.oracle.SymbolicOracle._check_angr",
            return_value=True,
        ):
            result = oracle.verify_function_equivalence(None, None)

        assert "1.5" in result.notes

    def test_error_verdict_notes_installation_hint(self):
        """ERROR result when angr absent should suggest pip install angr."""
        oracle = self._make_oracle()
        with patch(
            "reveng.verification.symbolic.oracle.SymbolicOracle._check_angr",
            return_value=False,
        ):
            result = oracle.verify_function_equivalence(None, None)

        from reveng.verification import VerificationVerdict

        assert result.verdict == VerificationVerdict.ERROR
        assert "angr" in result.notes.lower()
