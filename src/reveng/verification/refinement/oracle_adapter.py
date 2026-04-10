"""
Adapter that creates oracle_factory callables for the IterativeRefiner.

The IterativeRefiner requires a factory of the shape::

    oracle_factory: Callable[[Path], DifferentialOracle]

This module provides :func:`make_oracle_factory` which captures an original
binary path and configuration, returning a factory that constructs a fresh
:class:`~reveng.verification.differential.oracle.DifferentialOracle` per call.

Usage example::

    from pathlib import Path
    from reveng.verification.refinement.oracle_adapter import make_oracle_factory

    factory = make_oracle_factory(original_binary=Path("/bin/original"), timeout_seconds=30.0)
    oracle = factory(Path("/tmp/recompiled"))
    report = oracle.verify(seed_inputs)
"""

from pathlib import Path
from typing import Callable

from ..differential.oracle import DifferentialOracle


def make_oracle_factory(
    original_binary: Path,
    timeout_seconds: float = 30.0,
) -> Callable[[Path], DifferentialOracle]:
    """
    Return a factory: ``(recompiled_binary: Path) -> DifferentialOracle``.

    The returned factory constructs a fresh :class:`DifferentialOracle` on
    every call, bound to *original_binary* with the given *timeout_seconds*.
    Each refinement round therefore gets an independent oracle with no shared
    per-run state.

    Parameters
    ----------
    original_binary:
        Path to the reference (original) binary.  **Must exist** at the time
        :func:`make_oracle_factory` is called; a :class:`FileNotFoundError`
        is raised immediately if it does not.
    timeout_seconds:
        Per-invocation wall-clock deadline passed through to
        :class:`DifferentialOracle`.  Must be strictly positive; a
        :class:`ValueError` is raised if it is ``<= 0``.

    Returns
    -------
    Callable[[Path], DifferentialOracle]
        A closure that accepts a recompiled-binary path and returns a ready-to-
        use :class:`DifferentialOracle` with *original_binary* pre-bound.

    Raises
    ------
    FileNotFoundError
        If *original_binary* does not exist on the filesystem.
    ValueError
        If *timeout_seconds* is not strictly positive.
    """
    original_binary = Path(original_binary)

    if not original_binary.exists():
        raise FileNotFoundError(
            f"Original binary not found: {original_binary!s}. "
            "Ensure the path points to an existing executable before creating the oracle factory."
        )

    if timeout_seconds <= 0:
        raise ValueError(
            f"timeout_seconds must be strictly positive, got {timeout_seconds!r}. "
            "Provide a value > 0 (e.g. 30.0 for a 30-second per-invocation deadline)."
        )

    # Capture configuration in closure — immutable references only.
    _original = original_binary
    _timeout = timeout_seconds

    def _factory(recompiled_binary: Path) -> DifferentialOracle:
        """
        Construct a fresh DifferentialOracle for *recompiled_binary*.

        Parameters
        ----------
        recompiled_binary:
            Path to the candidate binary produced by the current refinement
            round.  Coerced to :class:`pathlib.Path` if a string is passed.

        Returns
        -------
        DifferentialOracle
            A newly constructed oracle bound to the captured original binary
            and timeout.  A fresh instance is returned on every call so that
            each refinement round begins with clean state.
        """
        return DifferentialOracle(
            original=_original,
            recompiled=Path(recompiled_binary),
            timeout_seconds=_timeout,
        )

    return _factory
