#!/usr/bin/env python3
"""
run_vrl.py — End-to-end Verified Recompilation Loop runner.

Reads corpus.yaml to locate a benchmark binary entry, loads the best
available decompiled C source, then drives IterativeRefiner to convergence
(or budget exhaustion).  Results are written as a JSON log and a one-line
corpus grade update.

Usage::

    python scripts/run_vrl.py --binary hexyl --max-iterations 3

Environment:
    REVENG_AI_PROVIDER  — "ollama" | "anthropic" | "openai"  (default: ollama)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

# ---------------------------------------------------------------------------
# Repository root (parent of scripts/)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("run_vrl")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_CORPUS_YAML = _REPO_ROOT / ".reveng" / "benchmarks" / "corpus.yaml"
_WORKSPACE_BASE = _REPO_ROOT / ".reveng" / "vrl-runs" / "workspaces"
_RUNS_DIR = _REPO_ROOT / ".reveng" / "vrl-runs"

#: Where the pre-existing hexyl analysis lives.
_ARCHIVE_ANALYSIS_DIR = _REPO_ROOT / "_archive" / "2026-04-10-cleanup" / "analysis-dirs"

#: Candidate filenames searched inside the per-binary archive directory.
_RECONSTRUCTED_CANDIDATES = [
    "reconstructed.c",
    "reconstructed_gcc.c",
    "reconstructed_clang.c",
    "decompiled.c",
    "output.c",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _load_corpus(corpus_path: Path) -> Dict[str, Any]:
    """Load and return the parsed corpus YAML document."""
    if not corpus_path.exists():
        raise FileNotFoundError(
            f"corpus.yaml not found at {corpus_path}. "
            "Expected at .reveng/benchmarks/corpus.yaml relative to the repository root."
        )
    with corpus_path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _find_binary_entry(corpus: Dict[str, Any], binary_name: str) -> Dict[str, Any]:
    """Return the corpus entry for *binary_name*, or raise KeyError."""
    for entry in corpus.get("binaries", []):
        if entry.get("name") == binary_name:
            return entry
    available = [e.get("name") for e in corpus.get("binaries", [])]
    raise KeyError(f"Binary {binary_name!r} not found in corpus.yaml. " f"Available: {available}")


def _load_initial_source(binary_name: str) -> str:
    """
    Attempt to load an existing decompiled C source for *binary_name*.

    Search order:
      1. ``_archive/2026-04-10-cleanup/analysis-dirs/analysis_{binary_name}/``
         for any of the candidate filenames.
      2. A fallback stub is returned with a warning when nothing is found.

    Returns the C source text.
    """
    archive_dir = _ARCHIVE_ANALYSIS_DIR / f"analysis_{binary_name}"
    if archive_dir.is_dir():
        for candidate in _RECONSTRUCTED_CANDIDATES:
            candidate_path = archive_dir / candidate
            if candidate_path.exists():
                logger.info("Loading pre-existing decompilation from %s", candidate_path)
                return candidate_path.read_text(encoding="utf-8", errors="replace")

    # Nothing found — emit a clear message and use a stub.
    print("No pre-existing decompilation found — would run Ghidra (not implemented in this script)")
    logger.warning("No reconstructed.c found in %s; using placeholder stub.", archive_dir)
    return (
        "/* VRL stub — replace with real Ghidra decompilation output */\n"
        "#include <stdint.h>\n"
        "#include <stdio.h>\n"
        "int main(int argc, char **argv) {\n"
        '    fprintf(stderr, "stub: not implemented\\n");\n'
        "    return 1;\n"
        "}\n"
    )


def _get_seed_inputs(entry: Dict[str, Any]) -> List[bytes]:
    """
    Extract seed inputs from a corpus entry.

    Looks for ``seed_inputs`` or ``test_inputs`` lists in the YAML entry.
    Each item is converted to bytes (UTF-8 encoded when a string).
    Falls back to ``[b"--help"]`` when neither key is present.
    """
    raw: Optional[List[Any]] = entry.get("seed_inputs") or entry.get("test_inputs")
    if not raw:
        logger.info(
            "No seed_inputs in corpus entry for %r — using ['--help'] default.",
            entry.get("name"),
        )
        return [b"--help"]

    seeds: List[bytes] = []
    for item in raw:
        if isinstance(item, bytes):
            seeds.append(item)
        elif isinstance(item, str):
            seeds.append(item.encode("utf-8"))
        else:
            seeds.append(str(item).encode("utf-8"))
    return seeds


def _resolve_binary_path(entry: Dict[str, Any]) -> Path:
    """
    Resolve a filesystem path for the original binary referenced by *entry*.

    Checks ``binary_path`` and ``path`` keys in the entry, then falls back to
    the archive directory.  Raises ``FileNotFoundError`` when nothing is found
    so ``make_oracle_factory`` can provide a clear message.
    """
    # Allow explicit overrides in the corpus entry.
    for key in ("binary_path", "path"):
        raw_path = entry.get(key)
        if raw_path:
            p = Path(raw_path)
            if not p.is_absolute():
                p = _REPO_ROOT / p
            if p.exists():
                return p

    # Try to find a pre-compiled binary in the archive.
    name = entry["name"]
    archive_dir = _ARCHIVE_ANALYSIS_DIR / f"analysis_{name}"
    for candidate in (
        f"{name}.exe",
        f"{name}",
        "reconstructed_gcc.exe",
        "reconstructed_clang.exe",
        "reconstructed_gcc",
        "reconstructed_clang",
    ):
        p = archive_dir / candidate
        if p.exists():
            logger.info("Using archived binary as original: %s", p)
            return p

    raise FileNotFoundError(
        f"Original binary for {name!r} not found. "
        "Add 'binary_path' to the corpus entry or place the binary in the archive directory."
    )


def _update_corpus_grade(
    corpus_path: Path,
    binary_name: str,
    new_grade: str,
) -> None:
    """
    Update ``current_grade`` for *binary_name* in corpus.yaml in-place.

    Performs a line-by-line rewrite to preserve comments and formatting.
    """
    lines = corpus_path.read_text(encoding="utf-8").splitlines(keepends=True)
    inside_entry = False
    wrote_grade = False
    out_lines = []

    for line in lines:
        stripped = line.lstrip()
        # Detect start of the matching binary entry.
        if stripped.startswith("- name:") and binary_name in line:
            inside_entry = True
        elif stripped.startswith("- name:") and inside_entry:
            # We've moved to the next entry.
            inside_entry = False

        if inside_entry and "current_grade:" in line and not wrote_grade:
            indent = len(line) - len(line.lstrip())
            out_lines.append(" " * indent + f"current_grade: {new_grade}\n")
            wrote_grade = True
            continue

        out_lines.append(line)

    corpus_path.write_text("".join(out_lines), encoding="utf-8")
    if wrote_grade:
        logger.info("Updated corpus.yaml: %s.current_grade = %s", binary_name, new_grade)
    else:
        logger.warning("Could not locate current_grade for %r in corpus.yaml", binary_name)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Verified Recompilation Loop (VRL) for a benchmark binary.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--binary",
        default="hexyl",
        help="Name of the binary to process (must exist in corpus.yaml).",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=3,
        help="Maximum number of LLM refinement rounds.",
    )
    parser.add_argument(
        "--workspace",
        default=str(_WORKSPACE_BASE),
        help="Base directory for per-run workspace files.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:  # noqa: C901  (complexity is intentional)
    """
    Entry point for the VRL runner.

    Returns 0 on success, 1 on any error that prevents a meaningful run.
    """
    # --- delayed imports (allow mocking in tests) --------------------------
    from reveng.agents.ai.ai_analyzer_enhanced import get_analyzer
    from reveng.verification.refinement.compile_adapter import make_compile_fn
    from reveng.verification.refinement.models import RefinementBudget
    from reveng.verification.refinement.oracle_adapter import make_oracle_factory
    from reveng.verification.refinement.refiner import IterativeRefiner

    args = _parse_args(argv)

    # ------------------------------------------------------------------
    # 1. Load corpus
    # ------------------------------------------------------------------
    try:
        corpus = _load_corpus(_CORPUS_YAML)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    # ------------------------------------------------------------------
    # 2. Find corpus entry
    # ------------------------------------------------------------------
    try:
        entry = _find_binary_entry(corpus, args.binary)
    except KeyError as exc:
        logger.error("%s", exc)
        return 1

    logger.info(
        "Processing %r  current_grade=%s  target_grade=%s",
        args.binary,
        entry.get("current_grade", "unknown"),
        entry.get("target_grade", "unknown"),
    )

    # ------------------------------------------------------------------
    # 3. Load initial C source
    # ------------------------------------------------------------------
    initial_source = _load_initial_source(args.binary)

    # ------------------------------------------------------------------
    # 4. Create workspace directory
    # ------------------------------------------------------------------
    workspace_dir = Path(args.workspace) / args.binary
    workspace_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Workspace: %s", workspace_dir)

    # ------------------------------------------------------------------
    # 5. Resolve original binary path
    # ------------------------------------------------------------------
    try:
        original_binary = _resolve_binary_path(entry)
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 1

    # ------------------------------------------------------------------
    # 6. Build components
    # ------------------------------------------------------------------
    provider = os.environ.get("REVENG_AI_PROVIDER", "ollama")
    logger.info("AI provider: %s", provider)

    try:
        analyzer = get_analyzer(provider)
    except (ImportError, ValueError) as exc:
        logger.error("Failed to initialise analyzer: %s", exc)
        return 1

    compile_fn = make_compile_fn(workspace_dir)
    oracle_factory = make_oracle_factory(original_binary, timeout_seconds=30.0)
    budget = RefinementBudget(max_iterations=args.max_iterations)
    refiner = IterativeRefiner(
        analyzer=analyzer,
        compile_fn=compile_fn,
        oracle_factory=oracle_factory,
        budget=budget,
    )

    # ------------------------------------------------------------------
    # 7. Get seed inputs
    # ------------------------------------------------------------------
    seed_inputs = _get_seed_inputs(entry)
    logger.info("Seed inputs: %d item(s)", len(seed_inputs))

    # ------------------------------------------------------------------
    # 8. Run refinement loop
    # ------------------------------------------------------------------
    logger.info("Starting refinement loop (max_iterations=%d)…", args.max_iterations)
    result = refiner.refine(initial_source, seed_inputs)

    # ------------------------------------------------------------------
    # 9. Record results
    # ------------------------------------------------------------------
    final_grade = result.status.value  # e.g. "converged", "budget_exhausted"

    # 9a. Update corpus.yaml
    _update_corpus_grade(_CORPUS_YAML, args.binary, final_grade)

    # 9b. Write JSON run log
    _RUNS_DIR.mkdir(parents=True, exist_ok=True)
    today = date.today().isoformat()
    log_path = _RUNS_DIR / f"{args.binary}-{today}.json"
    log_data: Dict[str, Any] = {
        "binary_name": args.binary,
        "date": today,
        "status": result.status.value,
        "final_grade": final_grade,
        "iterations": result.iterations,
        "total_elapsed_seconds": result.total_elapsed_seconds,
        "total_tokens": result.total_tokens,
        "notes": result.notes,
        "workspace": str(workspace_dir),
        "original_binary": str(original_binary),
        "seed_inputs_count": len(seed_inputs),
    }
    log_path.write_text(json.dumps(log_data, indent=2), encoding="utf-8")
    logger.info("Run log written to %s", log_path)

    # 9c. Human-readable summary
    print()
    print("=" * 60)
    print("VRL RUN SUMMARY")
    print("=" * 60)
    print(f"  binary       : {args.binary}")
    print(f"  status       : {result.status.value}")
    print(f"  final grade  : {final_grade}")
    print(f"  iterations   : {result.iterations}")
    print(f"  elapsed      : {result.total_elapsed_seconds:.1f}s")
    print(f"  tokens used  : {result.total_tokens}")
    if result.notes:
        print(f"  notes        : {result.notes}")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
