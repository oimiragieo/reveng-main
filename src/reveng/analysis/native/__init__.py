"""Native binary reverse-engineering helpers."""

from .ghidra_workflow import (
    build_native_project_ir,
    build_native_source_segments,
    materialize_decompiled_functions,
    run_native_ghidra_analysis,
    write_analysis_payload,
)

__all__ = [
    "build_native_project_ir",
    "build_native_source_segments",
    "materialize_decompiled_functions",
    "run_native_ghidra_analysis",
    "write_analysis_payload",
]
