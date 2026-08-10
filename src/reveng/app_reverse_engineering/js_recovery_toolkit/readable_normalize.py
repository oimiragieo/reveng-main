"""Hermetic readable-normalize (beautify-lite) for minified JS.

Does **not** undo control-flow flattening or encrypted string arrays — that is
webcrack/synchrony territory (optional ``--run-external``). This stage only
restores whitespace and a few minifier idioms so pattern/fingerprint passes
see more structure — the prerequisite for AST-chunked LLM summarize later.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class ReadableNormalizeResult:
    text: str
    notes: List[str] = field(default_factory=list)
    transformations: int = 0

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "readable_normalize",
            "output_chars": len(self.text),
            "transformations": self.transformations,
            "notes": list(self.notes),
            "decoded_exe_claim": False,
        }


_VOID0 = re.compile(r"\bvoid\s+0\b")
_BANG0 = re.compile(r"!0\b")
_BANG1 = re.compile(r"!1\b")
# Insert newlines after statement boundaries (safe-ish for fingerprinting, not exec)
_SEMI = re.compile(r";(?!\s*\n)")
_BRACE_OPEN = re.compile(r"\{(?!\s*\n)")
_BRACE_CLOSE = re.compile(r"\}(?!\s*\n)")


def readable_normalize(text: str, *, max_chars: int = 40_000_000) -> ReadableNormalizeResult:
    """Beautify-lite: minifier idioms + line breaks. Caps output size."""
    notes = ["hermetic_beautify_lite", "not_cff_unflatten", "not_string_array_decrypt"]
    if not text:
        return ReadableNormalizeResult(text="", notes=notes + ["empty"])
    body = text if len(text) <= max_chars else text[:max_chars]
    if len(text) > max_chars:
        notes.append("truncated_input")
    n = 0
    before = body
    body = _VOID0.sub("undefined", body)
    body = _BANG0.sub("true", body)
    body = _BANG1.sub("false", body)
    if body != before:
        n += 1
    # Line-break pass (helps regex scanners and human/LLM chunking)
    body2 = _SEMI.sub(";\n", body)
    body2 = _BRACE_OPEN.sub("{\n", body2)
    body2 = _BRACE_CLOSE.sub("\n}\n", body2)
    if body2 != body:
        n += 1
        body = body2
    notes.append("readable_normalize_ok")
    return ReadableNormalizeResult(text=body, notes=notes, transformations=n)
