"""
Prompt templates for the Iterative LLM Refiner.

Only one template is defined here: REFINEMENT_PROMPT_TEMPLATE.  The
build_refinement_prompt() helper formats it from a DivergenceReport and
the current source.
"""

from typing import Optional

from ..models import DivergenceReport

# ---------------------------------------------------------------------------
# Template
# ---------------------------------------------------------------------------

REFINEMENT_PROMPT_TEMPLATE: str = """\
You are a C decompilation repair expert.  Round {iteration} of {max_iterations}.

## Task

The decompiled C source below was compiled and tested.  The resulting binary
produced output that DIVERGED from the original binary on the failing input
shown.  Your job is to fix the C source so that it produces the SAME output
as the original binary.

## Failing input (hex-encoded)

{failing_input_hex}

## Expected output (original binary)

{expected_output}

## Actual output (recompiled binary)

{actual_output}

## Current C source

```c
{current_source}
```

## Instructions

1. Return a COMPLETE, compilable C source file — not a diff or a patch.
2. Preserve the overall function structure.  Only fix what is broken.
3. Do NOT add any comments explaining what you changed.
4. Wrap the fixed source in a single ```c ... ``` code fence and nothing else.
"""

# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


def build_refinement_prompt(
    source: str,
    divergence: DivergenceReport,
    iteration: int,
    max_iterations: int,
) -> str:
    """
    Format REFINEMENT_PROMPT_TEMPLATE with data extracted from *divergence*.

    When divergence contains multiple failing inputs, only the first is used
    to keep the prompt focused.  When divergence contains multiple diverging
    output pairs, only the first pair is shown.

    Args:
        source:         Current decompiled C source.
        divergence:     DivergenceReport from the last oracle run.
        iteration:      Current 1-based round number.
        max_iterations: Budget cap (shown to the LLM for context).

    Returns:
        A fully-formatted prompt string ready to send to the LLM.
    """
    # --- failing input ---
    if divergence.failing_inputs:
        failing_input_hex = divergence.failing_inputs[0].hex()
    else:
        failing_input_hex = "(no failing input recorded)"

    # --- expected / actual outputs ---
    if divergence.diverging_outputs:
        expected_raw, actual_raw = divergence.diverging_outputs[0]
        expected_output = _decode_output(expected_raw)
        actual_output = _decode_output(actual_raw)
    else:
        expected_output = "(not recorded)"
        actual_output = "(not recorded)"

    return REFINEMENT_PROMPT_TEMPLATE.format(
        iteration=iteration,
        max_iterations=max_iterations,
        failing_input_hex=failing_input_hex,
        expected_output=expected_output,
        actual_output=actual_output,
        current_source=source,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _decode_output(raw: bytes, max_bytes: int = 512) -> str:
    """
    Decode raw bytes to a human-readable string for inclusion in the prompt.

    Tries UTF-8 first; falls back to hex if the bytes are not valid text or
    exceed max_bytes.
    """
    if len(raw) > max_bytes:
        return f"(binary, {len(raw)} bytes) " + raw[:max_bytes].hex() + " ..."
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.hex()
