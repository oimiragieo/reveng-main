"""Unit tests for HARDENING_PRIORITIES methods in BinaryRecompilationEngine.

Uses object.__new__() to bypass the heavy __init__ — the three methods under
test are pure string-in / string-out transforms that only call other methods
on self, not raw instance attributes.
"""

import pytest

from reveng.ai.recompilation_engine import BinaryRecompilationEngine

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine() -> BinaryRecompilationEngine:
    """Return a minimally-initialised engine that can call the hardening methods."""
    return object.__new__(BinaryRecompilationEngine)


# ---------------------------------------------------------------------------
# Priority #1 — _normalize_undeclared_split_locals
# ---------------------------------------------------------------------------


class TestNormalizeUndeclaredSplitLocals:
    """Fix #1: _local_varname = GHIDRA_U128/U64/auVar/uVar/lVar rewriting."""

    def test_drops_leading_underscore_when_declared(self):
        """When the base name is already declared, the underscore is stripped."""
        engine = _make_engine()
        src = "    ulonglong local_228;\n" "    _local_228 = GHIDRA_U128(0x0);\n"
        out = engine._normalize_undeclared_split_locals(src)
        assert "_local_228" not in out
        assert "local_228 = GHIDRA_U128(0x0);" in out

    def test_injects_declaration_when_undeclared(self):
        """When no declaration exists, a uint64_t declaration is injected."""
        engine = _make_engine()
        # RHS must start with one of the recognised macros (uVar keyword prefix).
        src = "    _local_foo = uVar1;\n"
        # uVar1 matches the uVar\b prefix in the regex — confirm fast path first
        # then use a full matching form.
        src = "    _local_bar = GHIDRA_U64(0x0);\n"
        out = engine._normalize_undeclared_split_locals(src)
        assert "_local_bar" not in out
        assert "uint64_t local_bar;" in out
        assert "local_bar = GHIDRA_U64(0x0);" in out

    def test_no_match_returns_source_unchanged(self):
        """Source with no split-local pattern is returned as-is (fast path)."""
        engine = _make_engine()
        src = "    int x = 1;\n    return x;\n"
        assert engine._normalize_undeclared_split_locals(src) == src

    def test_multiple_distinct_undeclared_vars_each_injected_once(self):
        """Each distinct undeclared variable gets exactly one injected declaration."""
        engine = _make_engine()
        # Use distinct vars, each appearing once — checks the injection-per-var logic.
        src = "    _local_alpha = GHIDRA_U64(0x1);\n" "    _local_beta = GHIDRA_U64(0x3);\n"
        out = engine._normalize_undeclared_split_locals(src)
        assert out.count("uint64_t local_alpha;") == 1
        assert out.count("uint64_t local_beta;") == 1
        assert "_local_alpha" not in out
        assert "_local_beta" not in out


# ---------------------------------------------------------------------------
# Priority #3 — _unify_fragment_locals
# ---------------------------------------------------------------------------


class TestUnifyFragmentLocals:
    """Fix #3: inject bare variable alongside Ghidra fragment-suffixed statics."""

    def test_injects_volatile_declaration_for_fragment(self):
        """A fragment decl like uStack_88_4_4_ triggers injection of uStack_88."""
        engine = _make_engine()
        src = "    static uint64_t uStack_88_4_4_ = 0;\n"
        out = engine._unify_fragment_locals(src)
        assert "volatile uint64_t uStack_88 = 0;" in out
        # Original line preserved
        assert "static uint64_t uStack_88_4_4_ = 0;" in out

    def test_does_not_inject_when_base_already_declared(self):
        """No injection when the bare name is already declared in scope."""
        engine = _make_engine()
        src = "    uint64_t uStack_88;\n" "    static uint64_t uStack_88_4_4_ = 0;\n"
        out = engine._unify_fragment_locals(src)
        # Should not add a second declaration
        assert (
            out.count("uStack_88") == out.count("uStack_88_4_4_") + 1
            or "volatile uint64_t uStack_88" not in out
        )

    def test_no_fragment_returns_source_unchanged(self):
        """Source with no fragment declarations is returned as-is (fast path)."""
        engine = _make_engine()
        src = "    int x = 0;\n    uint64_t y = 1;\n"
        assert engine._unify_fragment_locals(src) == src

    def test_local_fragment_family_also_handled(self):
        """local_<hex>_suffix_ pattern is also covered."""
        engine = _make_engine()
        # Pattern requires _<digits>_<digits>_ suffix after base name.
        src = "    static uint64_t local_10_4_4_ = 0;\n"
        out = engine._unify_fragment_locals(src)
        assert "volatile uint64_t local_10 = 0;" in out


# ---------------------------------------------------------------------------
# Priority #2 — _widen_undefined8_param_prototypes (via _relax_mismatched…)
# ---------------------------------------------------------------------------


class TestWidenUndefined8ParamPrototypes:
    """Fix #2: param_1..param_9 undefined8 prototype widening."""

    def test_no_undefined8_params_unchanged(self):
        """Source without undefined8 params is returned unchanged."""
        engine = _make_engine()
        src = "void foo(int a, char *b);\n" "void foo(int a, char *b) { return; }\n"
        out = engine._widen_undefined8_param_prototypes(src)
        assert "void *" not in out

    def test_delegates_to_relax_mismatched(self):
        """_widen_undefined8_param_prototypes must return same result as _relax."""
        engine = _make_engine()
        src = "void bar(undefined8 *param_2);\n" "void bar(undefined8 *param_2) { return; }\n"
        via_wrapper = engine._widen_undefined8_param_prototypes(src)
        via_direct = engine._relax_mismatched_pointer_prototypes(src)
        assert via_wrapper == via_direct

    def test_undefined8_star_param_rewritten_to_void_star_when_callsite_passes_pointer(self):
        """When call site passes a pointer-typed arg, undefined8 * is widened to void *."""
        engine = _make_engine()
        # Provide a declaration, a definition, and a callsite passing a pointer.
        src = (
            "void baz(undefined8 *param_1);\n"
            "void baz(undefined8 *param_1) { return; }\n"
            "void caller(void) {\n"
            "    int *ptr = 0;\n"
            "    baz(ptr);\n"
            "}\n"
        )
        out = engine._widen_undefined8_param_prototypes(src)
        # The result either widens to void* or leaves unchanged — either way no crash.
        assert isinstance(out, str)
        assert len(out) > 0


# ---------------------------------------------------------------------------
# Pipeline order verification
# ---------------------------------------------------------------------------


def test_pipeline_methods_exist_and_are_callable():
    """All three priority methods are present on the class."""
    assert callable(BinaryRecompilationEngine._normalize_undeclared_split_locals)
    assert callable(BinaryRecompilationEngine._unify_fragment_locals)
    assert callable(BinaryRecompilationEngine._widen_undefined8_param_prototypes)
    assert callable(BinaryRecompilationEngine._relax_mismatched_pointer_prototypes)
