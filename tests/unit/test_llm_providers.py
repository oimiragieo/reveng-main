"""
Unit tests for LLM provider integrations.

Tests AnthropicAnalyzer, OpenAIAnalyzer, and the get_analyzer() registry
function using unittest.mock — no real API calls are made.

Run with:
    cd C:/dev/projects/reveng-main && python -m pytest tests/unit/test_llm_providers.py -xvs
"""

import importlib
import json
import sys
import types
import unittest
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers to build lightweight mock SDK modules
# ---------------------------------------------------------------------------


def _make_anthropic_stub():
    """Return a minimal fake ``anthropic`` module."""
    mod = types.ModuleType("anthropic")

    class RateLimitError(Exception):
        pass

    class APIConnectionError(Exception):
        pass

    class Anthropic:
        def __init__(self, **kwargs):
            self.messages = MagicMock()

    mod.Anthropic = Anthropic
    mod.RateLimitError = RateLimitError
    mod.APIConnectionError = APIConnectionError
    return mod


def _make_openai_stub():
    """Return a minimal fake ``openai`` module."""
    mod = types.ModuleType("openai")

    class RateLimitError(Exception):
        pass

    class APIConnectionError(Exception):
        pass

    class OpenAI:
        def __init__(self, **kwargs):
            self.chat = MagicMock()

    mod.OpenAI = OpenAI
    mod.RateLimitError = RateLimitError
    mod.APIConnectionError = APIConnectionError
    return mod


# ---------------------------------------------------------------------------
# Fixtures / shared helpers
# ---------------------------------------------------------------------------

SAMPLE_JSON = json.dumps(
    {
        "purpose": "Allocates and zeroes a memory buffer",
        "category": "Memory",
        "complexity": "Low",
        "security_concerns": ["Unchecked malloc return"],
        "suggested_name": "alloc_zeroed_buffer",
        "confidence": 0.92,
        "reasoning": "Uses malloc + memset pattern",
    }
)

SAMPLE_CODE = "void* sub_1000(size_t n) { void* p = malloc(n); memset(p,0,n); return p; }"


# ---------------------------------------------------------------------------
# AnthropicAnalyzer tests
# ---------------------------------------------------------------------------


class TestAnthropicAnalyzer(unittest.TestCase):
    """Tests for AnthropicAnalyzer using a stubbed anthropic SDK."""

    def setUp(self):
        self.anthropic_mod = _make_anthropic_stub()
        # Inject stub into sys.modules so lazy import picks it up
        sys.modules["anthropic"] = self.anthropic_mod

        # Re-import the module to get a fresh class bound to our stub
        if "reveng.agents.ai.anthropic_analyzer" in sys.modules:
            del sys.modules["reveng.agents.ai.anthropic_analyzer"]
        from reveng.agents.ai.anthropic_analyzer import AnthropicAnalyzer

        self.AnthropicAnalyzer = AnthropicAnalyzer

    def tearDown(self):
        # Remove stub from sys.modules to avoid polluting other tests
        sys.modules.pop("anthropic", None)
        sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)

    # --- helper ---

    def _mock_response(self, text):
        """Build a mock Anthropic messages.create() return value."""
        block = MagicMock()
        block.text = text
        message = MagicMock()
        message.content = [block]
        message.usage = MagicMock(input_tokens=100, output_tokens=50)
        return message

    def _make_analyzer(self, **kwargs):
        return self.AnthropicAnalyzer(api_key="test-key", **kwargs)

    # --- constructor ---

    def test_init_defaults(self):
        az = self._make_analyzer()
        assert az.model_id == "claude-opus-4-6"
        assert az.max_tokens == 8192
        assert az.temperature == 0.2
        assert az.api_key == "test-key"

    def test_init_custom_model(self):
        az = self._make_analyzer(model_id="claude-sonnet-4-6")
        assert az.model_id == "claude-sonnet-4-6"

    def test_api_key_from_env(self, monkeypatch=None):
        import os

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "env-key"}):
            az = self.AnthropicAnalyzer()
            assert az.api_key == "env-key"

    # --- analyze_function happy path ---

    def test_analyze_function_returns_result(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.messages.create.return_value = self._mock_response(SAMPLE_JSON)

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "sub_1000")

        assert result.purpose == "Allocates and zeroes a memory buffer"
        assert result.category == "Memory"
        assert result.complexity == "Low"
        assert result.confidence == pytest.approx(0.92)
        assert result.suggested_name == "alloc_zeroed_buffer"
        assert len(result.security_concerns) == 1

    def test_analyze_function_passes_model_id(self):
        az = self._make_analyzer(model_id="claude-haiku-4-5-20251001")
        client_instance = MagicMock()
        client_instance.messages.create.return_value = self._mock_response(SAMPLE_JSON)

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            az.analyze_function(SAMPLE_CODE, "fn")

        call_kwargs = client_instance.messages.create.call_args[1]
        assert call_kwargs["model"] == "claude-haiku-4-5-20251001"

    # --- analyze_function error / fallback paths ---

    def test_analyze_function_falls_back_on_api_error(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.messages.create.side_effect = RuntimeError("network down")

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "sub_1000")

        # Should return a fallback AnalysisResult, not raise
        assert result.purpose == "Function sub_1000"
        assert result.confidence == pytest.approx(0.2)

    def test_analyze_function_rate_limit_retries_then_fails(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.messages.create.side_effect = self.anthropic_mod.RateLimitError(
            "rate limit"
        )

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            with patch("time.sleep"):  # don't actually sleep in tests
                result = az.analyze_function(SAMPLE_CODE, "fn")

        # After retries exhausted, falls back to heuristic
        assert result.confidence == pytest.approx(0.2)
        # messages.create should have been called max_retries times
        assert client_instance.messages.create.call_count == 3

    def test_analyze_function_connection_error_retries(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        # Fail twice, succeed on third attempt
        client_instance.messages.create.side_effect = [
            self.anthropic_mod.APIConnectionError("timeout"),
            self.anthropic_mod.APIConnectionError("timeout"),
            self._mock_response(SAMPLE_JSON),
        ]

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            with patch("time.sleep"):
                result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.purpose == "Allocates and zeroes a memory buffer"
        assert client_instance.messages.create.call_count == 3

    # --- generate_implementation ---

    def test_generate_implementation_returns_string(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.messages.create.return_value = self._mock_response(
            "```c\nvoid* alloc_zeroed(size_t n) { return calloc(1, n); }\n```"
        )

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            code = az.generate_implementation(
                {"name": "alloc_zeroed", "purpose": "alloc", "return_type": "void*"}
            )

        assert "alloc_zeroed" in code

    def test_generate_implementation_fallback_stub(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.messages.create.side_effect = RuntimeError("error")

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            code = az.generate_implementation({"name": "my_fn", "return_type": "int"})

        assert "my_fn" in code
        assert "TODO" in code

    # --- JSON parsing edge cases ---

    def test_parse_json_with_code_fence(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        fenced = f"```json\n{SAMPLE_JSON}\n```"
        client_instance.messages.create.return_value = self._mock_response(fenced)

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.category == "Memory"

    def test_parse_invalid_json_falls_back_to_text_extraction(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.messages.create.return_value = self._mock_response(
            "This function handles memory allocation and zeroing."
        )

        with patch.object(self.anthropic_mod, "Anthropic", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.category == "Memory"
        assert result.confidence == pytest.approx(0.3)

    # --- missing package ---

    def test_missing_anthropic_package_raises_import_error(self):
        sys.modules.pop("anthropic", None)
        sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)

        # Block import at sys.modules level
        sys.modules["anthropic"] = None  # type: ignore[assignment]

        try:
            if "reveng.agents.ai.anthropic_analyzer" in sys.modules:
                del sys.modules["reveng.agents.ai.anthropic_analyzer"]
            from reveng.agents.ai.anthropic_analyzer import AnthropicAnalyzer

            az = AnthropicAnalyzer(api_key="k")
            with pytest.raises(ImportError, match="anthropic"):
                az._call_anthropic("hello")
        finally:
            sys.modules.pop("anthropic", None)
            sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)


# ---------------------------------------------------------------------------
# OpenAIAnalyzer tests
# ---------------------------------------------------------------------------


class TestOpenAIAnalyzer(unittest.TestCase):
    """Tests for OpenAIAnalyzer using a stubbed openai SDK."""

    def setUp(self):
        self.openai_mod = _make_openai_stub()
        sys.modules["openai"] = self.openai_mod

        if "reveng.agents.ai.openai_analyzer" in sys.modules:
            del sys.modules["reveng.agents.ai.openai_analyzer"]
        from reveng.agents.ai.openai_analyzer import OpenAIAnalyzer

        self.OpenAIAnalyzer = OpenAIAnalyzer

    def tearDown(self):
        sys.modules.pop("openai", None)
        sys.modules.pop("reveng.agents.ai.openai_analyzer", None)

    # --- helper ---

    def _mock_response(self, text):
        """Build a mock OpenAI chat.completions.create() return value."""
        message = MagicMock()
        message.content = text
        choice = MagicMock()
        choice.message = message
        response = MagicMock()
        response.choices = [choice]
        response.usage = MagicMock(prompt_tokens=100, completion_tokens=50)
        return response

    def _make_analyzer(self, **kwargs):
        return self.OpenAIAnalyzer(api_key="test-key", **kwargs)

    # --- constructor ---

    def test_init_defaults(self):
        az = self._make_analyzer()
        assert az.model_id == "gpt-4o"
        assert az.max_tokens == 8192
        assert az.temperature == 0.2

    def test_init_custom_model(self):
        az = self._make_analyzer(model_id="gpt-4o")
        assert az.model_id == "gpt-4o"

    def test_api_key_from_env(self):
        import os

        with patch.dict(os.environ, {"OPENAI_API_KEY": "env-oai-key"}):
            az = self.OpenAIAnalyzer()
            assert az.api_key == "env-oai-key"

    # --- analyze_function happy path ---

    def test_analyze_function_returns_result(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.return_value = self._mock_response(SAMPLE_JSON)

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "sub_1000")

        assert result.purpose == "Allocates and zeroes a memory buffer"
        assert result.category == "Memory"
        assert result.complexity == "Low"
        assert result.confidence == pytest.approx(0.92)

    def test_analyze_function_passes_model_id(self):
        az = self._make_analyzer(model_id="gpt-4o")
        client_instance = MagicMock()
        client_instance.chat.completions.create.return_value = self._mock_response(SAMPLE_JSON)

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            az.analyze_function(SAMPLE_CODE, "fn")

        call_kwargs = client_instance.chat.completions.create.call_args[1]
        assert call_kwargs["model"] == "gpt-4o"

    # --- fallback paths ---

    def test_analyze_function_falls_back_on_api_error(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.side_effect = RuntimeError("network down")

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "sub_1000")

        assert result.purpose == "Function sub_1000"
        assert result.confidence == pytest.approx(0.2)

    def test_analyze_function_rate_limit_retries_then_fails(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.side_effect = self.openai_mod.RateLimitError(
            "rate limit"
        )

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            with patch("time.sleep"):
                result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.confidence == pytest.approx(0.2)
        assert client_instance.chat.completions.create.call_count == 3

    def test_analyze_function_connection_error_retries(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.side_effect = [
            self.openai_mod.APIConnectionError("timeout"),
            self.openai_mod.APIConnectionError("timeout"),
            self._mock_response(SAMPLE_JSON),
        ]

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            with patch("time.sleep"):
                result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.purpose == "Allocates and zeroes a memory buffer"
        assert client_instance.chat.completions.create.call_count == 3

    # --- generate_implementation ---

    def test_generate_implementation_returns_string(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.return_value = self._mock_response(
            "```c\nvoid* alloc_zeroed(size_t n) { return calloc(1, n); }\n```"
        )

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            code = az.generate_implementation(
                {"name": "alloc_zeroed", "purpose": "alloc", "return_type": "void*"}
            )

        assert "alloc_zeroed" in code

    def test_generate_implementation_fallback_stub(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.side_effect = RuntimeError("error")

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            code = az.generate_implementation({"name": "my_fn", "return_type": "int"})

        assert "my_fn" in code
        assert "TODO" in code

    # --- JSON parsing edge cases ---

    def test_parse_json_with_code_fence(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        fenced = f"```json\n{SAMPLE_JSON}\n```"
        client_instance.chat.completions.create.return_value = self._mock_response(fenced)

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.category == "Memory"

    def test_parse_invalid_json_falls_back_to_text_extraction(self):
        az = self._make_analyzer()
        client_instance = MagicMock()
        client_instance.chat.completions.create.return_value = self._mock_response(
            "This function handles memory allocation and zeroing."
        )

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "fn")

        assert result.category == "Memory"
        assert result.confidence == pytest.approx(0.3)

    def test_none_content_raises_value_error(self):
        """OpenAI returning message.content=None should be caught and fall back."""
        az = self._make_analyzer()
        client_instance = MagicMock()
        null_resp = self._mock_response(None)
        # Override content to None
        null_resp.choices[0].message.content = None
        client_instance.chat.completions.create.return_value = null_resp

        with patch.object(self.openai_mod, "OpenAI", return_value=client_instance):
            result = az.analyze_function(SAMPLE_CODE, "fn")

        # Falls back gracefully — does not raise
        assert result.confidence == pytest.approx(0.2)

    # --- missing package ---

    def test_missing_openai_package_raises_import_error(self):
        sys.modules.pop("openai", None)
        sys.modules.pop("reveng.agents.ai.openai_analyzer", None)

        sys.modules["openai"] = None  # type: ignore[assignment]

        try:
            if "reveng.agents.ai.openai_analyzer" in sys.modules:
                del sys.modules["reveng.agents.ai.openai_analyzer"]
            from reveng.agents.ai.openai_analyzer import OpenAIAnalyzer

            az = OpenAIAnalyzer(api_key="k")
            with pytest.raises(ImportError, match="openai"):
                az._call_openai("hello")
        finally:
            sys.modules.pop("openai", None)
            sys.modules.pop("reveng.agents.ai.openai_analyzer", None)


# ---------------------------------------------------------------------------
# get_analyzer() registry tests
# ---------------------------------------------------------------------------


class TestGetAnalyzer(unittest.TestCase):
    """Tests for the get_analyzer() provider registry function."""

    def _import_get_analyzer(self):
        """Re-import get_analyzer after clearing cached module."""
        if "reveng.agents.ai.ai_provider_registry" in sys.modules:
            del sys.modules["reveng.agents.ai.ai_provider_registry"]
        from reveng.agents.ai.ai_provider_registry import get_analyzer

        return get_analyzer

    def test_get_analyzer_anthropic_returns_instance(self):
        anthropic_mod = _make_anthropic_stub()
        sys.modules["anthropic"] = anthropic_mod
        sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)

        try:
            get_analyzer = self._import_get_analyzer()
            az = get_analyzer("anthropic")
            from reveng.agents.ai.anthropic_analyzer import AnthropicAnalyzer

            assert isinstance(az, AnthropicAnalyzer)
        finally:
            sys.modules.pop("anthropic", None)
            sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)
            sys.modules.pop("reveng.agents.ai.ai_provider_registry", None)

    def test_get_analyzer_openai_returns_instance(self):
        openai_mod = _make_openai_stub()
        sys.modules["openai"] = openai_mod
        sys.modules.pop("reveng.agents.ai.openai_analyzer", None)

        try:
            get_analyzer = self._import_get_analyzer()
            az = get_analyzer("openai")
            from reveng.agents.ai.openai_analyzer import OpenAIAnalyzer

            assert isinstance(az, OpenAIAnalyzer)
        finally:
            sys.modules.pop("openai", None)
            sys.modules.pop("reveng.agents.ai.openai_analyzer", None)
            sys.modules.pop("reveng.agents.ai.ai_provider_registry", None)

    def test_get_analyzer_unknown_provider_raises_value_error(self):
        get_analyzer = self._import_get_analyzer()
        with pytest.raises(ValueError, match="Unknown AI provider"):
            get_analyzer("bogus_provider")

    def test_get_analyzer_reads_env_var(self):
        import os

        anthropic_mod = _make_anthropic_stub()
        sys.modules["anthropic"] = anthropic_mod
        sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)

        try:
            get_analyzer = self._import_get_analyzer()
            with patch.dict(os.environ, {"REVENG_AI_PROVIDER": "anthropic"}):
                az = get_analyzer()
            from reveng.agents.ai.anthropic_analyzer import AnthropicAnalyzer

            assert isinstance(az, AnthropicAnalyzer)
        finally:
            sys.modules.pop("anthropic", None)
            sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)
            sys.modules.pop("reveng.agents.ai.ai_provider_registry", None)

    def test_get_analyzer_explicit_arg_overrides_env(self):
        import os

        openai_mod = _make_openai_stub()
        sys.modules["openai"] = openai_mod
        sys.modules.pop("reveng.agents.ai.openai_analyzer", None)

        try:
            get_analyzer = self._import_get_analyzer()
            # Env says anthropic but explicit arg says openai
            with patch.dict(os.environ, {"REVENG_AI_PROVIDER": "anthropic"}):
                az = get_analyzer("openai")
            from reveng.agents.ai.openai_analyzer import OpenAIAnalyzer

            assert isinstance(az, OpenAIAnalyzer)
        finally:
            sys.modules.pop("openai", None)
            sys.modules.pop("reveng.agents.ai.openai_analyzer", None)
            sys.modules.pop("reveng.agents.ai.ai_provider_registry", None)

    def test_get_analyzer_case_insensitive(self):
        anthropic_mod = _make_anthropic_stub()
        sys.modules["anthropic"] = anthropic_mod
        sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)

        try:
            get_analyzer = self._import_get_analyzer()
            az = get_analyzer("ANTHROPIC")
            from reveng.agents.ai.anthropic_analyzer import AnthropicAnalyzer

            assert isinstance(az, AnthropicAnalyzer)
        finally:
            sys.modules.pop("anthropic", None)
            sys.modules.pop("reveng.agents.ai.anthropic_analyzer", None)
            sys.modules.pop("reveng.agents.ai.ai_provider_registry", None)


if __name__ == "__main__":
    unittest.main()
