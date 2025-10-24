"""Tests for moving configuration into the new package layout."""

from pathlib import Path
from unittest.mock import patch

from reveng.agents.ai.ollama_analyzer import OllamaAnalyzer
from reveng.tools.config.config_manager import ConfigManager


def _write_config(path: Path) -> None:
    path.write_text(
        """
ai:
  provider: ollama
  ollama:
    host: http://localhost:11439
    model: llama3
    timeout: 45
    temperature: 0.4
    max_tokens: 384
analysis:
  enable_ai: true
  fallback_to_heuristics: false
  max_ai_functions: 8
  batch_size: 4
  show_progress: true
"""
    )


def test_config_manager_returns_expected_ai_settings(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)

    manager = ConfigManager(config_path=config_path)
    ai_config = manager.get_ai_config()

    assert ai_config.ollama_host == "http://localhost:11439"
    assert ai_config.ollama_model == "llama3"
    assert ai_config.ollama_timeout == 45
    assert ai_config.enable_ai is True


def test_ollama_analyzer_uses_config_values(tmp_path: Path):
    config_path = tmp_path / "config.yaml"
    _write_config(config_path)

    manager = ConfigManager(config_path=config_path)
    ai_config = manager.get_ai_config()

    with patch(
        "reveng.agents.ai.ollama_analyzer.OllamaAnalyzer._get_available_models",
        return_value=[],
    ):
        analyzer = OllamaAnalyzer(
            model_name=ai_config.ollama_model,
            ollama_host=ai_config.ollama_host,
            timeout=ai_config.ollama_timeout,
            temperature=ai_config.ollama_temperature,
            max_tokens=ai_config.ollama_max_tokens,
        )

    assert analyzer.model_name == "llama3"
    assert analyzer.timeout == 45
    assert analyzer.temperature == 0.4
    assert analyzer.max_tokens == 384
