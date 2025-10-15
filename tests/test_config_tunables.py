#!/usr/bin/env python3
"""Test that Ollama config tunables are actually threaded through"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "tools"))

from config_manager import get_config
from ollama_analyzer import OllamaAnalyzer

def test_config_tunables():
    """Verify config tunables are passed to OllamaAnalyzer"""

    print("=" * 70)
    print("Testing Ollama Config Tunables")
    print("=" * 70)

    # Load config
    config = get_config()
    ai_config = config.get_ai_config()

    print(f"\nConfig from .reveng/config.yaml:")
    print(f"  Timeout: {ai_config.ollama_timeout}s")
    print(f"  Temperature: {ai_config.ollama_temperature}")
    print(f"  Max Tokens: {ai_config.ollama_max_tokens}")
    print(f"  Model: {ai_config.ollama_model}")

    # Create analyzer with config values
    analyzer = OllamaAnalyzer(
        model_name=ai_config.ollama_model if ai_config.ollama_model != 'auto' else None,
        ollama_host=ai_config.ollama_host,
        timeout=ai_config.ollama_timeout,
        temperature=ai_config.ollama_temperature,
        max_tokens=ai_config.ollama_max_tokens
    )

    print(f"\nOllamaAnalyzer instance values:")
    print(f"  Timeout: {analyzer.timeout}s")
    print(f"  Temperature: {analyzer.temperature}")
    print(f"  Max Tokens: {analyzer.max_tokens}")
    print(f"  Model: {analyzer.model_name}")

    # Verify values match
    print(f"\nVerification:")
    if analyzer.timeout == ai_config.ollama_timeout:
        print(f"  [OK] Timeout matches config: {analyzer.timeout}s")
    else:
        print(f"  [FAIL] Timeout mismatch: config={ai_config.ollama_timeout}, analyzer={analyzer.timeout}")

    if analyzer.temperature == ai_config.ollama_temperature:
        print(f"  [OK] Temperature matches config: {analyzer.temperature}")
    else:
        print(f"  [FAIL] Temperature mismatch: config={ai_config.ollama_temperature}, analyzer={analyzer.temperature}")

    if analyzer.max_tokens == ai_config.ollama_max_tokens:
        print(f"  [OK] Max tokens matches config: {analyzer.max_tokens}")
    else:
        print(f"  [FAIL] Max tokens mismatch: config={ai_config.ollama_max_tokens}, analyzer={analyzer.max_tokens}")

    print(f"\n" + "=" * 70)
    print("Config Tunables Test Complete")
    print("=" * 70)

if __name__ == "__main__":
    test_config_tunables()
