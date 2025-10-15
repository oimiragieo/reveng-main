#!/usr/bin/env python3
"""
REVENG Ollama Preflight Checker
================================

Validates Ollama installation and model availability before running AI analysis.

Provides:
- Ollama service connectivity check
- Model availability verification
- Configuration validation
- Helpful error messages and setup instructions

Author: REVENG Project
Version: 1.0
"""

import logging
import requests
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import sys

logger = logging.getLogger(__name__)


class OllamaPreflightChecker:
    """
    Preflight checker for Ollama AI integration

    Validates Ollama is ready before attempting analysis
    """

    def __init__(self, ollama_host: str = "http://localhost:11434"):
        """
        Initialize preflight checker

        Args:
            ollama_host: Ollama API host URL
        """
        self.ollama_host = ollama_host.rstrip('/')
        self.api_base = f"{self.ollama_host}/api"

    def check_all(self, required_model: Optional[str] = None) -> Tuple[bool, Dict[str, any]]:
        """
        Run all preflight checks

        Args:
            required_model: Specific model that must be available (optional)

        Returns:
            Tuple of (success: bool, results: dict)
        """
        results = {
            'service_running': False,
            'models_available': [],
            'required_model_found': False,
            'errors': [],
            'warnings': []
        }

        # Check 1: Ollama service running
        service_ok, service_msg = self._check_service()
        results['service_running'] = service_ok

        if not service_ok:
            results['errors'].append(service_msg)
            return False, results

        # Check 2: List available models
        models = self._list_models()
        results['models_available'] = models

        if not models:
            results['warnings'].append("No Ollama models found - AI analysis will fail")
            results['errors'].append("Please install at least one model: ollama pull phi3.5")
            return False, results

        # Check 3: Required model (if specified)
        if required_model and required_model != 'auto':
            model_found = any(required_model in m['name'] for m in models)
            results['required_model_found'] = model_found

            if not model_found:
                results['errors'].append(
                    f"Required model '{required_model}' not found. "
                    f"Install with: ollama pull {required_model}"
                )
                return False, results
        else:
            results['required_model_found'] = True

        # All checks passed
        logger.info(f"Ollama preflight passed: {len(models)} models available")
        return True, results

    def _check_service(self) -> Tuple[bool, str]:
        """
        Check if Ollama service is running and accessible

        Returns:
            Tuple of (success: bool, message: str)
        """
        # Try /api/version first (proper Ollama endpoint), fall back to /api/tags
        endpoints = ["/api/version", "/api/tags"]

        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.ollama_host}{endpoint}", timeout=5)
                if response.status_code == 200:
                    logger.info(f"Ollama service is running (verified via {endpoint})")
                    return True, "Ollama service running"
                elif response.status_code == 404:
                    # Try next endpoint
                    continue
                else:
                    msg = f"Ollama {endpoint} returned status {response.status_code}"
                    logger.warning(msg)
                    # Try next endpoint
                    continue

            except requests.ConnectionError:
                msg = (
                    "Cannot connect to Ollama service. "
                    "Is Ollama running? Start with: ollama serve"
                )
                logger.error(msg)
                return False, msg

            except requests.Timeout:
                msg = "Ollama service connection timed out"
                logger.error(msg)
                return False, msg

            except Exception as e:
                msg = f"Error checking Ollama service: {e}"
                logger.error(msg)
                return False, msg

        # All endpoints failed
        msg = "Ollama service endpoints not responding (tried /api/version, /api/tags)"
        logger.error(msg)
        return False, msg

    def _list_models(self) -> List[Dict[str, any]]:
        """
        List available Ollama models

        Returns:
            List of model dictionaries with 'name' and 'size' fields
        """
        try:
            response = requests.get(f"{self.api_base}/tags", timeout=10)
            if response.status_code == 200:
                data = response.json()
                models = data.get('models', [])
                logger.info(f"Found {len(models)} Ollama models")
                return models
            else:
                logger.error(f"Failed to list models: HTTP {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error listing models: {e}")
            return []

    def get_recommended_model(self) -> Optional[str]:
        """
        Get recommended model for code analysis

        Returns:
            Model name or None if no suitable model found
        """
        models = self._list_models()
        if not models:
            return None

        # Preference order for code analysis
        preferred = [
            'deepseek-coder',
            'qwen2.5-coder',
            'codellama',
            'phi3.5',
            'phi',
            'llama3.1',
            'llama3',
            'mistral'
        ]

        for pref in preferred:
            for model in models:
                if pref in model['name'].lower():
                    logger.info(f"Recommended model: {model['name']}")
                    return model['name']

        # Return first available model as fallback
        first_model = models[0]['name']
        logger.info(f"No preferred model found, using: {first_model}")
        return first_model

    def print_setup_instructions(self):
        """Print helpful setup instructions for Ollama"""
        print("\n" + "=" * 70)
        print(" OLLAMA SETUP REQUIRED")
        print("=" * 70)
        print("\nOllama is not properly configured. To enable AI-powered analysis:\n")

        print("1. Install Ollama:")
        print("   Windows: Download from https://ollama.ai")
        print("   Linux:   curl -fsSL https://ollama.ai/install.sh | sh")
        print("   macOS:   brew install ollama")

        print("\n2. Start Ollama service:")
        print("   ollama serve")

        print("\n3. Pull a code analysis model (choose one):")
        print("   ollama pull phi3.5              # Fast, 3.8B params, 2.2GB")
        print("   ollama pull qwen2.5-coder       # Best, 14.8B params, 9GB")
        print("   ollama pull deepseek-coder      # Excellent, 6.7B params, 4GB")

        print("\n4. Verify installation:")
        print("   ollama list")

        print("\n5. Configure REVENG (.reveng/config.yaml):")
        print("   ai:")
        print("     provider: ollama")
        print("     ollama:")
        print("       host: http://localhost:11434")
        print("       model: auto  # or specify: phi3.5, qwen2.5-coder, etc.")

        print("\n" + "=" * 70)
        print(" For more info: OLLAMA_QUICKSTART.md")
        print("=" * 70 + "\n")


# CLI for standalone testing
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format='%(levelname)s: %(message)s'
    )

    parser = argparse.ArgumentParser(description='Check Ollama preflight status')
    parser.add_argument('--host', default='http://localhost:11434', help='Ollama host URL')
    parser.add_argument('--model', help='Check for specific model')
    parser.add_argument('--setup', action='store_true', help='Show setup instructions')
    args = parser.parse_args()

    checker = OllamaPreflightChecker(args.host)

    if args.setup:
        checker.print_setup_instructions()
        sys.exit(0)

    # Run preflight checks
    success, results = checker.check_all(args.model)

    # Print results
    print("\n" + "=" * 70)
    print(" OLLAMA PREFLIGHT CHECK")
    print("=" * 70)

    print(f"\nService Running: {'OK' if results['service_running'] else 'FAIL'}")
    print(f"Models Available: {len(results['models_available'])}")

    if results['models_available']:
        print("\nInstalled Models:")
        for model in results['models_available']:
            size_gb = model.get('size', 0) / (1024**3)
            print(f"  - {model['name']:40s} ({size_gb:.1f} GB)")

        recommended = checker.get_recommended_model()
        if recommended:
            print(f"\nRecommended for Code Analysis: {recommended}")

    if args.model:
        print(f"\nRequired Model '{args.model}': {'Found' if results['required_model_found'] else 'Not Found'}")

    # Print errors and warnings
    if results['errors']:
        print("\nErrors:")
        for error in results['errors']:
            print(f"  [!] {error}")

    if results['warnings']:
        print("\nWarnings:")
        for warning in results['warnings']:
            print(f"  [!] {warning}")

    print("\n" + "=" * 70)

    if success:
        print(" STATUS: OK - Ollama is ready for AI analysis")
        print("=" * 70 + "\n")
        sys.exit(0)
    else:
        print(" STATUS: FAIL - Ollama setup required")
        print("=" * 70 + "\n")
        print("Run with --setup for installation instructions")
        sys.exit(1)
