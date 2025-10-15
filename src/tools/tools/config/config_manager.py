#!/usr/bin/env python3
"""
REVENG Configuration Manager
=============================

Manages REVENG configuration from YAML file with environment variable support.
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class AIConfig:
    """AI/LLM configuration"""
    provider: str
    enable_ai: bool
    fallback_to_heuristics: bool
    max_ai_functions: int
    batch_size: int
    show_progress: bool

    # Ollama
    ollama_host: str
    ollama_model: str
    ollama_timeout: int
    ollama_temperature: float
    ollama_max_tokens: int

    # Anthropic
    anthropic_api_key: Optional[str]
    anthropic_model: str
    anthropic_max_tokens: int

    # OpenAI
    openai_api_key: Optional[str]
    openai_model: str
    openai_max_tokens: int


@dataclass
class GhidraConfig:
    """Ghidra MCP configuration"""
    enabled: bool
    mcp_url: str
    timeout: int
    fallback: bool


@dataclass
class ValidationConfig:
    """Validation configuration"""
    default_mode: str
    smoke_test_timeout: int
    use_lief: bool


@dataclass
class CompilationConfig:
    """Compilation configuration"""
    auto_detect_compiler: bool
    preferred_compiler: str
    platform_aware: bool
    test_during_pipeline: bool


@dataclass
class SecurityConfig:
    """Security configuration"""
    enable_security_analysis: bool
    security_errors: bool
    defang_iocs: bool


class ConfigManager:
    """Manage REVENG configuration"""

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize configuration manager

        Args:
            config_path: Path to config.yaml (default: .reveng/config.yaml)
        """
        if config_path is None:
            config_path = Path(".reveng/config.yaml")

        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            logger.warning(f"Config file not found: {self.config_path}")
            logger.info("Using default configuration")
            return self._get_default_config()

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)

            # Expand environment variables
            config = self._expand_env_vars(config)

            logger.info(f"Loaded configuration from {self.config_path}")
            return config

        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            return self._get_default_config()

    def _expand_env_vars(self, config: Any) -> Any:
        """Recursively expand ${VAR} environment variables in config"""
        if isinstance(config, dict):
            return {k: self._expand_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self._expand_env_vars(item) for item in config]
        elif isinstance(config, str):
            # Replace ${VAR} with environment variable value
            if config.startswith('${') and config.endswith('}'):
                var_name = config[2:-1]
                return os.environ.get(var_name, '')
            return config
        else:
            return config

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'ai': {
                'provider': 'ollama',
                'ollama': {
                    'host': 'http://localhost:11434',
                    'model': 'auto',
                    'timeout': 60,
                    'temperature': 0.1,
                    'max_tokens': 500
                }
            },
            'analysis': {
                'enable_ai': True,
                'fallback_to_heuristics': True,
                'max_ai_functions': 0,
                'batch_size': 10,
                'show_progress': True
            },
            'ghidra': {
                'enabled': True,
                'mcp_url': 'http://localhost:13337',
                'timeout': 10,
                'fallback': True
            },
            'validation': {
                'default_mode': 'checksum',
                'smoke_test_timeout': 30,
                'use_lief': True
            },
            'compilation': {
                'auto_detect_compiler': True,
                'preferred_compiler': 'auto',
                'platform_aware': True,
                'test_during_pipeline': False
            },
            'security': {
                'enable_security_analysis': True,
                'security_errors': False,
                'defang_iocs': True
            }
        }

    def get_ai_config(self) -> AIConfig:
        """Get AI configuration"""
        ai = self.config.get('ai', {})
        analysis = self.config.get('analysis', {})
        ollama = ai.get('ollama', {})
        anthropic = ai.get('anthropic', {})
        openai = ai.get('openai', {})

        return AIConfig(
            provider=ai.get('provider', 'ollama'),
            enable_ai=analysis.get('enable_ai', True),
            fallback_to_heuristics=analysis.get('fallback_to_heuristics', True),
            max_ai_functions=analysis.get('max_ai_functions', 0),
            batch_size=analysis.get('batch_size', 10),
            show_progress=analysis.get('show_progress', True),
            ollama_host=ollama.get('host', 'http://localhost:11434'),
            ollama_model=ollama.get('model', 'auto'),
            ollama_timeout=ollama.get('timeout', 60),
            ollama_temperature=ollama.get('temperature', 0.1),
            ollama_max_tokens=ollama.get('max_tokens', 500),
            anthropic_api_key=anthropic.get('api_key'),
            anthropic_model=anthropic.get('model', 'claude-3-5-sonnet-20241022'),
            anthropic_max_tokens=anthropic.get('max_tokens', 4000),
            openai_api_key=openai.get('api_key'),
            openai_model=openai.get('model', 'gpt-4'),
            openai_max_tokens=openai.get('max_tokens', 4000)
        )

    def get_ghidra_config(self) -> GhidraConfig:
        """Get Ghidra configuration"""
        ghidra = self.config.get('ghidra', {})

        return GhidraConfig(
            enabled=ghidra.get('enabled', True),
            mcp_url=ghidra.get('mcp_url', 'http://localhost:13337'),
            timeout=ghidra.get('timeout', 10),
            fallback=ghidra.get('fallback', True)
        )

    def get_validation_config(self) -> ValidationConfig:
        """Get validation configuration"""
        validation = self.config.get('validation', {})

        return ValidationConfig(
            default_mode=validation.get('default_mode', 'checksum'),
            smoke_test_timeout=validation.get('smoke_test_timeout', 30),
            use_lief=validation.get('use_lief', True)
        )

    def get_compilation_config(self) -> CompilationConfig:
        """Get compilation configuration"""
        compilation = self.config.get('compilation', {})

        return CompilationConfig(
            auto_detect_compiler=compilation.get('auto_detect_compiler', True),
            preferred_compiler=compilation.get('preferred_compiler', 'auto'),
            platform_aware=compilation.get('platform_aware', True),
            test_during_pipeline=compilation.get('test_during_pipeline', False)
        )

    def get_security_config(self) -> SecurityConfig:
        """Get security configuration"""
        security = self.config.get('security', {})

        return SecurityConfig(
            enable_security_analysis=security.get('enable_security_analysis', True),
            security_errors=security.get('security_errors', False),
            defang_iocs=security.get('defang_iocs', True)
        )

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by dot-notation key

        Example: config.get('ai.ollama.model')
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        Set configuration value by dot-notation key

        Example: config.set('ai.ollama.model', 'phi')
        """
        keys = key.split('.')
        target = self.config

        for k in keys[:-1]:
            if k not in target:
                target[k] = {}
            target = target[k]

        target[keys[-1]] = value

    def save(self, path: Optional[Path] = None):
        """Save configuration to YAML file"""
        if path is None:
            path = self.config_path

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, sort_keys=False)

        logger.info(f"Configuration saved to {path}")


# Global instance
_global_config = None


def get_config(config_path: Optional[Path] = None) -> ConfigManager:
    """Get global configuration instance"""
    global _global_config

    if _global_config is None:
        _global_config = ConfigManager(config_path)

    return _global_config


# CLI interface
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    config = ConfigManager()

    print("=" * 70)
    print("REVENG CONFIGURATION")
    print("=" * 70)
    print()

    # Display current configuration
    ai_config = config.get_ai_config()
    print("AI Configuration:")
    print(f"  Provider: {ai_config.provider}")
    print(f"  AI Enabled: {ai_config.enable_ai}")
    print(f"  Ollama Host: {ai_config.ollama_host}")
    print(f"  Ollama Model: {ai_config.ollama_model}")
    print()

    ghidra_config = config.get_ghidra_config()
    print("Ghidra Configuration:")
    print(f"  Enabled: {ghidra_config.enabled}")
    print(f"  MCP URL: {ghidra_config.mcp_url}")
    print(f"  Fallback: {ghidra_config.fallback}")
    print()

    if len(sys.argv) > 1:
        if sys.argv[1] == 'get':
            if len(sys.argv) > 2:
                key = sys.argv[2]
                value = config.get(key)
                print(f"{key} = {value}")

        elif sys.argv[1] == 'set':
            if len(sys.argv) > 3:
                key = sys.argv[2]
                value = sys.argv[3]
                config.set(key, value)
                config.save()
                print(f"Set {key} = {value}")

        elif sys.argv[1] == 'show':
            print("Full Configuration:")
            print("-" * 70)
            print(yaml.dump(config.config, default_flow_style=False))

    else:
        print("Usage:")
        print("  python config_manager.py get <key>")
        print("  python config_manager.py set <key> <value>")
        print("  python config_manager.py show")
        print()
        print("Examples:")
        print("  python config_manager.py get ai.ollama.model")
        print("  python config_manager.py set ai.ollama.model phi")

    print("=" * 70)
