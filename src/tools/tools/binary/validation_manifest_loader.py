#!/usr/bin/env python3
"""
REVENG Validation Manifest Loader
==================================

Loads external validation configuration from YAML/JSON files.

Supports:
- Per-binary validation rules
- Custom smoke tests
- Sandboxed execution config
- Checksum allowances

Usage:
    from validation_manifest_loader import load_validation_manifest

    config = load_validation_manifest("binary.exe")
    validator = BinaryValidator(config)
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import fnmatch

# Try to import YAML support
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logging.warning("PyYAML not installed - only JSON manifests supported")
    logging.warning("Install with: pip install pyyaml")

from validation_config import ValidationConfig, ValidationMode, SmokeTest

logger = logging.getLogger(__name__)


class ValidationManifestLoader:
    """Load validation manifests from YAML/JSON"""

    DEFAULT_PATHS = [
        Path(".reveng/validation.yaml"),
        Path(".reveng/validation.yml"),
        Path(".reveng/validation.json"),
        Path("validation.yaml"),
        Path("validation.yml"),
        Path("validation.json")
    ]

    def __init__(self, manifest_path: Optional[Path] = None):
        """Initialize loader"""
        self.manifest_path = manifest_path
        self.manifest_data = None

        if manifest_path:
            self.load(manifest_path)
        else:
            # Try to auto-detect manifest
            self._auto_load()

    def _auto_load(self):
        """Automatically load manifest from default paths"""
        for path in self.DEFAULT_PATHS:
            if path.exists():
                logger.info(f"Found validation manifest: {path}")
                self.load(path)
                return

        logger.debug("No validation manifest found, using defaults")

    def load(self, path: Path):
        """Load manifest from file"""
        try:
            with open(path, 'r', encoding='utf-8') as f:
                if path.suffix in ['.yaml', '.yml']:
                    if not HAS_YAML:
                        raise ImportError("PyYAML not installed")
                    self.manifest_data = yaml.safe_load(f)
                elif path.suffix == '.json':
                    self.manifest_data = json.load(f)
                else:
                    raise ValueError(f"Unsupported format: {path.suffix}")

            logger.info(f"Loaded validation manifest: {path}")
            self.manifest_path = path

        except Exception as e:
            logger.error(f"Failed to load manifest {path}: {e}")
            self.manifest_data = None

    def get_config_for_binary(self, binary_name: str) -> ValidationConfig:
        """Get validation config for a specific binary"""
        if not self.manifest_data:
            # No manifest - use defaults
            return ValidationConfig()

        # Get default mode
        default_mode_str = self.manifest_data.get('default_mode', 'checksum')
        default_mode = self._parse_mode(default_mode_str)

        # Get global settings
        global_settings = self.manifest_data.get('global', {})
        max_runtime = global_settings.get('max_runtime', 10)
        allow_network = global_settings.get('allow_network', False)
        sandbox_enabled = global_settings.get('sandbox_enabled', False)

        # Check for binary-specific config
        binaries = self.manifest_data.get('binaries', {})
        binary_config = self._find_binary_config(binary_name, binaries)

        if binary_config:
            # Use binary-specific settings
            mode = self._parse_mode(binary_config.get('mode', default_mode_str))
            smoke_tests = self._parse_smoke_tests(binary_config.get('smoke_tests', []))
            checksum_algorithm = binary_config.get('checksum_algorithm', 'sha256')
        else:
            # Use defaults
            mode = default_mode
            smoke_tests = None  # Will be populated by ValidationConfig if mode is SMOKE_TEST
            checksum_algorithm = 'sha256'

        return ValidationConfig(
            mode=mode,
            smoke_tests=smoke_tests,
            checksum_algorithm=checksum_algorithm,
            sandbox_enabled=sandbox_enabled,
            allow_network=allow_network,
            max_runtime=max_runtime
        )

    def _find_binary_config(self, binary_name: str, binaries: Dict) -> Optional[Dict]:
        """Find config for binary (supports glob patterns)"""
        # First try exact match
        if binary_name in binaries:
            return binaries[binary_name]

        # Try glob patterns
        for pattern, config in binaries.items():
            if fnmatch.fnmatch(binary_name, pattern):
                logger.info(f"Binary {binary_name} matches pattern {pattern}")
                return config

        return None

    def _parse_mode(self, mode_str: str) -> ValidationMode:
        """Parse validation mode from string"""
        mode_map = {
            'checksum': ValidationMode.CHECKSUM,
            'smoke_test': ValidationMode.SMOKE_TEST,
            'sandboxed': ValidationMode.SANDBOXED,
            'none': ValidationMode.NONE
        }

        mode = mode_map.get(mode_str.lower(), ValidationMode.CHECKSUM)
        return mode

    def _parse_smoke_tests(self, tests: List[Dict]) -> List[SmokeTest]:
        """Parse smoke tests from manifest"""
        smoke_tests = []

        for test in tests:
            smoke_test = SmokeTest(
                args=test.get('args', []),
                expected_exit_code=test.get('expected_exit_code'),
                timeout=test.get('timeout', 5),
                description=test.get('description', 'Custom smoke test')
            )
            smoke_tests.append(smoke_test)

        return smoke_tests if smoke_tests else None

    def get_sandbox_config(self) -> Optional[Dict]:
        """Get sandbox configuration"""
        if not self.manifest_data:
            return None

        return self.manifest_data.get('sandbox')

    def get_hooks(self) -> Optional[Dict]:
        """Get validation hooks"""
        if not self.manifest_data:
            return None

        return self.manifest_data.get('hooks')

    def get_checksum_allowances(self) -> Optional[Dict]:
        """Get checksum allowances"""
        if not self.manifest_data:
            return None

        return self.manifest_data.get('checksum_allowances')


def load_validation_manifest(
    binary_name: Optional[str] = None,
    manifest_path: Optional[Path] = None
) -> ValidationConfig:
    """
    Load validation config from manifest file.

    Args:
        binary_name: Name of binary to get config for
        manifest_path: Path to manifest file (auto-detects if None)

    Returns:
        ValidationConfig instance
    """
    loader = ValidationManifestLoader(manifest_path)

    if binary_name:
        return loader.get_config_for_binary(binary_name)
    else:
        # Return default config
        return loader.get_config_for_binary("default")


# Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) > 1:
        binary = sys.argv[1]
    else:
        binary = "test.exe"

    print(f"Loading validation config for: {binary}")
    print()

    config = load_validation_manifest(binary)

    print(f"Mode: {config.mode.value}")
    print(f"Smoke tests: {len(config.smoke_tests) if config.smoke_tests else 0}")
    print(f"Max runtime: {config.max_runtime}s")
    print(f"Checksum algorithm: {config.checksum_algorithm}")
    print(f"Sandbox enabled: {config.sandbox_enabled}")
    print(f"Allow network: {config.allow_network}")

    if config.smoke_tests:
        print()
        print("Smoke Tests:")
        for i, test in enumerate(config.smoke_tests, 1):
            print(f"  {i}. {test.description}")
            print(f"     Args: {' '.join(test.args)}")
            print(f"     Expected exit: {test.expected_exit_code if test.expected_exit_code else 'any'}")
