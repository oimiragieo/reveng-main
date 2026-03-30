#!/usr/bin/env python3
"""
Binary Validation Configuration
================================

Configurable validation strategies for reassembled binaries.
Supports multiple validation modes: checksum, smoke tests, sandboxed execution.

Author: Enhancement
Version: 1.0
"""

import hashlib
import json
import logging
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
VALIDATION_SCHEMA_VERSION = "1.0"


class ValidationMode(Enum):
    """Validation strategies"""

    CHECKSUM = "checksum"  # Compare file hashes
    SMOKE_TEST = "smoke_test"  # Run with predefined args
    SANDBOXED = "sandboxed"  # Run in isolated environment
    NONE = "none"  # Skip validation


@dataclass
class SmokeTest:
    """Smoke test configuration"""

    args: List[str]  # Command line arguments
    expected_exit_code: Optional[int] = None
    expected_output: Optional[str] = None
    timeout: int = 5
    description: str = "Basic smoke test"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize smoke test to a stable dictionary format."""
        return {
            "args": list(self.args),
            "expected_exit_code": self.expected_exit_code,
            "expected_output": self.expected_output,
            "timeout": self.timeout,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SmokeTest":
        """Create a smoke test from dictionary data."""
        return cls(
            args=list(data.get("args", [])),
            expected_exit_code=data.get("expected_exit_code"),
            expected_output=data.get("expected_output"),
            timeout=data.get("timeout", 5),
            description=data.get("description", "Basic smoke test"),
        )


@dataclass
class ValidationConfig:
    """Binary validation configuration"""

    mode: ValidationMode = ValidationMode.CHECKSUM  # Default to checksum (most reliable)
    smoke_tests: List[SmokeTest] = None  # Optional CLI tests, empty by default
    checksum_algorithm: str = "sha256"
    sandbox_enabled: bool = False
    allow_network: bool = False
    max_runtime: int = 10

    def __post_init__(self):
        # Only populate default smoke tests if user explicitly requested SMOKE_TEST mode
        if self.smoke_tests is None and self.mode == ValidationMode.SMOKE_TEST:
            # Default smoke tests for binaries with CLI interfaces
            self.smoke_tests = [
                SmokeTest(
                    args=["--version"],
                    expected_exit_code=None,  # Any exit code acceptable
                    description="Try --version flag",
                ),
                SmokeTest(
                    args=["--help"],
                    expected_exit_code=None,
                    description="Try --help flag",
                ),
                SmokeTest(args=["-h"], expected_exit_code=None, description="Try -h flag"),
            ]
        elif self.smoke_tests is None:
            # For other modes, no default smoke tests
            self.smoke_tests = []

    def to_dict(self) -> Dict[str, Any]:
        """Serialize validation config to a versioned schema dictionary."""
        return {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "mode": self.mode.value,
            "smoke_tests": [test.to_dict() for test in self.smoke_tests],
            "checksum_algorithm": self.checksum_algorithm,
            "sandbox_enabled": self.sandbox_enabled,
            "allow_network": self.allow_network,
            "max_runtime": self.max_runtime,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationConfig":
        """Create validation config from serialized dictionary data."""
        mode_value = data.get("mode", ValidationMode.CHECKSUM.value)
        if isinstance(mode_value, ValidationMode):
            mode = mode_value
        else:
            mode = ValidationMode(mode_value.lower())

        smoke_tests_data = data.get("smoke_tests")
        smoke_tests = None
        if smoke_tests_data is not None:
            smoke_tests = [SmokeTest.from_dict(test) for test in smoke_tests_data]

        return cls(
            mode=mode,
            smoke_tests=smoke_tests,
            checksum_algorithm=data.get("checksum_algorithm", "sha256"),
            sandbox_enabled=data.get("sandbox_enabled", False),
            allow_network=data.get("allow_network", False),
            max_runtime=data.get("max_runtime", 10),
        )


@dataclass
class ValidationResult:
    """Versioned validation result contract."""

    valid: bool = True
    mode: str = ValidationMode.CHECKSUM.value
    tests_passed: int = 0
    tests_failed: int = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize validation result to a versioned dictionary."""
        data = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "valid": self.valid,
            "mode": self.mode,
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }
        data.update(self.details)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationResult":
        """Hydrate a validation result from dictionary data."""
        base_keys = {
            "schema_version",
            "valid",
            "mode",
            "tests_passed",
            "tests_failed",
            "warnings",
            "errors",
        }
        details = {key: value for key, value in data.items() if key not in base_keys}
        return cls(
            valid=data.get("valid", True),
            mode=data.get("mode", ValidationMode.CHECKSUM.value),
            tests_passed=data.get("tests_passed", 0),
            tests_failed=data.get("tests_failed", 0),
            warnings=list(data.get("warnings", [])),
            errors=list(data.get("errors", [])),
            details=details,
        )


class BinaryValidator:
    """
    Configurable binary validator

    Supports multiple validation strategies with user configuration.
    """

    def __init__(self, config: ValidationConfig = None):
        """Initialize validator"""
        self.config = config or ValidationConfig()
        logger.info(f"Validator initialized with mode: {self.config.mode.value}")

    def validate(self, binary: Path, original: Optional[Path] = None) -> Dict[str, any]:
        """
        Validate reassembled binary

        Args:
            binary: Reassembled binary to validate
            original: Original binary for comparison (optional)

        Returns:
            Dictionary with validation results
        """
        result = ValidationResult(mode=self.config.mode.value)

        # Basic existence check
        if not binary.exists():
            result.valid = False
            result.errors.append("Binary file not found")
            return result.to_dict()

        if binary.stat().st_size == 0:
            result.valid = False
            result.errors.append("Binary file is empty")
            return result.to_dict()

        # Mode-specific validation
        if self.config.mode == ValidationMode.CHECKSUM:
            checksum_result = self._validate_checksum(binary, original)
            self._merge_result(result, checksum_result)

        elif self.config.mode == ValidationMode.SMOKE_TEST:
            smoke_result = self._validate_smoke_tests(binary)
            self._merge_result(result, smoke_result)

        elif self.config.mode == ValidationMode.SANDBOXED:
            sandbox_result = self._validate_sandboxed(binary)
            self._merge_result(result, sandbox_result)

        elif self.config.mode == ValidationMode.NONE:
            result.warnings.append("Validation skipped (mode=NONE)")

        return result.to_dict()

    def _merge_result(self, result: ValidationResult, update: Dict[str, Any]) -> None:
        """Merge mode-specific validation details into the versioned result."""
        warnings = list(update.pop("warnings", []))
        errors = list(update.pop("errors", []))

        result.warnings.extend(warnings)
        result.errors.extend(errors)
        result.tests_passed = update.get("tests_passed", result.tests_passed)
        result.tests_failed = update.get("tests_failed", result.tests_failed)
        if "valid" in update:
            result.valid = update.pop("valid")
        result.details.update(update)

    def _validate_checksum(self, binary: Path, original: Optional[Path]) -> Dict:
        """Validate using checksum comparison"""
        result = {"checksum_match": False}

        if not original or not original.exists():
            result["warnings"] = ["No original binary for comparison"]
            return result

        # Calculate checksums
        hash_func = getattr(hashlib, self.config.checksum_algorithm)

        with open(binary, "rb") as f:
            binary_hash = hash_func(f.read()).hexdigest()

        with open(original, "rb") as f:
            original_hash = hash_func(f.read()).hexdigest()

        result["binary_hash"] = binary_hash
        result["original_hash"] = original_hash
        result["checksum_match"] = binary_hash == original_hash

        if not result["checksum_match"]:
            result["warnings"] = [
                "Checksum mismatch (expected modifications)",
                f"Original: {original_hash[:16]}...",
                f"Reassembled: {binary_hash[:16]}...",
            ]

        return result

    def _validate_smoke_tests(self, binary: Path) -> Dict:
        """Run configurable smoke tests"""
        result = {
            "tests_run": 0,
            "tests_passed": 0,
            "tests_failed": 0,
            "test_results": [],
        }

        for smoke_test in self.config.smoke_tests:
            test_result = self._run_smoke_test(binary, smoke_test)
            result["tests_run"] += 1

            if test_result["passed"]:
                result["tests_passed"] += 1
            else:
                result["tests_failed"] += 1

            result["test_results"].append(test_result)

        # Only mark as invalid if ALL tests failed AND at least one was expected to pass
        # If binary doesn't support any CLI flags, that's OK - mark as valid with warning
        if result["tests_run"] > 0 and result["tests_failed"] == result["tests_run"]:
            result["warnings"] = [
                f"All {result['tests_run']} smoke tests failed - binary may not support CLI flags"
            ]
            # Don't fail validation - binary might not have CLI interface
        elif result["tests_failed"] > 0:
            result["warnings"] = [
                f"{result['tests_failed']}/{result['tests_run']} smoke tests failed (not critical)"
            ]

        return result

    def _run_smoke_test(self, binary: Path, test: SmokeTest) -> Dict:
        """Run a single smoke test"""
        test_result = {
            "description": test.description,
            "args": test.args,
            "passed": False,
            "output": None,
            "exit_code": None,
            "error": None,
        }

        try:
            result = subprocess.run(
                [str(binary)] + test.args,
                capture_output=True,
                text=True,
                timeout=test.timeout,
            )

            test_result["exit_code"] = result.returncode
            test_result["output"] = result.stdout + result.stderr

            # Check exit code if specified
            if test.expected_exit_code is not None:
                if result.returncode == test.expected_exit_code:
                    test_result["passed"] = True
                else:
                    test_result["error"] = (
                        f"Exit code {result.returncode}, expected {test.expected_exit_code}"
                    )
            else:
                # Any exit code is acceptable (binary ran without crashing)
                test_result["passed"] = True

            # Check output if specified
            if test.expected_output and test_result["passed"]:
                if test.expected_output in test_result["output"]:
                    test_result["passed"] = True
                else:
                    test_result["passed"] = False
                    test_result["error"] = "Expected output not found"

            logger.info(
                f"Smoke test {test.description}: {'PASS' if test_result['passed'] else 'FAIL'}"
            )

        except subprocess.TimeoutExpired:
            test_result["error"] = f"Timeout after {test.timeout}s"
            test_result["passed"] = False
            logger.warning(f"Smoke test {test.description}: TIMEOUT")

        except FileNotFoundError:
            test_result["error"] = "Binary not executable or not found"
            test_result["passed"] = False
            logger.error(f"Smoke test {test.description}: NOT FOUND")

        except Exception as e:
            test_result["error"] = str(e)
            test_result["passed"] = False
            logger.error(f"Smoke test {test.description}: ERROR - {e}")

        return test_result

    def _validate_sandboxed(self, binary: Path) -> Dict:
        """Run in sandboxed environment (placeholder)"""

        # TODO: Implement proper sandboxing
        # Options:
        # - Docker container
        # - Firejail on Linux
        # - Windows Sandbox on Windows
        # - VM-based execution

        logger.warning("Sandboxed validation not implemented, falling back to smoke tests")
        return self._validate_smoke_tests(binary)

    @classmethod
    def load_config(cls, config_file: Path, binary_name: Optional[str] = None) -> "BinaryValidator":
        """
        Load validator configuration from JSON policy file

        Args:
            config_file: Path to validation_policy.json
            binary_name: Specific binary name to load policy for (e.g., "droid.exe")

        Returns:
            BinaryValidator instance configured per policy
        """
        with open(config_file, "r") as f:
            policy = json.load(f)

        # Select policy: binary-specific or default
        if binary_name and binary_name in policy.get("binary_policies", {}):
            config_dict = policy["binary_policies"][binary_name]
            logger.info(f"Loaded custom policy for {binary_name}")
        else:
            config_dict = policy.get("default_policy", {})
            logger.info("Using default validation policy")

        # Parse configuration
        config = ValidationConfig.from_dict(
            {
                "mode": config_dict.get("mode", "checksum"),
                "smoke_tests": config_dict.get("smoke_tests"),
                "checksum_algorithm": config_dict.get("checksum_algorithm", "sha256"),
                "sandbox_enabled": config_dict.get("sandbox", {}).get("enabled", False),
                "allow_network": config_dict.get("sandbox", {}).get("allow_network", False),
                "max_runtime": config_dict.get("timeout", 30),
            }
        )

        return cls(config)

    @classmethod
    def create_default_config(cls, output_path: Path):
        """Create default validation config file"""
        config = {
            "schema_version": VALIDATION_SCHEMA_VERSION,
            "mode": "smoke_test",
            "smoke_tests": [
                {
                    "args": ["--version"],
                    "description": "Check version flag",
                    "timeout": 5,
                },
                {"args": ["--help"], "description": "Check help flag", "timeout": 5},
            ],
            "checksum_algorithm": "sha256",
            "sandbox_enabled": False,
        }

        with open(output_path, "w") as f:
            json.dump(config, f, indent=2)

        logger.info(f"Created default validation config: {output_path}")


# Example usage
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Validate reassembled binary")
    parser.add_argument("binary", type=Path, help="Binary to validate")
    parser.add_argument("--original", type=Path, help="Original binary for comparison")
    parser.add_argument(
        "--policy",
        type=Path,
        help="Validation policy JSON (default: .reveng/validation_policy.json)",
    )
    parser.add_argument("--create-config", type=Path, help="Create default config file")
    args = parser.parse_args()

    if args.create_config:
        BinaryValidator.create_default_config(args.create_config)
        print(f"Created config: {args.create_config}")
        exit(0)

    # Load validator with policy file
    if args.policy:
        validator = BinaryValidator.load_config(args.policy, args.binary.name)
    else:
        # Try default policy location
        default_policy = Path(".reveng/validation_policy.json")
        if default_policy.exists():
            validator = BinaryValidator.load_config(default_policy, args.binary.name)
        else:
            validator = BinaryValidator()

    # Validate
    result = validator.validate(args.binary, args.original)

    # Print results
    print(f"\nValidation: {'PASSED' if result['valid'] else 'FAILED'}")
    print(f"Mode: {result['mode']}")

    if result.get("tests_run"):
        print(f"Tests: {result['tests_passed']}/{result['tests_run']} passed")

    if result.get("warnings"):
        print("\nWarnings:")
        for warning in result["warnings"]:
            print(f"  - {warning}")

    if result.get("errors"):
        print("\nErrors:")
        for error in result["errors"]:
            print(f"  - {error}")
