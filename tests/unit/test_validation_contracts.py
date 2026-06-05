from pathlib import Path

from reveng.tools.binary.validation_config import (
    BinaryValidator,
    SmokeTest,
    ValidationConfig,
    ValidationMode,
    ValidationResult,
)
from reveng.tools.binary.validation_manifest_loader import ValidationManifestLoader


def test_validation_config_round_trip_preserves_schema_and_smoke_tests():
    config = ValidationConfig(
        mode=ValidationMode.SMOKE_TEST,
        smoke_tests=[
            SmokeTest(
                args=["--help"],
                expected_exit_code=0,
                expected_output="usage",
                timeout=9,
                description="help smoke",
            )
        ],
        checksum_algorithm="sha512",
        sandbox_enabled=True,
        allow_network=False,
        max_runtime=42,
    )

    serialized = config.to_dict()
    restored = ValidationConfig.from_dict(serialized)

    assert serialized["schema_version"] == "1.0"
    assert restored.mode == ValidationMode.SMOKE_TEST
    assert restored.checksum_algorithm == "sha512"
    assert restored.sandbox_enabled is True
    assert restored.max_runtime == 42
    assert len(restored.smoke_tests) == 1
    assert restored.smoke_tests[0].to_dict() == config.smoke_tests[0].to_dict()


def test_validation_result_round_trip_preserves_details():
    result = ValidationResult(
        valid=True,
        mode="none",
        warnings=["skipped"],
        details={"tests_run": 0, "custom_flag": True},
    )

    serialized = result.to_dict()
    restored = ValidationResult.from_dict(serialized)

    assert serialized["schema_version"] == "1.0"
    assert restored.mode == "none"
    assert restored.warnings == ["skipped"]
    assert restored.details["tests_run"] == 0
    assert restored.details["custom_flag"] is True


def test_binary_validator_returns_versioned_result_dict(tmp_path: Path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"MZ\x00\x01")

    validator = BinaryValidator(ValidationConfig(mode=ValidationMode.NONE))
    result = validator.validate(binary)

    assert result["schema_version"] == "1.0"
    assert result["valid"] is True
    assert result["mode"] == "none"
    assert "Validation skipped (mode=NONE)" in result["warnings"]


def test_validation_manifest_loader_builds_versioned_binary_specific_config(tmp_path: Path):
    manifest_path = tmp_path / "validation.json"
    manifest_path.write_text(
        """
{
  "default_mode": "checksum",
  "global": {
    "max_runtime": 15,
    "allow_network": false,
    "sandbox_enabled": true
  },
  "binaries": {
    "*.exe": {
      "mode": "smoke_test",
      "checksum_algorithm": "sha512",
      "smoke_tests": [
        {
          "args": ["--version"],
          "expected_exit_code": 0,
          "description": "version smoke"
        }
      ]
    }
  }
}
        """.strip(),
        encoding="utf-8",
    )

    loader = ValidationManifestLoader(manifest_path)
    config = loader.get_config_for_binary("demo.exe")

    assert config.mode == ValidationMode.SMOKE_TEST
    assert config.checksum_algorithm == "sha512"
    assert config.sandbox_enabled is True
    assert config.max_runtime == 15
    assert config.to_dict()["schema_version"] == "1.0"
    assert config.smoke_tests[0].description == "version smoke"
