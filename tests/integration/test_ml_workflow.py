"""Integration tests for the current ML workflow API."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from reveng.ml.anomaly_detection import AnomalyType
from reveng.ml.code_reconstruction import ModelType
from reveng.ml.integration import MLIntegration, MLIntegrationConfig


@pytest.fixture
def sample_binary(tmp_path):
    """Create a small PE-like binary for workflow tests."""
    binary_path = tmp_path / "test.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 1024)
    return binary_path


@pytest.fixture
def sample_analysis_data():
    """Representative analysis payload consumed by MLIntegration."""
    return {
        "disassembly": {
            "instructions": [
                {
                    "address": 0x401000,
                    "size": 2,
                    "mnemonic": "call eax",
                    "bytes": "90ab",
                    "function": "entry",
                }
            ]
        },
        "functions": [
            {
                "address": 0x401100,
                "size": 16,
                "disassembly": "int main(void) { return 0; }",
                "name": "main",
            }
        ],
        "imports": ["CreateFileA"],
        "strings": ["hello"],
    }


@pytest.fixture
def ml_integration(tmp_path):
    """Construct MLIntegration with mocked heavy dependencies."""
    with (
        patch("reveng.ml.integration.MLCodeReconstruction") as mock_reconstruction_cls,
        patch("reveng.ml.integration.MLAnomalyDetection") as mock_anomaly_cls,
    ):
        mock_reconstruction = MagicMock()
        mock_reconstruction.models = {}
        mock_anomaly = MagicMock()
        mock_anomaly.models = {}

        mock_reconstruction_cls.return_value = mock_reconstruction
        mock_anomaly_cls.return_value = mock_anomaly

        config = MLIntegrationConfig(output_directory=str(tmp_path / "ml_output"))
        integration = MLIntegration(config)

        yield integration, mock_reconstruction, mock_anomaly


class TestMLWorkflow:
    """Integration tests for MLIntegration's current public behavior."""

    def test_full_ml_analysis_workflow(self, ml_integration, sample_binary, sample_analysis_data):
        """Enabled components should populate the structured ml_analysis payload."""
        integration, _, _ = ml_integration

        reconstruction_result = {"summary": {"total_reconstructions": 1}}
        anomaly_result = {"summary": {"total_anomalies": 1}}
        threat_result = {"summary": {"total_threats": 1}}

        with (
            patch.object(
                integration,
                "_perform_code_reconstruction",
                return_value=reconstruction_result,
            ) as mock_reconstruction,
            patch.object(
                integration,
                "_perform_anomaly_detection",
                return_value=anomaly_result,
            ) as mock_anomaly,
            patch.object(
                integration,
                "_generate_threat_intelligence",
                return_value=threat_result,
            ) as mock_threat,
            patch.object(integration, "_save_ml_results", return_value=True) as mock_save,
        ):
            result = integration.analyze_binary(str(sample_binary), sample_analysis_data)

        assert result["binary_path"] == str(sample_binary)
        assert "analysis_timestamp" in result
        assert result["ml_analysis"] == {
            "code_reconstruction": reconstruction_result,
            "anomaly_detection": anomaly_result,
            "threat_intelligence": threat_result,
        }
        mock_reconstruction.assert_called_once_with(str(sample_binary), sample_analysis_data)
        mock_anomaly.assert_called_once_with(sample_analysis_data)
        mock_threat.assert_called_once_with(sample_analysis_data)
        saved_results, saved_binary_path = mock_save.call_args[0]
        assert saved_results == result
        assert saved_binary_path == str(sample_binary)

    def test_disabled_components_are_skipped(self, sample_binary, sample_analysis_data, tmp_path):
        """Boolean config flags should disable optional ML stages cleanly."""
        with (
            patch("reveng.ml.integration.MLCodeReconstruction") as mock_reconstruction_cls,
            patch("reveng.ml.integration.MLAnomalyDetection") as mock_anomaly_cls,
        ):
            config = MLIntegrationConfig(
                enable_code_reconstruction=False,
                enable_anomaly_detection=False,
                enable_threat_intelligence=False,
                output_directory=str(tmp_path / "disabled_output"),
                save_intermediate_results=False,
            )
            integration = MLIntegration(config)

        result = integration.analyze_binary(str(sample_binary), sample_analysis_data)

        assert integration.code_reconstruction is None
        assert integration.anomaly_detection is None
        assert result["ml_analysis"] == {}
        mock_reconstruction_cls.assert_not_called()
        mock_anomaly_cls.assert_not_called()

    def test_analysis_can_skip_saving_results(
        self, ml_integration, sample_binary, sample_analysis_data
    ):
        """save_intermediate_results=False should avoid the persistence step."""
        integration, _, _ = ml_integration
        integration.config.save_intermediate_results = False

        with (
            patch.object(
                integration,
                "_perform_code_reconstruction",
                return_value={"summary": {"total_reconstructions": 1}},
            ),
            patch.object(
                integration,
                "_perform_anomaly_detection",
                return_value={"summary": {"total_anomalies": 0}},
            ),
            patch.object(
                integration,
                "_generate_threat_intelligence",
                return_value={"summary": {"total_threats": 0}},
            ),
            patch.object(integration, "_save_ml_results", return_value=True) as mock_save,
        ):
            result = integration.analyze_binary(str(sample_binary), sample_analysis_data)

        assert "code_reconstruction" in result["ml_analysis"]
        mock_save.assert_not_called()

    def test_extract_code_fragments_combines_disassembly_and_functions(
        self, ml_integration, sample_analysis_data
    ):
        """Fragment extraction should preserve addresses, bytes, and function context."""
        integration, _, _ = ml_integration

        fragments = integration._extract_code_fragments(sample_analysis_data)

        assert len(fragments) == 2
        assert fragments[0].address == 0x401000
        assert fragments[0].hex_data == bytes.fromhex("90ab")
        assert fragments[0].context["function"] == "entry"
        assert fragments[1].address == 0x401100
        assert fragments[1].context["function_name"] == "main"

    def test_get_model_status_reports_loaded_models(self, ml_integration):
        """Model status output should match the current serialized shape."""
        integration, mock_reconstruction, mock_anomaly = ml_integration

        mock_reconstruction.models = {
            ModelType.CODEBERT: {
                "loaded": True,
                "local": True,
                "config": {"model_name": "microsoft/codebert-base"},
            }
        }
        mock_anomaly.models = {
            "behavioral": SimpleNamespace(
                name="Behavioral Anomaly Detector",
                type=AnomalyType.BEHAVIORAL,
                features=["api_entropy"],
                threshold=0.7,
                performance={"accuracy": 0.85},
            )
        }

        status = integration.get_model_status()

        assert status["code_reconstruction"]["available"] is True
        assert status["code_reconstruction"]["models"]["codebert"]["loaded"] is True
        assert status["anomaly_detection"]["models"]["behavioral"]["type"] == "behavioral"
        assert status["anomaly_detection"]["models"]["behavioral"]["threshold"] == 0.7

    def test_get_model_status_returns_error_payload_on_failure(self, ml_integration):
        """Unexpected model-status errors should be surfaced as an error dict."""
        integration, _, _ = ml_integration
        integration.code_reconstruction = SimpleNamespace()

        status = integration.get_model_status()

        assert "error" in status
        assert "models" in status["error"]

    def test_update_config_can_enable_components_after_startup(self, tmp_path):
        """update_config should initialize newly-enabled components and output paths."""
        with (
            patch("reveng.ml.integration.MLCodeReconstruction") as mock_reconstruction_cls,
            patch("reveng.ml.integration.MLAnomalyDetection") as mock_anomaly_cls,
        ):
            mock_reconstruction = MagicMock()
            mock_anomaly = MagicMock()
            mock_reconstruction_cls.return_value = mock_reconstruction
            mock_anomaly_cls.return_value = mock_anomaly

            initial_config = MLIntegrationConfig(
                enable_code_reconstruction=False,
                enable_anomaly_detection=False,
                output_directory=str(tmp_path / "initial_output"),
            )
            integration = MLIntegration(initial_config)

            updated_config = MLIntegrationConfig(
                enable_code_reconstruction=True,
                enable_anomaly_detection=True,
                output_directory=str(tmp_path / "updated_output"),
            )

            assert integration.update_config(updated_config) is True

        assert integration.code_reconstruction is mock_reconstruction
        assert integration.anomaly_detection is mock_anomaly
        assert (tmp_path / "updated_output").exists()

    def test_update_config_returns_false_when_component_init_fails(self, tmp_path):
        """Initialization failures during config updates should return False, not raise."""
        with (
            patch(
                "reveng.ml.integration.MLCodeReconstruction",
                side_effect=RuntimeError("reconstruction init failed"),
            ),
            patch("reveng.ml.integration.MLAnomalyDetection") as mock_anomaly_cls,
        ):
            initial_config = MLIntegrationConfig(
                enable_code_reconstruction=False,
                enable_anomaly_detection=False,
                output_directory=str(tmp_path / "initial_output"),
            )
            integration = MLIntegration(initial_config)

            updated_config = MLIntegrationConfig(
                enable_code_reconstruction=True,
                enable_anomaly_detection=False,
                output_directory=str(tmp_path / "updated_output"),
            )

            assert integration.update_config(updated_config) is False
            mock_anomaly_cls.assert_not_called()
