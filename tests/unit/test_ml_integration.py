"""Characterization tests for the ML integration subsystem."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from reveng.ml.integration import MLIntegration, MLIntegrationConfig


class _EnumValue:
    def __init__(self, value: str):
        self.value = value


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_ml_integration_initialises_enabled_components(mock_anomaly_cls, mock_recon_cls, tmp_path):
    mock_recon_cls.return_value = MagicMock()
    mock_anomaly_cls.return_value = MagicMock()

    config = MLIntegrationConfig(output_directory=str(tmp_path))
    ml = MLIntegration(config)

    assert ml.code_reconstruction is mock_recon_cls.return_value
    assert ml.anomaly_detection is mock_anomaly_cls.return_value


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_ml_integration_skips_disabled_components(mock_anomaly_cls, mock_recon_cls, tmp_path):
    config = MLIntegrationConfig(
        enable_code_reconstruction=False,
        enable_anomaly_detection=False,
        output_directory=str(tmp_path),
    )

    ml = MLIntegration(config)

    assert ml.code_reconstruction is None
    assert ml.anomaly_detection is None
    mock_recon_cls.assert_not_called()
    mock_anomaly_cls.assert_not_called()


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_analyze_binary_returns_expected_sections(mock_anomaly_cls, mock_recon_cls, tmp_path):
    mock_recon_cls.return_value = MagicMock()
    mock_anomaly_cls.return_value = MagicMock()

    config = MLIntegrationConfig(output_directory=str(tmp_path), save_intermediate_results=False)
    ml = MLIntegration(config)

    with (
        patch.object(
            ml,
            "_perform_code_reconstruction",
            return_value={"reconstructions": [], "summary": {}},
        ) as mock_reconstruction,
        patch.object(
            ml,
            "_perform_anomaly_detection",
            return_value={"anomalies": [], "summary": {}},
        ) as mock_anomaly,
        patch.object(
            ml,
            "_generate_threat_intelligence",
            return_value={"threat_intelligence": [], "summary": {}},
        ) as mock_threat,
    ):
        result = ml.analyze_binary("sample.bin", {"disassembly": {}, "functions": []})

    assert result["binary_path"] == "sample.bin"
    assert "analysis_timestamp" in result
    assert result["ml_analysis"]["code_reconstruction"] == {"reconstructions": [], "summary": {}}
    assert result["ml_analysis"]["anomaly_detection"] == {"anomalies": [], "summary": {}}
    assert result["ml_analysis"]["threat_intelligence"] == {
        "threat_intelligence": [],
        "summary": {},
    }
    mock_reconstruction.assert_called_once()
    mock_anomaly.assert_called_once()
    mock_threat.assert_called_once()


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_perform_anomaly_detection_handles_errors(mock_anomaly_cls, mock_recon_cls, tmp_path):
    mock_recon_cls.return_value = MagicMock()
    mock_anomaly = MagicMock()
    mock_anomaly.detect_anomalies.side_effect = RuntimeError("boom")
    mock_anomaly_cls.return_value = mock_anomaly

    ml = MLIntegration(MLIntegrationConfig(output_directory=str(tmp_path)))

    summary = ml._perform_anomaly_detection({})

    assert summary == {"error": "boom"}


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_extract_code_fragments_combines_disassembly_and_functions(
    mock_anomaly_cls, mock_recon_cls, tmp_path
):
    mock_recon_cls.return_value = MagicMock()
    mock_anomaly_cls.return_value = MagicMock()
    ml = MLIntegration(MLIntegrationConfig(output_directory=str(tmp_path)))

    fragments = ml._extract_code_fragments(
        {
            "disassembly": {
                "instructions": [
                    {
                        "address": 0x401000,
                        "size": 2,
                        "mnemonic": "call eax",
                        "bytes": "90ff",
                        "function": "entry",
                    }
                ]
            },
            "functions": [
                {
                    "address": 0x401100,
                    "size": 8,
                    "disassembly": "main",
                    "name": "main",
                }
            ],
        }
    )

    assert len(fragments) == 2
    assert fragments[0].address == 0x401000
    assert fragments[0].context["function"] == "entry"
    assert fragments[1].context["function_name"] == "main"


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_get_model_status_serializes_available_models(mock_anomaly_cls, mock_recon_cls, tmp_path):
    mock_reconstruction = MagicMock()
    mock_reconstruction.models = {
        _EnumValue("codebert"): {
            "loaded": True,
            "local": True,
            "config": {"device": "cpu"},
        }
    }
    mock_recon_cls.return_value = mock_reconstruction

    mock_anomaly_model = SimpleNamespace(
        name="iso-forest",
        type=SimpleNamespace(value="isolation_forest"),
        features=["entropy"],
        threshold=0.7,
        performance={"precision": 0.9},
    )
    mock_anomaly = MagicMock()
    mock_anomaly.models = {"primary": mock_anomaly_model}
    mock_anomaly_cls.return_value = mock_anomaly

    ml = MLIntegration(MLIntegrationConfig(output_directory=str(tmp_path)))
    status = ml.get_model_status()

    assert status["code_reconstruction"]["available"] is True
    assert status["code_reconstruction"]["models"]["codebert"]["loaded"] is True
    assert status["anomaly_detection"]["available"] is True
    assert status["anomaly_detection"]["models"]["primary"]["type"] == "isolation_forest"
