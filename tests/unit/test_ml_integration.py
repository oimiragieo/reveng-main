"""Unit tests for the ML integration subsystem."""

from unittest.mock import MagicMock, patch

from reveng.ml.integration import MLIntegration, MLIntegrationConfig


@patch("reveng.ml.integration.MLCodeReconstruction")
@patch("reveng.ml.integration.MLAnomalyDetection")
def test_ml_integration_initialises_components(
    mock_anomaly_cls, mock_recon_cls, tmp_path
):
    mock_recon_cls.return_value = MagicMock()
    mock_anomaly_cls.return_value = MagicMock()

    config = MLIntegrationConfig(output_directory=str(tmp_path))
    ml = MLIntegration(config)

    assert ml.code_reconstruction is mock_recon_cls.return_value
    assert ml.anomaly_detection is mock_anomaly_cls.return_value


@patch(
    "reveng.ml.integration.MLIntegration._generate_threat_intelligence",
    return_value={"summary": {}},
)
@patch(
    "reveng.ml.integration.MLIntegration._perform_anomaly_detection",
    return_value={"anomalies": []},
)
@patch(
    "reveng.ml.integration.MLIntegration._perform_code_reconstruction",
    return_value={"reconstructions": []},
)
def test_analyze_binary_returns_structure(
    mock_recon, mock_anomaly, mock_threat, tmp_path
):
    config = MLIntegrationConfig(output_directory=str(tmp_path))

    with (
        patch("reveng.ml.integration.MLCodeReconstruction") as recon_cls,
        patch("reveng.ml.integration.MLAnomalyDetection") as anomaly_cls,
    ):
        recon_cls.return_value = MagicMock()
        anomaly_cls.return_value = MagicMock()
        ml = MLIntegration(config)

    analysis_data = {"disassembly": [], "functions": []}
    result = ml.analyze_binary("/tmp/sample.bin", analysis_data)

    assert "binary_path" in result
    assert "ml_analysis" in result
    assert "code_reconstruction" in result["ml_analysis"]
    assert "anomaly_detection" in result["ml_analysis"]
    assert "threat_intelligence" in result["ml_analysis"]


def test_perform_anomaly_detection_handles_errors(tmp_path):
    config = MLIntegrationConfig(output_directory=str(tmp_path))
    with (
        patch("reveng.ml.integration.MLCodeReconstruction") as recon_cls,
        patch("reveng.ml.integration.MLAnomalyDetection") as anomaly_cls,
    ):
        recon_cls.return_value = MagicMock()
        anomaly_cls.return_value = MagicMock()
        ml = MLIntegration(config)

    ml.anomaly_detection.detect_anomalies.side_effect = RuntimeError("boom")

    summary = ml._perform_anomaly_detection({})
    assert "error" in summary

    def test_analyze_threats_failure(self):
        """Test threat analysis with failure"""
        # Create test binary
        test_binary = self.temp_dir / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        # Mock threat intelligence to fail
        with patch.object(self.ml_integration, "threat_intelligence") as mock_threat:
            mock_threat.analyze_threats.side_effect = Exception(
                "Threat analysis failed"
            )

            # Analyze threats
            with pytest.raises(Exception):
                self.ml_integration.analyze_threats(str(test_binary))

    def test_get_model_status_success(self):
        """Test getting model status successfully"""
        # Mock model status
        with (
            patch.object(
                self.ml_integration, "code_reconstruction"
            ) as mock_reconstruction,
            patch.object(self.ml_integration, "anomaly_detection") as mock_anomaly,
            patch.object(self.ml_integration, "threat_intelligence") as mock_threat,
        ):
            # Setup mocks
            mock_reconstruction.get_model_status.return_value = {
                "status": "ready",
                "accuracy": 0.9,
            }
            mock_anomaly.get_model_status.return_value = {
                "status": "ready",
                "accuracy": 0.8,
            }
            mock_threat.get_model_status.return_value = {
                "status": "ready",
                "accuracy": 0.85,
            }

            # Get model status
            status = self.ml_integration.get_model_status()

            assert isinstance(status, dict)
            assert "code_reconstruction" in status
            assert "anomaly_detection" in status
            assert "threat_intelligence" in status
            assert status["code_reconstruction"]["status"] == "ready"
            assert status["anomaly_detection"]["status"] == "ready"
            assert status["threat_intelligence"]["status"] == "ready"

    def test_get_model_status_failure(self):
        """Test getting model status with failure"""
        # Mock model status to fail
        with (
            patch.object(
                self.ml_integration, "code_reconstruction"
            ) as mock_reconstruction,
            patch.object(self.ml_integration, "anomaly_detection") as mock_anomaly,
            patch.object(self.ml_integration, "threat_intelligence") as mock_threat,
        ):
            # Setup mocks to fail
            mock_reconstruction.get_model_status.side_effect = Exception(
                "Status check failed"
            )
            mock_anomaly.get_model_status.side_effect = Exception("Status check failed")
            mock_threat.get_model_status.side_effect = Exception("Status check failed")

            # Get model status
            with pytest.raises(Exception):
                self.ml_integration.get_model_status()

    def test_ml_integration_config_properties(self):
        """Test MLIntegrationConfig properties"""
        config = MLIntegrationConfig()

        assert hasattr(config, "code_reconstruction")
        assert hasattr(config, "anomaly_detection")
        assert hasattr(config, "threat_intelligence")
        assert hasattr(config, "models")
        assert hasattr(config, "providers")
        assert hasattr(config, "tasks")

    def test_ml_model_properties(self):
        """Test MLModel properties"""
        model = MLModel(
            name="test_model",
            provider=MLProvider.LOCAL,
            task=MLTask.CODE_RECONSTRUCTION,
            accuracy=0.9,
            status="ready",
        )

        assert model.name == "test_model"
        assert model.provider == MLProvider.LOCAL
        assert model.task == MLTask.CODE_RECONSTRUCTION
        assert model.accuracy == 0.9
        assert model.status == "ready"

    def test_ml_provider_enum(self):
        """Test MLProvider enum values"""
        assert MLProvider.LOCAL == "local"
        assert MLProvider.CLOUD == "cloud"
        assert MLProvider.HYBRID == "hybrid"

    def test_ml_task_enum(self):
        """Test MLTask enum values"""
        assert MLTask.CODE_RECONSTRUCTION == "code_reconstruction"
        assert MLTask.ANOMALY_DETECTION == "anomaly_detection"
        assert MLTask.THREAT_INTELLIGENCE == "threat_intelligence"
        assert MLTask.VULNERABILITY_DETECTION == "vulnerability_detection"
        assert MLTask.MALWARE_ANALYSIS == "malware_analysis"

    def test_ml_integration_with_custom_config(self):
        """Test MLIntegration with custom config"""
        custom_config = MLIntegrationConfig()
        custom_config.code_reconstruction.enabled = True
        custom_config.anomaly_detection.enabled = True
        custom_config.threat_intelligence.enabled = True

        ml_integration = MLIntegration(custom_config)

        assert ml_integration.config == custom_config
        assert ml_integration.config.code_reconstruction.enabled is True
        assert ml_integration.config.anomaly_detection.enabled is True
        assert ml_integration.config.threat_intelligence.enabled is True

    def test_ml_integration_with_disabled_components(self):
        """Test MLIntegration with disabled components"""
        disabled_config = MLIntegrationConfig()
        disabled_config.code_reconstruction.enabled = False
        disabled_config.anomaly_detection.enabled = False
        disabled_config.threat_intelligence.enabled = False

        ml_integration = MLIntegration(disabled_config)

        assert ml_integration.config.code_reconstruction.enabled is False
        assert ml_integration.config.anomaly_detection.enabled is False
        assert ml_integration.config.threat_intelligence.enabled is False

    def test_ml_integration_with_large_binary(self):
        """Test MLIntegration with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / "large.exe"
        test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000000)  # 1MB file

        # Mock ML components
        with (
            patch.object(
                self.ml_integration, "code_reconstruction"
            ) as mock_reconstruction,
            patch.object(self.ml_integration, "anomaly_detection") as mock_anomaly,
            patch.object(self.ml_integration, "threat_intelligence") as mock_threat,
        ):
            # Setup mocks
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework=".NET",
                confidence=0.9,
                reconstructed_code="large binary code",
                vulnerabilities=["vuln1", "vuln2"],
                threat_level="Medium",
            )
            mock_anomaly.detect_anomalies.return_value = Mock(
                anomalies=["anomaly1", "anomaly2"], confidence=0.8, risk_score=0.7
            )
            mock_threat.analyze_threats.return_value = Mock(
                threats=["threat1", "threat2"], confidence=0.85, risk_level="High"
            )

            # Analyze binary
            result = self.ml_integration.analyze_binary(str(test_binary))

            assert result is not None
            assert hasattr(result, "framework")
            assert hasattr(result, "confidence")
            assert hasattr(result, "reconstructed_code")
            assert hasattr(result, "vulnerabilities")
            assert hasattr(result, "threat_level")
            assert hasattr(result, "anomalies")
            assert hasattr(result, "risk_score")
            assert hasattr(result, "threats")
            assert hasattr(result, "risk_level")
