"""
Unit tests for ML Integration
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.ml.integration import (
    MLIntegration, MLIntegrationConfig, MLModel, MLProvider, MLTask
)


class TestMLIntegration:
    """Test cases for MLIntegration"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config = MLIntegrationConfig()
        self.ml_integration = MLIntegration(self.config)

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test MLIntegration initialization"""
        assert self.ml_integration is not None
        assert self.ml_integration.config == self.config
        assert hasattr(self.ml_integration, 'logger')
        assert hasattr(self.ml_integration, 'code_reconstruction')
        assert hasattr(self.ml_integration, 'anomaly_detection')
        assert hasattr(self.ml_integration, 'threat_intelligence')

    def test_analyze_binary_success(self):
        """Test analyzing binary successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock ML components
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='test code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )
            mock_anomaly.detect_anomalies.return_value = Mock(
                anomalies=['anomaly1', 'anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )
            mock_threat.analyze_threats.return_value = Mock(
                threats=['threat1', 'threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Analyze binary
            result = self.ml_integration.analyze_binary(str(test_binary))

            assert result is not None
            assert hasattr(result, 'framework')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'reconstructed_code')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'threat_level')
            assert hasattr(result, 'anomalies')
            assert hasattr(result, 'risk_score')
            assert hasattr(result, 'threats')
            assert hasattr(result, 'risk_level')

    def test_analyze_binary_failure(self):
        """Test analyzing binary with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock ML components to fail
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks to fail
            mock_reconstruction.analyze_binary.side_effect = Exception('Reconstruction failed')
            mock_anomaly.detect_anomalies.side_effect = Exception('Anomaly detection failed')
            mock_threat.analyze_threats.side_effect = Exception('Threat analysis failed')

            # Analyze binary
            with pytest.raises(Exception):
                self.ml_integration.analyze_binary(str(test_binary))

    def test_reconstruct_code_success(self):
        """Test code reconstruction successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock code reconstruction
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction:
            mock_reconstruction.reconstruct_code.return_value = Mock(
                reconstructed_code='test code',
                confidence=0.9,
                framework='.NET',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )

            # Reconstruct code
            result = self.ml_integration.reconstruct_code(str(test_binary))

            assert result is not None
            assert hasattr(result, 'reconstructed_code')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'framework')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'threat_level')

    def test_reconstruct_code_failure(self):
        """Test code reconstruction with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock code reconstruction to fail
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction:
            mock_reconstruction.reconstruct_code.side_effect = Exception('Reconstruction failed')

            # Reconstruct code
            with pytest.raises(Exception):
                self.ml_integration.reconstruct_code(str(test_binary))

    def test_detect_anomalies_success(self):
        """Test anomaly detection successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock anomaly detection
        with patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly:
            mock_anomaly.detect_anomalies.return_value = Mock(
                anomalies=['anomaly1', 'anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )

            # Detect anomalies
            result = self.ml_integration.detect_anomalies(str(test_binary))

            assert result is not None
            assert hasattr(result, 'anomalies')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'risk_score')

    def test_detect_anomalies_failure(self):
        """Test anomaly detection with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock anomaly detection to fail
        with patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly:
            mock_anomaly.detect_anomalies.side_effect = Exception('Anomaly detection failed')

            # Detect anomalies
            with pytest.raises(Exception):
                self.ml_integration.detect_anomalies(str(test_binary))

    def test_analyze_threats_success(self):
        """Test threat analysis successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock threat intelligence
        with patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:
            mock_threat.analyze_threats.return_value = Mock(
                threats=['threat1', 'threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Analyze threats
            result = self.ml_integration.analyze_threats(str(test_binary))

            assert result is not None
            assert hasattr(result, 'threats')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'risk_level')

    def test_analyze_threats_failure(self):
        """Test threat analysis with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock threat intelligence to fail
        with patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:
            mock_threat.analyze_threats.side_effect = Exception('Threat analysis failed')

            # Analyze threats
            with pytest.raises(Exception):
                self.ml_integration.analyze_threats(str(test_binary))

    def test_get_model_status_success(self):
        """Test getting model status successfully"""
        # Mock model status
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks
            mock_reconstruction.get_model_status.return_value = {'status': 'ready', 'accuracy': 0.9}
            mock_anomaly.get_model_status.return_value = {'status': 'ready', 'accuracy': 0.8}
            mock_threat.get_model_status.return_value = {'status': 'ready', 'accuracy': 0.85}

            # Get model status
            status = self.ml_integration.get_model_status()

            assert isinstance(status, dict)
            assert 'code_reconstruction' in status
            assert 'anomaly_detection' in status
            assert 'threat_intelligence' in status
            assert status['code_reconstruction']['status'] == 'ready'
            assert status['anomaly_detection']['status'] == 'ready'
            assert status['threat_intelligence']['status'] == 'ready'

    def test_get_model_status_failure(self):
        """Test getting model status with failure"""
        # Mock model status to fail
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks to fail
            mock_reconstruction.get_model_status.side_effect = Exception('Status check failed')
            mock_anomaly.get_model_status.side_effect = Exception('Status check failed')
            mock_threat.get_model_status.side_effect = Exception('Status check failed')

            # Get model status
            with pytest.raises(Exception):
                self.ml_integration.get_model_status()

    def test_ml_integration_config_properties(self):
        """Test MLIntegrationConfig properties"""
        config = MLIntegrationConfig()

        assert hasattr(config, 'code_reconstruction')
        assert hasattr(config, 'anomaly_detection')
        assert hasattr(config, 'threat_intelligence')
        assert hasattr(config, 'models')
        assert hasattr(config, 'providers')
        assert hasattr(config, 'tasks')

    def test_ml_model_properties(self):
        """Test MLModel properties"""
        model = MLModel(
            name='test_model',
            provider=MLProvider.LOCAL,
            task=MLTask.CODE_RECONSTRUCTION,
            accuracy=0.9,
            status='ready'
        )

        assert model.name == 'test_model'
        assert model.provider == MLProvider.LOCAL
        assert model.task == MLTask.CODE_RECONSTRUCTION
        assert model.accuracy == 0.9
        assert model.status == 'ready'

    def test_ml_provider_enum(self):
        """Test MLProvider enum values"""
        assert MLProvider.LOCAL == 'local'
        assert MLProvider.CLOUD == 'cloud'
        assert MLProvider.HYBRID == 'hybrid'

    def test_ml_task_enum(self):
        """Test MLTask enum values"""
        assert MLTask.CODE_RECONSTRUCTION == 'code_reconstruction'
        assert MLTask.ANOMALY_DETECTION == 'anomaly_detection'
        assert MLTask.THREAT_INTELLIGENCE == 'threat_intelligence'
        assert MLTask.VULNERABILITY_DETECTION == 'vulnerability_detection'
        assert MLTask.MALWARE_ANALYSIS == 'malware_analysis'

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
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Mock ML components
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='large binary code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )
            mock_anomaly.detect_anomalies.return_value = Mock(
                anomalies=['anomaly1', 'anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )
            mock_threat.analyze_threats.return_value = Mock(
                threats=['threat1', 'threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Analyze binary
            result = self.ml_integration.analyze_binary(str(test_binary))

            assert result is not None
            assert hasattr(result, 'framework')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'reconstructed_code')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'threat_level')
            assert hasattr(result, 'anomalies')
            assert hasattr(result, 'risk_score')
            assert hasattr(result, 'threats')
            assert hasattr(result, 'risk_level')
