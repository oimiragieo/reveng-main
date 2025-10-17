"""
Integration tests for ML workflow
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.ml.integration import MLIntegration, MLIntegrationConfig
from src.reveng.ml.code_reconstruction import MLCodeReconstruction
from src.reveng.ml.anomaly_detection import MLAnomalyDetection


class TestMLWorkflow:
    """Integration tests for ML workflow"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.config = MLIntegrationConfig()
        self.ml_integration = MLIntegration(self.config)

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_full_ml_analysis_workflow(self):
        """Test complete ML analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock all ML components
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for complete workflow
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

            # Run complete ML analysis workflow
            result = self.ml_integration.analyze_binary(str(test_binary))

            # Verify all components were called
            mock_reconstruction.analyze_binary.assert_called_once()
            mock_anomaly.detect_anomalies.assert_called_once()
            mock_threat.analyze_threats.assert_called_once()

            # Verify result structure
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

    def test_ml_workflow_with_failures(self):
        """Test ML workflow with component failures"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock ML components with mixed success/failure
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks - some succeed, some fail
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='test code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )
            mock_anomaly.detect_anomalies.side_effect = Exception('Anomaly detection failed')
            mock_threat.analyze_threats.return_value = Mock(
                threats=['threat1', 'threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Run ML analysis workflow
            with pytest.raises(Exception):
                self.ml_integration.analyze_binary(str(test_binary))

    def test_ml_workflow_with_large_binary(self):
        """Test ML workflow with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Mock all ML components
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for large binary
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

            # Run ML analysis workflow
            result = self.ml_integration.analyze_binary(str(test_binary))

            # Verify all components were called
            mock_reconstruction.analyze_binary.assert_called_once()
            mock_anomaly.detect_anomalies.assert_called_once()
            mock_threat.analyze_threats.assert_called_once()

            # Verify result structure
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

    def test_ml_workflow_with_multiple_binaries(self):
        """Test ML workflow with multiple binaries"""
        # Create multiple test binaries
        test_binaries = []
        for i in range(3):
            binary_path = self.temp_dir / f'test_{i}.exe'
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)
            test_binaries.append(binary_path)

        # Mock all ML components
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for multiple binaries
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

            # Run ML analysis workflow for each binary
            results = []
            for binary in test_binaries:
                result = self.ml_integration.analyze_binary(str(binary))
                results.append(result)

            # Verify all components were called for each binary
            assert mock_reconstruction.analyze_binary.call_count == 3
            assert mock_anomaly.detect_anomalies.call_count == 3
            assert mock_threat.analyze_threats.call_count == 3

            # Verify all results
            assert len(results) == 3
            for result in results:
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

    def test_ml_workflow_with_custom_models(self):
        """Test ML workflow with custom models"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock all ML components with custom models
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for custom models
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='custom model code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )
            mock_anomaly.detect_anomalies.return_value = Mock(
                anomalies=['custom_anomaly1', 'custom_anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )
            mock_threat.analyze_threats.return_value = Mock(
                threats=['custom_threat1', 'custom_threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Run ML analysis workflow with custom models
            result = self.ml_integration.analyze_binary(str(test_binary), model='custom')

            # Verify all components were called
            mock_reconstruction.analyze_binary.assert_called_once()
            mock_anomaly.detect_anomalies.assert_called_once()
            mock_threat.analyze_threats.assert_called_once()

            # Verify result structure
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

    def test_ml_workflow_with_disabled_components(self):
        """Test ML workflow with disabled components"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Create config with disabled components
        disabled_config = MLIntegrationConfig()
        disabled_config.code_reconstruction.enabled = False
        disabled_config.anomaly_detection.enabled = False
        disabled_config.threat_intelligence.enabled = False

        ml_integration = MLIntegration(disabled_config)

        # Mock all ML components
        with patch.object(ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for disabled components
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

            # Run ML analysis workflow with disabled components
            result = ml_integration.analyze_binary(str(test_binary))

            # Verify all components were called (even if disabled)
            mock_reconstruction.analyze_binary.assert_called_once()
            mock_anomaly.detect_anomalies.assert_called_once()
            mock_threat.analyze_threats.assert_called_once()

            # Verify result structure
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

    def test_ml_workflow_with_model_status_check(self):
        """Test ML workflow with model status check"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock all ML components
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for model status
            mock_reconstruction.get_model_status.return_value = {'status': 'ready', 'accuracy': 0.9}
            mock_anomaly.get_model_status.return_value = {'status': 'ready', 'accuracy': 0.8}
            mock_threat.get_model_status.return_value = {'status': 'ready', 'accuracy': 0.85}

            # Check model status
            status = self.ml_integration.get_model_status()

            # Verify model status
            assert isinstance(status, dict)
            assert 'code_reconstruction' in status
            assert 'anomaly_detection' in status
            assert 'threat_intelligence' in status
            assert status['code_reconstruction']['status'] == 'ready'
            assert status['anomaly_detection']['status'] == 'ready'
            assert status['threat_intelligence']['status'] == 'ready'

    def test_ml_workflow_with_model_status_failure(self):
        """Test ML workflow with model status failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock all ML components with status failures
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for model status failures
            mock_reconstruction.get_model_status.side_effect = Exception('Status check failed')
            mock_anomaly.get_model_status.side_effect = Exception('Status check failed')
            mock_threat.get_model_status.side_effect = Exception('Status check failed')

            # Check model status
            with pytest.raises(Exception):
                self.ml_integration.get_model_status()

    def test_ml_workflow_with_partial_failures(self):
        """Test ML workflow with partial failures"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock all ML components with partial failures
        with patch.object(self.ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(self.ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(self.ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for partial failures
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='test code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )
            mock_anomaly.detect_anomalies.side_effect = Exception('Anomaly detection failed')
            mock_threat.analyze_threats.return_value = Mock(
                threats=['threat1', 'threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Run ML analysis workflow with partial failures
            with pytest.raises(Exception):
                self.ml_integration.analyze_binary(str(test_binary))

    def test_ml_workflow_with_custom_config(self):
        """Test ML workflow with custom configuration"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Create custom config
        custom_config = MLIntegrationConfig()
        custom_config.code_reconstruction.enabled = True
        custom_config.anomaly_detection.enabled = True
        custom_config.threat_intelligence.enabled = True

        ml_integration = MLIntegration(custom_config)

        # Mock all ML components
        with patch.object(ml_integration, 'code_reconstruction') as mock_reconstruction, \
             patch.object(ml_integration, 'anomaly_detection') as mock_anomaly, \
             patch.object(ml_integration, 'threat_intelligence') as mock_threat:

            # Setup mocks for custom config
            mock_reconstruction.analyze_binary.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='custom config code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )
            mock_anomaly.detect_anomalies.return_value = Mock(
                anomalies=['custom_anomaly1', 'custom_anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )
            mock_threat.analyze_threats.return_value = Mock(
                threats=['custom_threat1', 'custom_threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Run ML analysis workflow with custom config
            result = ml_integration.analyze_binary(str(test_binary))

            # Verify all components were called
            mock_reconstruction.analyze_binary.assert_called_once()
            mock_anomaly.detect_anomalies.assert_called_once()
            mock_threat.analyze_threats.assert_called_once()

            # Verify result structure
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
