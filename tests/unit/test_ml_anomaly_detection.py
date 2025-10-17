"""
Unit tests for ML Anomaly Detection
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.ml.anomaly_detection import (
    MLAnomalyDetection, AnomalyResult, AnomalyFeature,
    AnomalyType, AnomalySeverity, AnomalyModel
)


class TestMLAnomalyDetection:
    """Test cases for MLAnomalyDetection"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.ml_anomaly_detection = MLAnomalyDetection()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test MLAnomalyDetection initialization"""
        assert self.ml_anomaly_detection is not None
        assert hasattr(self.ml_anomaly_detection, 'logger')
        assert hasattr(self.ml_anomaly_detection, 'models')
        assert hasattr(self.ml_anomaly_detection, 'feature_extractors')
        assert hasattr(self.ml_anomaly_detection, 'anomaly_types')

    def test_detect_anomalies_success(self):
        """Test detecting anomalies successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_with_model') as mock_detect:
            mock_detect.return_value = Mock(
                anomalies=['anomaly1', 'anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )

            # Detect anomalies
            result = self.ml_anomaly_detection.detect_anomalies(str(test_binary))

            assert result is not None
            assert hasattr(result, 'anomalies')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'risk_score')

    def test_detect_anomalies_failure(self):
        """Test detecting anomalies with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock anomaly detection to fail
        with patch.object(self.ml_anomaly_detection, '_detect_with_model') as mock_detect:
            mock_detect.side_effect = Exception('Anomaly detection failed')

            # Detect anomalies
            with pytest.raises(Exception):
                self.ml_anomaly_detection.detect_anomalies(str(test_binary))

    def test_detect_behavioral_anomalies_success(self):
        """Test detecting behavioral anomalies successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock behavioral anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_behavioral_anomalies') as mock_detect:
            mock_detect.return_value = ['anomaly1', 'anomaly2']

            # Detect behavioral anomalies
            anomalies = self.ml_anomaly_detection.detect_behavioral_anomalies(str(test_binary))

            assert isinstance(anomalies, list)
            assert len(anomalies) == 2
            assert 'anomaly1' in anomalies
            assert 'anomaly2' in anomalies

    def test_detect_behavioral_anomalies_failure(self):
        """Test detecting behavioral anomalies with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock behavioral anomaly detection to fail
        with patch.object(self.ml_anomaly_detection, '_detect_behavioral_anomalies') as mock_detect:
            mock_detect.side_effect = Exception('Behavioral anomaly detection failed')

            # Detect behavioral anomalies
            with pytest.raises(Exception):
                self.ml_anomaly_detection.detect_behavioral_anomalies(str(test_binary))

    def test_detect_structural_anomalies_success(self):
        """Test detecting structural anomalies successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock structural anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_structural_anomalies') as mock_detect:
            mock_detect.return_value = ['anomaly1', 'anomaly2']

            # Detect structural anomalies
            anomalies = self.ml_anomaly_detection.detect_structural_anomalies(str(test_binary))

            assert isinstance(anomalies, list)
            assert len(anomalies) == 2
            assert 'anomaly1' in anomalies
            assert 'anomaly2' in anomalies

    def test_detect_structural_anomalies_failure(self):
        """Test detecting structural anomalies with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock structural anomaly detection to fail
        with patch.object(self.ml_anomaly_detection, '_detect_structural_anomalies') as mock_detect:
            mock_detect.side_effect = Exception('Structural anomaly detection failed')

            # Detect structural anomalies
            with pytest.raises(Exception):
                self.ml_anomaly_detection.detect_structural_anomalies(str(test_binary))

    def test_detect_statistical_anomalies_success(self):
        """Test detecting statistical anomalies successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock statistical anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_statistical_anomalies') as mock_detect:
            mock_detect.return_value = ['anomaly1', 'anomaly2']

            # Detect statistical anomalies
            anomalies = self.ml_anomaly_detection.detect_statistical_anomalies(str(test_binary))

            assert isinstance(anomalies, list)
            assert len(anomalies) == 2
            assert 'anomaly1' in anomalies
            assert 'anomaly2' in anomalies

    def test_detect_statistical_anomalies_failure(self):
        """Test detecting statistical anomalies with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock statistical anomaly detection to fail
        with patch.object(self.ml_anomaly_detection, '_detect_statistical_anomalies') as mock_detect:
            mock_detect.side_effect = Exception('Statistical anomaly detection failed')

            # Detect statistical anomalies
            with pytest.raises(Exception):
                self.ml_anomaly_detection.detect_statistical_anomalies(str(test_binary))

    def test_detect_pattern_anomalies_success(self):
        """Test detecting pattern anomalies successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock pattern anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_pattern_anomalies') as mock_detect:
            mock_detect.return_value = ['anomaly1', 'anomaly2']

            # Detect pattern anomalies
            anomalies = self.ml_anomaly_detection.detect_pattern_anomalies(str(test_binary))

            assert isinstance(anomalies, list)
            assert len(anomalies) == 2
            assert 'anomaly1' in anomalies
            assert 'anomaly2' in anomalies

    def test_detect_pattern_anomalies_failure(self):
        """Test detecting pattern anomalies with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock pattern anomaly detection to fail
        with patch.object(self.ml_anomaly_detection, '_detect_pattern_anomalies') as mock_detect:
            mock_detect.side_effect = Exception('Pattern anomaly detection failed')

            # Detect pattern anomalies
            with pytest.raises(Exception):
                self.ml_anomaly_detection.detect_pattern_anomalies(str(test_binary))

    def test_detect_temporal_anomalies_success(self):
        """Test detecting temporal anomalies successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock temporal anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_temporal_anomalies') as mock_detect:
            mock_detect.return_value = ['anomaly1', 'anomaly2']

            # Detect temporal anomalies
            anomalies = self.ml_anomaly_detection.detect_temporal_anomalies(str(test_binary))

            assert isinstance(anomalies, list)
            assert len(anomalies) == 2
            assert 'anomaly1' in anomalies
            assert 'anomaly2' in anomalies

    def test_detect_temporal_anomalies_failure(self):
        """Test detecting temporal anomalies with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock temporal anomaly detection to fail
        with patch.object(self.ml_anomaly_detection, '_detect_temporal_anomalies') as mock_detect:
            mock_detect.side_effect = Exception('Temporal anomaly detection failed')

            # Detect temporal anomalies
            with pytest.raises(Exception):
                self.ml_anomaly_detection.detect_temporal_anomalies(str(test_binary))

    def test_extract_features_success(self):
        """Test extracting features successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock feature extraction
        with patch.object(self.ml_anomaly_detection, '_extract_features_with_model') as mock_extract:
            mock_extract.return_value = [
                AnomalyFeature('feature1', 0.9, 'type1'),
                AnomalyFeature('feature2', 0.8, 'type2')
            ]

            # Extract features
            features = self.ml_anomaly_detection.extract_features(str(test_binary))

            assert isinstance(features, list)
            assert len(features) == 2
            assert all(isinstance(feature, AnomalyFeature) for feature in features)
            assert features[0].name == 'feature1'
            assert features[0].confidence == 0.9
            assert features[0].feature_type == 'type1'
            assert features[1].name == 'feature2'
            assert features[1].confidence == 0.8
            assert features[1].feature_type == 'type2'

    def test_extract_features_failure(self):
        """Test extracting features with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock feature extraction to fail
        with patch.object(self.ml_anomaly_detection, '_extract_features_with_model') as mock_extract:
            mock_extract.side_effect = Exception('Feature extraction failed')

            # Extract features
            with pytest.raises(Exception):
                self.ml_anomaly_detection.extract_features(str(test_binary))

    def test_get_model_status_success(self):
        """Test getting model status successfully"""
        # Mock model status
        with patch.object(self.ml_anomaly_detection, '_get_model_status') as mock_status:
            mock_status.return_value = {
                'behavioral': {'status': 'ready', 'accuracy': 0.9},
                'structural': {'status': 'ready', 'accuracy': 0.85},
                'statistical': {'status': 'ready', 'accuracy': 0.8},
                'pattern': {'status': 'ready', 'accuracy': 0.88},
                'temporal': {'status': 'ready', 'accuracy': 0.82}
            }

            # Get model status
            status = self.ml_anomaly_detection.get_model_status()

            assert isinstance(status, dict)
            assert 'behavioral' in status
            assert 'structural' in status
            assert 'statistical' in status
            assert 'pattern' in status
            assert 'temporal' in status
            assert status['behavioral']['status'] == 'ready'
            assert status['structural']['status'] == 'ready'
            assert status['statistical']['status'] == 'ready'
            assert status['pattern']['status'] == 'ready'
            assert status['temporal']['status'] == 'ready'

    def test_get_model_status_failure(self):
        """Test getting model status with failure"""
        # Mock model status to fail
        with patch.object(self.ml_anomaly_detection, '_get_model_status') as mock_status:
            mock_status.side_effect = Exception('Status check failed')

            # Get model status
            with pytest.raises(Exception):
                self.ml_anomaly_detection.get_model_status()

    def test_anomaly_result_properties(self):
        """Test AnomalyResult properties"""
        result = AnomalyResult(
            anomalies=['anomaly1', 'anomaly2'],
            confidence=0.8,
            risk_score=0.7
        )

        assert result.anomalies == ['anomaly1', 'anomaly2']
        assert result.confidence == 0.8
        assert result.risk_score == 0.7

    def test_anomaly_feature_properties(self):
        """Test AnomalyFeature properties"""
        feature = AnomalyFeature(
            name='test_feature',
            confidence=0.9,
            feature_type='behavioral'
        )

        assert feature.name == 'test_feature'
        assert feature.confidence == 0.9
        assert feature.feature_type == 'behavioral'

    def test_anomaly_type_enum(self):
        """Test AnomalyType enum values"""
        assert AnomalyType.BEHAVIORAL == 'behavioral'
        assert AnomalyType.STRUCTURAL == 'structural'
        assert AnomalyType.STATISTICAL == 'statistical'
        assert AnomalyType.PATTERN == 'pattern'
        assert AnomalyType.TEMPORAL == 'temporal'

    def test_anomaly_severity_enum(self):
        """Test AnomalySeverity enum values"""
        assert AnomalySeverity.LOW == 'low'
        assert AnomalySeverity.MEDIUM == 'medium'
        assert AnomalySeverity.HIGH == 'high'
        assert AnomalySeverity.CRITICAL == 'critical'

    def test_anomaly_model_properties(self):
        """Test AnomalyModel properties"""
        model = AnomalyModel(
            name='test_model',
            model_type=AnomalyType.BEHAVIORAL,
            accuracy=0.9,
            status='ready'
        )

        assert model.name == 'test_model'
        assert model.model_type == AnomalyType.BEHAVIORAL
        assert model.accuracy == 0.9
        assert model.status == 'ready'

    def test_ml_anomaly_detection_with_custom_model(self):
        """Test ML anomaly detection with custom model"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock custom model
        with patch.object(self.ml_anomaly_detection, '_detect_with_model') as mock_detect:
            mock_detect.return_value = Mock(
                anomalies=['custom_anomaly1', 'custom_anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )

            # Detect anomalies with custom model
            result = self.ml_anomaly_detection.detect_anomalies(str(test_binary), model='custom')

            assert result is not None
            assert hasattr(result, 'anomalies')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'risk_score')

    def test_ml_anomaly_detection_with_large_binary(self):
        """Test ML anomaly detection with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Mock anomaly detection
        with patch.object(self.ml_anomaly_detection, '_detect_with_model') as mock_detect:
            mock_detect.return_value = Mock(
                anomalies=['large_anomaly1', 'large_anomaly2'],
                confidence=0.8,
                risk_score=0.7
            )

            # Detect anomalies
            result = self.ml_anomaly_detection.detect_anomalies(str(test_binary))

            assert result is not None
            assert hasattr(result, 'anomalies')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'risk_score')

    def test_ml_anomaly_detection_with_multiple_types(self):
        """Test ML anomaly detection with multiple types"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        anomaly_types = [
            AnomalyType.BEHAVIORAL,
            AnomalyType.STRUCTURAL,
            AnomalyType.STATISTICAL,
            AnomalyType.PATTERN,
            AnomalyType.TEMPORAL
        ]

        for anomaly_type in anomaly_types:
            # Mock anomaly detection for each type
            with patch.object(self.ml_anomaly_detection, f'_detect_{anomaly_type.value}_anomalies') as mock_detect:
                mock_detect.return_value = [f'{anomaly_type.value}_anomaly1', f'{anomaly_type.value}_anomaly2']

                # Detect anomalies for this type
                anomalies = getattr(self.ml_anomaly_detection, f'detect_{anomaly_type.value}_anomalies')(str(test_binary))

                assert isinstance(anomalies, list)
                assert len(anomalies) == 2
                assert f'{anomaly_type.value}_anomaly1' in anomalies
                assert f'{anomaly_type.value}_anomaly2' in anomalies
