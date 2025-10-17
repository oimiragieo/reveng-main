"""
Unit tests for ML Code Reconstruction
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.ml.code_reconstruction import (
    MLCodeReconstruction, CodeFragment, ReconstructionResult,
    ReconstructionTask, ModelType, ThreatIntelligence
)


class TestMLCodeReconstruction:
    """Test cases for MLCodeReconstruction"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.ml_reconstruction = MLCodeReconstruction()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test MLCodeReconstruction initialization"""
        assert self.ml_reconstruction is not None
        assert hasattr(self.ml_reconstruction, 'logger')
        assert hasattr(self.ml_reconstruction, 'models')
        assert hasattr(self.ml_reconstruction, 'providers')
        assert hasattr(self.ml_reconstruction, 'tasks')

    def test_analyze_binary_success(self):
        """Test analyzing binary successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock model analysis
        with patch.object(self.ml_reconstruction, '_analyze_with_model') as mock_analyze:
            mock_analyze.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='test code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )

            # Analyze binary
            result = self.ml_reconstruction.analyze_binary(str(test_binary))

            assert result is not None
            assert hasattr(result, 'framework')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'reconstructed_code')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'threat_level')

    def test_analyze_binary_failure(self):
        """Test analyzing binary with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock model analysis to fail
        with patch.object(self.ml_reconstruction, '_analyze_with_model') as mock_analyze:
            mock_analyze.side_effect = Exception('Analysis failed')

            # Analyze binary
            with pytest.raises(Exception):
                self.ml_reconstruction.analyze_binary(str(test_binary))

    def test_reconstruct_code_success(self):
        """Test code reconstruction successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock code reconstruction
        with patch.object(self.ml_reconstruction, '_reconstruct_with_model') as mock_reconstruct:
            mock_reconstruct.return_value = Mock(
                reconstructed_code='test code',
                confidence=0.9,
                framework='.NET',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )

            # Reconstruct code
            result = self.ml_reconstruction.reconstruct_code(str(test_binary))

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
        with patch.object(self.ml_reconstruction, '_reconstruct_with_model') as mock_reconstruct:
            mock_reconstruct.side_effect = Exception('Reconstruction failed')

            # Reconstruct code
            with pytest.raises(Exception):
                self.ml_reconstruction.reconstruct_code(str(test_binary))

    def test_detect_vulnerabilities_success(self):
        """Test vulnerability detection successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock vulnerability detection
        with patch.object(self.ml_reconstruction, '_detect_vulnerabilities_with_model') as mock_detect:
            mock_detect.return_value = ['vuln1', 'vuln2', 'vuln3']

            # Detect vulnerabilities
            vulnerabilities = self.ml_reconstruction.detect_vulnerabilities(str(test_binary))

            assert isinstance(vulnerabilities, list)
            assert len(vulnerabilities) == 3
            assert 'vuln1' in vulnerabilities
            assert 'vuln2' in vulnerabilities
            assert 'vuln3' in vulnerabilities

    def test_detect_vulnerabilities_failure(self):
        """Test vulnerability detection with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock vulnerability detection to fail
        with patch.object(self.ml_reconstruction, '_detect_vulnerabilities_with_model') as mock_detect:
            mock_detect.side_effect = Exception('Vulnerability detection failed')

            # Detect vulnerabilities
            with pytest.raises(Exception):
                self.ml_reconstruction.detect_vulnerabilities(str(test_binary))

    def test_analyze_threats_success(self):
        """Test threat analysis successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock threat analysis
        with patch.object(self.ml_reconstruction, '_analyze_threats_with_model') as mock_analyze:
            mock_analyze.return_value = Mock(
                threats=['threat1', 'threat2'],
                confidence=0.85,
                risk_level='High'
            )

            # Analyze threats
            result = self.ml_reconstruction.analyze_threats(str(test_binary))

            assert result is not None
            assert hasattr(result, 'threats')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'risk_level')

    def test_analyze_threats_failure(self):
        """Test threat analysis with failure"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock threat analysis to fail
        with patch.object(self.ml_reconstruction, '_analyze_threats_with_model') as mock_analyze:
            mock_analyze.side_effect = Exception('Threat analysis failed')

            # Analyze threats
            with pytest.raises(Exception):
                self.ml_reconstruction.analyze_threats(str(test_binary))

    def test_get_model_status_success(self):
        """Test getting model status successfully"""
        # Mock model status
        with patch.object(self.ml_reconstruction, '_get_model_status') as mock_status:
            mock_status.return_value = {
                'codebert': {'status': 'ready', 'accuracy': 0.9},
                'codet5': {'status': 'ready', 'accuracy': 0.85},
                'gpt': {'status': 'ready', 'accuracy': 0.95},
                'claude': {'status': 'ready', 'accuracy': 0.9}
            }

            # Get model status
            status = self.ml_reconstruction.get_model_status()

            assert isinstance(status, dict)
            assert 'codebert' in status
            assert 'codet5' in status
            assert 'gpt' in status
            assert 'claude' in status
            assert status['codebert']['status'] == 'ready'
            assert status['codet5']['status'] == 'ready'
            assert status['gpt']['status'] == 'ready'
            assert status['claude']['status'] == 'ready'

    def test_get_model_status_failure(self):
        """Test getting model status with failure"""
        # Mock model status to fail
        with patch.object(self.ml_reconstruction, '_get_model_status') as mock_status:
            mock_status.side_effect = Exception('Status check failed')

            # Get model status
            with pytest.raises(Exception):
                self.ml_reconstruction.get_model_status()

    def test_code_fragment_properties(self):
        """Test CodeFragment properties"""
        fragment = CodeFragment(
            code='test code',
            language='python',
            confidence=0.9,
            source='binary',
            metadata={'key': 'value'}
        )

        assert fragment.code == 'test code'
        assert fragment.language == 'python'
        assert fragment.confidence == 0.9
        assert fragment.source == 'binary'
        assert fragment.metadata == {'key': 'value'}

    def test_reconstruction_result_properties(self):
        """Test ReconstructionResult properties"""
        result = ReconstructionResult(
            reconstructed_code='test code',
            confidence=0.9,
            framework='.NET',
            vulnerabilities=['vuln1', 'vuln2'],
            threat_level='Medium'
        )

        assert result.reconstructed_code == 'test code'
        assert result.confidence == 0.9
        assert result.framework == '.NET'
        assert result.vulnerabilities == ['vuln1', 'vuln2']
        assert result.threat_level == 'Medium'

    def test_reconstruction_task_enum(self):
        """Test ReconstructionTask enum values"""
        assert ReconstructionTask.DECOMPILATION == 'decompilation'
        assert ReconstructionTask.FUNCTION == 'function'
        assert ReconstructionTask.VARIABLE == 'variable'
        assert ReconstructionTask.CONTROL_FLOW == 'control_flow'
        assert ReconstructionTask.DATA_FLOW == 'data_flow'
        assert ReconstructionTask.VULNERABILITY_DETECTION == 'vulnerability_detection'
        assert ReconstructionTask.THREAT_INTELLIGENCE == 'threat_intelligence'

    def test_model_type_enum(self):
        """Test ModelType enum values"""
        assert ModelType.CODEBERT == 'codebert'
        assert ModelType.CODET5 == 'codet5'
        assert ModelType.CODEGEN == 'codegen'
        assert ModelType.GPT == 'gpt'
        assert ModelType.CLAUDE == 'claude'
        assert ModelType.LOCAL_LLM == 'local_llm'

    def test_threat_intelligence_properties(self):
        """Test ThreatIntelligence properties"""
        threat = ThreatIntelligence(
            threats=['threat1', 'threat2'],
            confidence=0.85,
            risk_level='High',
            mitigation=['mit1', 'mit2']
        )

        assert threat.threats == ['threat1', 'threat2']
        assert threat.confidence == 0.85
        assert threat.risk_level == 'High'
        assert threat.mitigation == ['mit1', 'mit2']

    def test_ml_reconstruction_with_custom_model(self):
        """Test ML reconstruction with custom model"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Mock custom model
        with patch.object(self.ml_reconstruction, '_analyze_with_model') as mock_analyze:
            mock_analyze.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='custom model code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )

            # Analyze binary with custom model
            result = self.ml_reconstruction.analyze_binary(str(test_binary), model='custom')

            assert result is not None
            assert hasattr(result, 'framework')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'reconstructed_code')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'threat_level')

    def test_ml_reconstruction_with_large_binary(self):
        """Test ML reconstruction with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Mock model analysis
        with patch.object(self.ml_reconstruction, '_analyze_with_model') as mock_analyze:
            mock_analyze.return_value = Mock(
                framework='.NET',
                confidence=0.9,
                reconstructed_code='large binary code',
                vulnerabilities=['vuln1', 'vuln2'],
                threat_level='Medium'
            )

            # Analyze binary
            result = self.ml_reconstruction.analyze_binary(str(test_binary))

            assert result is not None
            assert hasattr(result, 'framework')
            assert hasattr(result, 'confidence')
            assert hasattr(result, 'reconstructed_code')
            assert hasattr(result, 'vulnerabilities')
            assert hasattr(result, 'threat_level')

    def test_ml_reconstruction_with_multiple_tasks(self):
        """Test ML reconstruction with multiple tasks"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        tasks = [
            ReconstructionTask.DECOMPILATION,
            ReconstructionTask.FUNCTION,
            ReconstructionTask.VARIABLE,
            ReconstructionTask.CONTROL_FLOW,
            ReconstructionTask.DATA_FLOW,
            ReconstructionTask.VULNERABILITY_DETECTION,
            ReconstructionTask.THREAT_INTELLIGENCE
        ]

        for task in tasks:
            # Mock task execution
            with patch.object(self.ml_reconstruction, '_execute_task') as mock_execute:
                mock_execute.return_value = Mock(
                    result=f'Result for {task}',
                    confidence=0.9
                )

                # Execute task
                result = self.ml_reconstruction.execute_task(str(test_binary), task)

                assert result is not None
                assert hasattr(result, 'result')
                assert hasattr(result, 'confidence')

    def test_ml_reconstruction_with_different_models(self):
        """Test ML reconstruction with different models"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        models = [
            ModelType.CODEBERT,
            ModelType.CODET5,
            ModelType.CODEGEN,
            ModelType.GPT,
            ModelType.CLAUDE,
            ModelType.LOCAL_LLM
        ]

        for model in models:
            # Mock model analysis
            with patch.object(self.ml_reconstruction, '_analyze_with_model') as mock_analyze:
                mock_analyze.return_value = Mock(
                    framework='.NET',
                    confidence=0.9,
                    reconstructed_code=f'Code from {model}',
                    vulnerabilities=['vuln1', 'vuln2'],
                    threat_level='Medium'
                )

                # Analyze binary with model
                result = self.ml_reconstruction.analyze_binary(str(test_binary), model=model)

                assert result is not None
                assert hasattr(result, 'framework')
                assert hasattr(result, 'confidence')
                assert hasattr(result, 'reconstructed_code')
                assert hasattr(result, 'vulnerabilities')
                assert hasattr(result, 'threat_level')
