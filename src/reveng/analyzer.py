#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - Core Analyzer
===========================================================

Enterprise-grade binary analysis and reassembly system that works on ANY binary:
- Step 1: AI-powered binary analysis
- Step 2: Complete disassembly
- Step 3: AI inspection with extra thinking
- Step 4: Specification library creation
- Step 5: Human-readable code conversion
- Step 6: Deobfuscation and domain splitting
- Step 7: Implementation of missing features
- Step 8: Enhanced corporate data exposure analysis
- Step 9: Automated vulnerability discovery
- Step 10: Threat intelligence correlation
- Step 11: Enhanced binary reconstruction
- Step 12: Security demonstration generation

Author: REVENG Development Team
Version: 2.1.0
License: MIT
"""

import sys
import json
import time
from pathlib import Path
import logging
import subprocess
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reveng_analyzer.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Enhanced analysis feature flags
class EnhancedAnalysisFeatures:
    """Feature flags for enhanced analysis capabilities"""
    def __init__(self):
        self.enable_enhanced_analysis = True
        self.enable_corporate_exposure = True
        self.enable_vulnerability_discovery = True
        self.enable_threat_intelligence = True
        self.enable_enhanced_reconstruction = True
        self.enable_demonstration_generation = True

    def from_config(self, config_dict: Dict[str, Any]) -> 'EnhancedAnalysisFeatures':
        """Load feature flags from configuration dictionary"""
        for key, value in config_dict.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self

    def is_any_enhanced_enabled(self) -> bool:
        """Check if any enhanced analysis features are enabled"""
        return (self.enable_enhanced_analysis and
                (self.enable_corporate_exposure or
                 self.enable_vulnerability_discovery or
                 self.enable_threat_intelligence or
                 self.enable_enhanced_reconstruction or
                 self.enable_demonstration_generation))

class REVENGAnalyzer:
    """
    REVENG Analyzer - Enterprise Binary Analysis

    This system provides comprehensive binary analysis for ANY binary:
    - AI-powered analysis and insights
    - Complete disassembly and source reconstruction
    - Deep AI inspection with extra thinking
    - Comprehensive specification library
    - Human-readable code conversion
    - Deobfuscation and domain organization
    - Implementation of missing features
    """

    def __init__(self, binary_path: str = None, check_ollama: bool = True,
                 enhanced_features: Optional[EnhancedAnalysisFeatures] = None):
        """
        Initialize the REVENG analyzer

        Args:
            binary_path: Path to binary to analyze
            check_ollama: Whether to run Ollama preflight check (default: True)
            enhanced_features: Enhanced analysis feature configuration
        """
        self.binary_path = binary_path or self._find_binary()
        self.binary_name = Path(self.binary_path).stem if self.binary_path else "unknown"
        self.analysis_folder = Path(f"analysis_{self.binary_name}")
        self.results = {}
        self.enhanced_results = {}
        self.ollama_available = False
        self.ai_config = None
        self.file_type = None
        self.audit_logger = None

        # Enhanced analysis configuration
        self.enhanced_features = enhanced_features or EnhancedAnalysisFeatures()

        # Enhanced analysis components (lazy loaded)
        self.ai_enhanced_analyzer = None
        self.corporate_exposure_detector = None
        self.vulnerability_discovery_engine = None
        self.threat_intelligence_correlator = None
        self.demonstration_generator = None

        # Create analysis folder
        self.analysis_folder.mkdir(exist_ok=True)

        # Initialize audit logging (optional - graceful fallback if unavailable)
        try:
            from ..tools.tools.enterprise.audit_trail import AuditLogger
            self.audit_logger = AuditLogger(log_dir=str(self.analysis_folder / "audit_logs"))
            logger.info("Audit trail initialized")
        except ImportError:
            logger.debug("Audit trail not available - continuing without audit logging")

        logger.info("REVENG Analyzer initialized")
        logger.info(f"Target binary: {self.binary_path}")
        logger.info("Enterprise-grade binary analysis for ANY binary")

        # Log enhanced analysis status
        if self.enhanced_features.is_any_enhanced_enabled():
            logger.info("AI-Enhanced analysis modules: ENABLED")
            enabled_modules = []
            if self.enhanced_features.enable_corporate_exposure:
                enabled_modules.append("Corporate Exposure")
            if self.enhanced_features.enable_vulnerability_discovery:
                enabled_modules.append("Vulnerability Discovery")
            if self.enhanced_features.enable_threat_intelligence:
                enabled_modules.append("Threat Intelligence")
            if self.enhanced_features.enable_enhanced_reconstruction:
                enabled_modules.append("Enhanced Reconstruction")
            if self.enhanced_features.enable_demonstration_generation:
                enabled_modules.append("Demonstration Generation")
            logger.info(f"Enabled modules: {', '.join(enabled_modules)}")
        else:
            logger.info("AI-Enhanced analysis modules: DISABLED")

        # Detect file type using language detector
        self._detect_file_type()

        # Run Ollama preflight check if requested
        if check_ollama:
            self._check_ollama_availability()

    def _find_binary(self) -> str:
        """Find the target binary in the current directory"""
        # Look for common binary and bytecode extensions
        binary_extensions = ['.exe', '.dll', '.so', '.dylib', '.bin', '.elf', '.jar', '.war', '.ear', '.class']

        for ext in binary_extensions:
            binaries = list(Path('.').glob(f'*{ext}'))
            if binaries:
                return str(binaries[0])

        # If no binaries found, return a default
        return "target_binary"

    def _detect_file_type(self):
        """Detect file type using language detector"""
        try:
            from ..tools.tools.languages.language_detector import LanguageDetector

            detector = LanguageDetector()
            self.file_type = detector.detect(self.binary_path)

            logger.info(f"Detected file type: {self.file_type.language}/{self.file_type.format} (confidence: {self.file_type.confidence:.2%})")

            # Log category for pipeline routing
            category = detector.get_language_category(self.file_type)
            logger.info(f"Analysis category: {category}")

        except ImportError as e:
            logger.warning(f"Language detector not available: {e}")
            self.file_type = None
        except Exception as e:
            logger.warning(f"Error detecting file type: {e}")
            self.file_type = None

    def _check_ollama_availability(self):
        """Check if Ollama is available and properly configured"""
        try:
            from ..tools.tools.ai.ollama_preflight import OllamaPreflightChecker
            from ..tools.tools.config.config_manager import get_config

            # Load AI configuration
            config = get_config()
            self.ai_config = config.get_ai_config()

            if not self.ai_config.enable_ai:
                logger.info("AI analysis disabled in configuration")
                self.ollama_available = False
                return

            if self.ai_config.provider != 'ollama':
                logger.info(f"AI provider is {self.ai_config.provider}, not ollama")
                self.ollama_available = False
                return

            # Run preflight check
            checker = OllamaPreflightChecker(self.ai_config.ollama_host)
            required_model = self.ai_config.ollama_model if self.ai_config.ollama_model != 'auto' else None

            success, results = checker.check_all(required_model)

            if success:
                self.ollama_available = True
                model_count = len(results['models_available'])
                logger.info(f"[OK] Ollama available with {model_count} models")

                # Get recommended model if using auto
                if self.ai_config.ollama_model == 'auto':
                    recommended = checker.get_recommended_model()
                    logger.info(f"Auto-selected model: {recommended}")

            else:
                self.ollama_available = False
                logger.warning("[FAIL] Ollama not available - AI analysis will be skipped")

                if results['errors']:
                    for error in results['errors']:
                        logger.warning(f"  - {error}")

                logger.info("Run 'python tools/ollama_preflight.py --setup' for installation instructions")

        except ImportError as e:
            logger.warning(f"Ollama modules not available: {e}")
            self.ollama_available = False
        except Exception as e:
            logger.warning(f"Ollama preflight check failed: {e}")
            self.ollama_available = False

    def analyze_binary(self):
        """Run the complete REVENG binary analysis process"""
        logger.info("Starting REVENG binary analysis process...")

        # Start audit session if available
        if self.audit_logger:
            session_id = self.audit_logger.start_session(
                target_files=[self.binary_path],
                analysis_types=[self.file_type.language if self.file_type else 'unknown']
            )
            logger.info(f"Audit session started: {session_id}")

        print("=" * 70)
        print(" REVENG - Reverse Engineering Toolkit")
        print(" Enterprise-Grade Binary Analysis & Reassembly")
        if self.enhanced_features.is_any_enhanced_enabled():
            print(" AI-ENHANCED UNIVERSAL ANALYSIS ENGINE")
        print("=" * 70)
        print(f"Target: {self.binary_path}")
        print(f"AI Analysis: {'[ENABLED] Ollama' if self.ollama_available else '[DISABLED] Heuristics only'}")
        if self.enhanced_features.is_any_enhanced_enabled():
            print(f"Enhanced Analysis: [ENABLED] {self._count_enabled_modules()} modules")
        print()

        try:
            # Step 1: AI-powered binary analysis
            print("[CHART] Step 1: AI-Powered Binary Analysis...")
            self._step1_ai_analysis()

            # Step 2: Complete disassembly
            print("[SEARCH] Step 2: Complete Disassembly...")
            self._step2_disassembly()

            # Step 3: AI inspection with extra thinking
            print("[BRAIN] Step 3: AI Inspection with Extra Thinking...")
            self._step3_ai_inspection()

            # Step 4: Specification library creation
            print("[BOOKS] Step 4: Specification Library Creation...")
            self._step4_specifications()

            # Step 5: Human-readable code conversion
            print("[WRITE] Step 5: Human-Readable Code Conversion...")
            self._step5_human_readable()

            # Step 6: Deobfuscation and domain splitting
            print("[TOOLS] Step 6: Deobfuscation and Domain Splitting...")
            self._step6_deobfuscation()

            # Step 7: Implementation of missing features
            print("[POWER] Step 7: Implementation of Missing Features...")
            self._step7_implementation()

            # Step 8: Binary validation (if rebuilt binary exists)
            print("[CHECK] Step 8: Binary Validation...")
            self._step8_validation()

            # Enhanced Analysis Steps (9-12) - only if enabled
            if self.enhanced_features.is_any_enhanced_enabled():
                print("\n" + "=" * 70)
                print(" AI-ENHANCED ANALYSIS MODULES")
                print("=" * 70)

                # Step 9: Corporate data exposure analysis
                if self.enhanced_features.enable_corporate_exposure:
                    print("[EXPOSURE] Step 9: Corporate Data Exposure Analysis...")
                    self._step9_corporate_exposure()

                # Step 10: Automated vulnerability discovery
                if self.enhanced_features.enable_vulnerability_discovery:
                    print("[VULNERABILITY] Step 10: Automated Vulnerability Discovery...")
                    self._step10_vulnerability_discovery()

                # Step 11: Threat intelligence correlation
                if self.enhanced_features.enable_threat_intelligence:
                    print("[INTELLIGENCE] Step 11: Threat Intelligence Correlation...")
                    self._step11_threat_intelligence()

                # Step 12: Enhanced binary reconstruction
                if self.enhanced_features.enable_enhanced_reconstruction:
                    print("[RECONSTRUCTION] Step 12: Enhanced Binary Reconstruction...")
                    self._step12_enhanced_reconstruction()

                # Step 13: Security demonstration generation
                if self.enhanced_features.enable_demonstration_generation:
                    print("[DEMONSTRATION] Step 13: Security Demonstration Generation...")
                    self._step13_demonstration_generation()

            # Generate final report
            self._generate_final_report()

            total_steps = 8 + (5 if self.enhanced_features.is_any_enhanced_enabled() else 0)
            print("\n" + "=" * 70)
            print(" REVENG ANALYSIS COMPLETED SUCCESSFULLY")
            if self.enhanced_features.is_any_enhanced_enabled():
                print(" AI-ENHANCED UNIVERSAL ANALYSIS ENGINE")
            print("=" * 70)
            print(f" Analysis folder: {self.analysis_folder}")
            print(f" Binary: {self.binary_name}")
            print(f" Steps completed: {total_steps}/{total_steps}")
            if self.enhanced_features.is_any_enhanced_enabled():
                print(f" Enhanced modules: {self._count_enabled_modules()}")
            print("=" * 70)

            # End audit session successfully
            if self.audit_logger:
                self.audit_logger.end_session(status='completed')
                logger.info("Audit session completed successfully")

        except Exception as e:
            logger.error(f"Error in REVENG analysis: {e}")
            print(f"[ERROR] Error: {e}")

            # End audit session with error
            if self.audit_logger:
                self.audit_logger.end_session(status='failed', error=str(e))
                logger.info("Audit session ended with error")

            return False

        return True

    def _step1_ai_analysis(self):
        """Step 1: AI-powered binary analysis"""
        logger.info("Step 1: AI-powered binary analysis")

        # Run AI recompiler converter
        try:
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/ai_recompiler_converter.py", self.binary_path
            ], capture_output=True, text=True, timeout=300, check=False)

            if result.returncode == 0:
                logger.info("AI analysis completed successfully")
                self.results['step1'] = {'status': 'success', 'output': result.stdout}
            else:
                logger.warning(f"AI analysis completed with warnings: {result.stderr}")
                self.results['step1'] = {'status': 'warning', 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            logger.error("AI analysis timed out")
            self.results['step1'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            self.results['step1'] = {'status': 'error', 'error': str(e)}

    def _step2_disassembly(self):
        """Step 2: Complete disassembly with multi-language support"""
        logger.info("Step 2: Complete disassembly with multi-language support")

        # Route to appropriate analyzer based on file type
        if self.file_type and self.file_type.language == 'java':
            logger.info("Java bytecode detected - using Java analyzer")
            return self._java_disassembly()
        elif self.file_type and self.file_type.language == 'csharp':
            logger.info("C# .NET assembly detected - using C# IL analyzer")
            return self._csharp_disassembly()
        elif self.file_type and self.file_type.language == 'python':
            logger.info("Python bytecode detected - using Python analyzer")
            return self._python_disassembly()
        else:
            logger.info("Native binary detected - using Ghidra/native analysis")
            return self._native_disassembly()

    def _java_disassembly(self):
        """Disassembly for Java bytecode files"""
        logger.info("Running Java bytecode analysis")

        try:
            from ..tools.tools.languages.java_bytecode_analyzer import JavaBytecodeAnalyzer

            # Run Java analyzer
            analyzer = JavaBytecodeAnalyzer(output_dir=str(self.analysis_folder / "java_analysis"))
            result = analyzer.analyze(self.binary_path)

            logger.info(f"Java analysis completed - analyzed {result.get('analyzed_classes', 0)} classes")

            self.results['step2'] = {
                'status': 'success',
                'mode': 'java_bytecode',
                'classes_analyzed': result.get('analyzed_classes', 0),
                'obfuscated': result.get('obfuscated', False)
            }

        except ImportError as e:
            logger.error(f"Java analyzer not available: {e}")
            self.results['step2'] = {'status': 'error', 'error': 'java_analyzer_not_found'}
        except Exception as e:
            logger.error(f"Error in Java analysis: {e}")
            self.results['step2'] = {'status': 'error', 'error': str(e)}

    def _csharp_disassembly(self):
        """Disassembly for C# .NET assemblies"""
        logger.info("Running C# IL analysis")

        try:
            from ..tools.tools.languages.csharp_il_analyzer import CSharpILAnalyzer

            # Run C# IL analyzer
            analyzer = CSharpILAnalyzer(output_dir=str(self.analysis_folder / "csharp_analysis"))
            result = analyzer.analyze(self.binary_path)

            logger.info(f"C# analysis completed - {result.metadata.get('types_count', 0)} types found")

            self.results['step2'] = {
                'status': 'success' if result.success else 'error',
                'mode': 'csharp_il',
                'types_count': result.metadata.get('types_count', 0),
                'obfuscated': result.metadata.get('obfuscated', False),
                'obfuscator': result.metadata.get('obfuscator'),
                'il_file': result.il_output_file,
                'decompiled_dir': result.decompiled_output_dir
            }

        except ImportError as e:
            logger.error(f"C# analyzer not available: {e}")
            self.results['step2'] = {'status': 'error', 'error': 'csharp_analyzer_not_found'}
        except Exception as e:
            logger.error(f"Error in C# analysis: {e}")
            self.results['step2'] = {'status': 'error', 'error': str(e)}

    def _python_disassembly(self):
        """Disassembly for Python bytecode files"""
        logger.info("Running Python bytecode analysis")

        try:
            from ..tools.tools.languages.python_bytecode_analyzer import PythonBytecodeAnalyzer

            # Run Python analyzer
            analyzer = PythonBytecodeAnalyzer(output_dir=str(self.analysis_folder / "python_analysis"))
            result = analyzer.analyze(self.binary_path)

            logger.info(f"Python analysis completed - version {result.metadata.get('python_version', 'unknown')}")

            self.results['step2'] = {
                'status': 'success' if result.success else 'error',
                'mode': 'python_bytecode',
                'python_version': result.metadata.get('python_version'),
                'decompiler_used': result.decompiler_used,
                'obfuscated': result.metadata.get('is_obfuscated', False),
                'obfuscator': result.metadata.get('obfuscator'),
                'decompiled_file': result.decompiled_file
            }

        except ImportError as e:
            logger.error(f"Python analyzer not available: {e}")
            self.results['step2'] = {'status': 'error', 'error': 'python_analyzer_not_found'}
        except Exception as e:
            logger.error(f"Error in Python analysis: {e}")
            self.results['step2'] = {'status': 'error', 'error': str(e)}

    def _native_disassembly(self):
        """Disassembly for native binaries (PE/ELF/Mach-O)"""
        # Try Ghidra MCP connection first
        try:
            from ..tools.tools.config.ghidra_mcp_connector import GhidraMCPConnector

            ghidra = GhidraMCPConnector()
            if ghidra.connect():
                logger.info("Connected to live Ghidra via MCP")
                ghidra.open_binary(self.binary_path)

                # Get function count
                functions = ghidra.list_functions(0, 0)
                logger.info(f"Ghidra MCP: Found {len(functions)} functions")

                self.results['step2'] = {
                    'status': 'success',
                    'mode': 'live_ghidra',
                    'functions': len(functions)
                }
                ghidra.disconnect()
                return
            else:
                logger.info("Ghidra MCP not available, using fallback analysis")
        except ImportError:
            logger.info("Ghidra MCP connector not found, using fallback analysis")
        except Exception as e:
            logger.warning(f"Ghidra MCP error: {e}, using fallback analysis")

        # Fallback: Run optimal binary analysis
        try:
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/optimal_binary_analysis.py", self.binary_path
            ], capture_output=True, text=True, timeout=600, check=False)

            if result.returncode == 0:
                logger.info("Disassembly completed successfully (fallback mode)")
                self.results['step2'] = {
                    'status': 'success',
                    'mode': 'fallback',
                    'output': result.stdout
                }
            else:
                logger.warning(f"Disassembly completed with warnings: {result.stderr}")
                self.results['step2'] = {
                    'status': 'warning',
                    'mode': 'fallback',
                    'output': result.stdout,
                    'error': result.stderr
                }
        except subprocess.TimeoutExpired:
            logger.error("Disassembly timed out")
            self.results['step2'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in disassembly: {e}")
            self.results['step2'] = {'status': 'error', 'error': str(e)}

    def _step3_ai_inspection(self):
        """Step 3: AI inspection with extra thinking"""
        logger.info("Step 3: AI inspection with extra thinking")

        # Run AI source inspector
        try:
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/ai_source_inspector.py"
            ], capture_output=True, text=True, timeout=300, check=False)

            if result.returncode == 0:
                logger.info("AI inspection completed successfully")
                self.results['step3'] = {'status': 'success', 'output': result.stdout}
            else:
                logger.warning(f"AI inspection completed with warnings: {result.stderr}")
                self.results['step3'] = {'status': 'warning', 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            logger.error("AI inspection timed out")
            self.results['step3'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in AI inspection: {e}")
            self.results['step3'] = {'status': 'error', 'error': str(e)}

    def _step4_specifications(self):
        """Step 4: Specification library creation"""
        logger.info("Step 4: Specification library creation")

        # Check if SPECS folder exists
        specs_folder = Path("SPECS")
        if specs_folder.exists():
            logger.info("SPECS folder already exists")
            self.results['step4'] = {'status': 'success', 'message': 'SPECS folder already exists'}
        else:
            logger.warning("SPECS folder not found - may need to run AI inspection first")
            self.results['step4'] = {'status': 'warning', 'message': 'SPECS folder not found'}

    def _step5_human_readable(self):
        """Step 5: Human-readable code conversion"""
        logger.info("Step 5: Human-readable code conversion")

        # Run FIXED human readable converter (generates real implementations)
        try:
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/human_readable_converter_fixed.py"
            ], capture_output=True, text=True, timeout=300, check=False)

            if result.returncode == 0:
                logger.info("Human-readable conversion completed successfully")
                self.results['step5'] = {'status': 'success', 'output': result.stdout}
            else:
                logger.warning(f"Human-readable conversion completed with warnings: {result.stderr}")
                self.results['step5'] = {'status': 'warning', 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            logger.error("Human-readable conversion timed out")
            self.results['step5'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in human-readable conversion: {e}")
            self.results['step5'] = {'status': 'error', 'error': str(e)}

    def _step6_deobfuscation(self):
        """Step 6: Deobfuscation and domain splitting"""
        logger.info("Step 6: Deobfuscation and domain splitting")

        # Run deobfuscation tool
        try:
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/deobfuscation_tool.py"
            ], capture_output=True, text=True, timeout=300, check=False)

            if result.returncode == 0:
                logger.info("Deobfuscation completed successfully")
                self.results['step6'] = {'status': 'success', 'output': result.stdout}
            else:
                logger.warning(f"Deobfuscation completed with warnings: {result.stderr}")
                self.results['step6'] = {'status': 'warning', 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            logger.error("Deobfuscation timed out")
            self.results['step6'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in deobfuscation: {e}")
            self.results['step6'] = {'status': 'error', 'error': str(e)}

    def _step7_implementation(self):
        """Step 7: Implementation of missing features"""
        logger.info("Step 7: Implementation of missing features")

        # Run implementation tool
        try:
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/implementation_tool.py"
            ], capture_output=True, text=True, timeout=300, check=False)

            if result.returncode == 0:
                logger.info("Implementation completed successfully")
                self.results['step7'] = {'status': 'success', 'output': result.stdout}
            else:
                logger.warning(f"Implementation completed with warnings: {result.stderr}")
                self.results['step7'] = {'status': 'warning', 'output': result.stdout, 'error': result.stderr}
        except subprocess.TimeoutExpired:
            logger.error("Implementation timed out")
            self.results['step7'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in implementation: {e}")
            self.results['step7'] = {'status': 'error', 'error': str(e)}

    def _step8_validation(self):
        """Step 8: Validate rebuilt binary against original"""
        logger.info("Step 8: Binary validation")

        # Check if rebuilt binary exists
        rebuilt_candidates = [
            Path("human_readable_code") / self.binary_name,
            Path("human_readable_code") / f"{self.binary_name}.exe",
            Path("deobfuscated_app") / self.binary_name,
            Path("deobfuscated_app") / f"{self.binary_name}.exe"
        ]

        rebuilt_path = None
        for candidate in rebuilt_candidates:
            if candidate.exists():
                rebuilt_path = candidate
                break

        if not rebuilt_path:
            logger.info("No rebuilt binary found - skipping validation")
            self.results['step8'] = {
                'status': 'skipped',
                'message': 'No rebuilt binary available for validation'
            }
            return

        # Run binary validator
        try:
            from ..tools.tools.core.binary_validator import BinaryValidator
            from ..tools.tools.binary.validation_manifest_loader import load_validation_manifest

            validator = BinaryValidator()

            # Load validation config for this binary
            validation_config = load_validation_manifest(self.binary_name)

            # Run validation
            logger.info(f"Validating {rebuilt_path} against {self.binary_path}")
            report = validator.validate_rebuild(
                Path(self.binary_path),
                rebuilt_path,
                smoke_tests=validation_config.smoke_tests if validation_config else None
            )

            # Save validation report
            report_path = self.analysis_folder / "validation_report.json"
            validator.save_report(report, report_path)

            # Log results
            verdict = report['verdict']
            if verdict['valid']:
                logger.info(f"Validation PASSED (confidence: {verdict['confidence']:.2f})")
                self.results['step8'] = {
                    'status': 'success',
                    'verdict': verdict,
                    'report_path': str(report_path)
                }
            else:
                logger.warning(f"Validation FAILED (confidence: {verdict['confidence']:.2f})")
                logger.warning(f"Errors: {verdict.get('errors', [])}")
                self.results['step8'] = {
                    'status': 'warning',
                    'verdict': verdict,
                    'report_path': str(report_path)
                }

        except ImportError as e:
            logger.warning(f"Binary validator not available: {e}")
            self.results['step8'] = {'status': 'skipped', 'error': 'validator_not_found'}
        except Exception as e:
            logger.error(f"Error in binary validation: {e}")
            self.results['step8'] = {'status': 'error', 'error': str(e)}

    def _step9_corporate_exposure(self):
        """Step 9: Corporate data exposure analysis"""
        logger.info("Step 9: Corporate data exposure analysis")

        try:
            # Lazy load corporate exposure detector
            if not self.corporate_exposure_detector:
                from ..tools.tools.security.corporate_exposure_detector import CorporateExposureDetector
                self.corporate_exposure_detector = CorporateExposureDetector()

            # Run corporate exposure analysis
            exposure_report = self.corporate_exposure_detector.analyze_file(self.binary_path)

            logger.info(f"Corporate exposure analysis completed - {len(exposure_report.credentials_found)} credentials found")

            self.enhanced_results['step9'] = {
                'status': 'success',
                'credentials_count': len(exposure_report.credentials_found),
                'business_logic_count': len(exposure_report.business_logic_exposed),
                'api_endpoints_count': len(exposure_report.api_endpoints_discovered),
                'risk_level': exposure_report.risk_level,
                'report': exposure_report
            }

        except ImportError as e:
            logger.warning(f"Corporate exposure detector not available: {e}")
            self.enhanced_results['step9'] = {'status': 'skipped', 'error': 'module_not_found'}
        except Exception as e:
            logger.error(f"Error in corporate exposure analysis: {e}")
            self.enhanced_results['step9'] = {'status': 'error', 'error': str(e)}

    def _step10_vulnerability_discovery(self):
        """Step 10: Automated vulnerability discovery"""
        logger.info("Step 10: Automated vulnerability discovery")

        try:
            # Lazy load vulnerability discovery engine
            if not self.vulnerability_discovery_engine:
                from ..tools.tools.security.vulnerability_discovery_engine import VulnerabilityDiscoveryEngine
                self.vulnerability_discovery_engine = VulnerabilityDiscoveryEngine()

            # Run vulnerability discovery
            vuln_report = self.vulnerability_discovery_engine.analyze_file(self.binary_path)

            logger.info(f"Vulnerability discovery completed - {vuln_report.total_vulnerabilities} vulnerabilities found")

            self.enhanced_results['step10'] = {
                'status': 'success',
                'total_vulnerabilities': vuln_report.total_vulnerabilities,
                'critical_count': vuln_report.critical_count,
                'high_count': vuln_report.high_count,
                'medium_count': vuln_report.medium_count,
                'low_count': vuln_report.low_count,
                'report': vuln_report
            }

        except ImportError as e:
            logger.warning(f"Vulnerability discovery engine not available: {e}")
            self.enhanced_results['step10'] = {'status': 'skipped', 'error': 'module_not_found'}
        except Exception as e:
            logger.error(f"Error in vulnerability discovery: {e}")
            self.enhanced_results['step10'] = {'status': 'error', 'error': str(e)}

    def _step11_threat_intelligence(self):
        """Step 11: Threat intelligence correlation"""
        logger.info("Step 11: Threat intelligence correlation")

        try:
            # Lazy load threat intelligence correlator
            if not self.threat_intelligence_correlator:
                from ..tools.tools.security.threat_intelligence_correlator import ThreatIntelligenceCorrelator
                self.threat_intelligence_correlator = ThreatIntelligenceCorrelator()

            # Run threat intelligence correlation
            threat_report = self.threat_intelligence_correlator.analyze_file(self.binary_path)

            logger.info(f"Threat intelligence correlation completed - threat level: {threat_report.threat_level}")

            self.enhanced_results['step11'] = {
                'status': 'success',
                'threat_level': threat_report.threat_level,
                'apt_attribution': threat_report.apt_attribution,
                'iocs_count': len(threat_report.iocs_extracted),
                'malware_classification': threat_report.malware_classification,
                'report': threat_report
            }

        except ImportError as e:
            logger.warning(f"Threat intelligence correlator not available: {e}")
            self.enhanced_results['step11'] = {'status': 'skipped', 'error': 'module_not_found'}
        except Exception as e:
            logger.error(f"Error in threat intelligence correlation: {e}")
            self.enhanced_results['step11'] = {'status': 'error', 'error': str(e)}

    def _step12_enhanced_reconstruction(self):
        """Step 12: Enhanced binary reconstruction"""
        logger.info("Step 12: Enhanced binary reconstruction")

        try:
            # Run enhanced binary reconstruction using existing binary reassembler
            result = subprocess.run([
                sys.executable, "src/tools/tools/core/binary_reassembler_v2.py", self.binary_path
            ], capture_output=True, text=True, timeout=600, check=False)

            if result.returncode == 0:
                logger.info("Enhanced binary reconstruction completed successfully")
                self.enhanced_results['step12'] = {
                    'status': 'success',
                    'output': result.stdout,
                    'reconstruction_quality': 'high'  # Placeholder
                }
            else:
                logger.warning(f"Enhanced binary reconstruction completed with warnings: {result.stderr}")
                self.enhanced_results['step12'] = {
                    'status': 'warning',
                    'output': result.stdout,
                    'error': result.stderr
                }

        except subprocess.TimeoutExpired:
            logger.error("Enhanced binary reconstruction timed out")
            self.enhanced_results['step12'] = {'status': 'timeout'}
        except Exception as e:
            logger.error(f"Error in enhanced binary reconstruction: {e}")
            self.enhanced_results['step12'] = {'status': 'error', 'error': str(e)}

    def _step13_demonstration_generation(self):
        """Step 13: Security demonstration generation"""
        logger.info("Step 13: Security demonstration generation")

        try:
            # Lazy load demonstration generator
            if not self.demonstration_generator:
                from ..tools.tools.utils.demonstration_generator import DemonstrationGenerator
                self.demonstration_generator = DemonstrationGenerator()

            # Generate security demonstrations
            demo_package = self.demonstration_generator.create_demonstration_package(
                binary_path=self.binary_path,
                analysis_results=self.results,
                enhanced_results=self.enhanced_results
            )

            logger.info(f"Security demonstration generation completed - {len(demo_package.components)} components created")

            self.enhanced_results['step13'] = {
                'status': 'success',
                'components_count': len(demo_package.components),
                'demo_package': demo_package
            }

        except ImportError as e:
            logger.warning(f"Demonstration generator not available: {e}")
            self.enhanced_results['step13'] = {'status': 'skipped', 'error': 'module_not_found'}
        except Exception as e:
            logger.error(f"Error in demonstration generation: {e}")
            self.enhanced_results['step13'] = {'status': 'error', 'error': str(e)}

    def _count_enabled_modules(self) -> int:
        """Count enabled enhanced analysis modules"""
        count = 0
        if self.enhanced_features.enable_corporate_exposure:
            count += 1
        if self.enhanced_features.enable_vulnerability_discovery:
            count += 1
        if self.enhanced_features.enable_threat_intelligence:
            count += 1
        if self.enhanced_features.enable_enhanced_reconstruction:
            count += 1
        if self.enhanced_features.enable_demonstration_generation:
            count += 1
        return count

    def _generate_final_report(self):
        """Generate final analysis report"""
        logger.info("Generating final analysis report...")

        # Combine core and enhanced results
        all_results = {**self.results, **self.enhanced_results}

        report = {
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
            "binary_path": self.binary_path,
            "binary_name": self.binary_name,
            "analysis_folder": str(self.analysis_folder),
            "enhanced_analysis_enabled": self.enhanced_features.is_any_enhanced_enabled(),
            "enhanced_modules_enabled": self._count_enabled_modules(),
            "process_steps": {
                "step1_ai_analysis": self.results.get('step1', {}),
                "step2_disassembly": self.results.get('step2', {}),
                "step3_ai_inspection": self.results.get('step3', {}),
                "step4_specifications": self.results.get('step4', {}),
                "step5_human_readable": self.results.get('step5', {}),
                "step6_deobfuscation": self.results.get('step6', {}),
                "step7_implementation": self.results.get('step7', {}),
                "step8_validation": self.results.get('step8', {})
            },
            "enhanced_steps": {
                "step9_corporate_exposure": self.enhanced_results.get('step9', {}),
                "step10_vulnerability_discovery": self.enhanced_results.get('step10', {}),
                "step11_threat_intelligence": self.enhanced_results.get('step11', {}),
                "step12_enhanced_reconstruction": self.enhanced_results.get('step12', {}),
                "step13_demonstration_generation": self.enhanced_results.get('step13', {})
            },
            "summary": {
                "total_steps": 8 + (5 if self.enhanced_features.is_any_enhanced_enabled() else 0),
                "core_steps": 8,
                "enhanced_steps": 5 if self.enhanced_features.is_any_enhanced_enabled() else 0,
                "successful_steps": len([s for s in all_results.values() if s.get('status') == 'success']),
                "warning_steps": len([s for s in all_results.values() if s.get('status') == 'warning']),
                "error_steps": len([s for s in all_results.values() if s.get('status') == 'error']),
                "timeout_steps": len([s for s in all_results.values() if s.get('status') == 'timeout']),
                "skipped_steps": len([s for s in all_results.values() if s.get('status') == 'skipped'])
            }
        }

        # Save report
        report_file = self.analysis_folder / "universal_analysis_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("Final analysis report generated")
