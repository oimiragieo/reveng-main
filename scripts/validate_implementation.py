#!/usr/bin/env python3
"""
Comprehensive validation script for REVENG implementation
"""

import sys
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
import json
import yaml


class REVENGValidator:
    """Validate REVENG implementation"""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.src_path = project_root / "src"
        self.tests_path = project_root / "tests"
        self.docs_path = project_root / "docs"
        self.results = {
            "validation_date": None,
            "project_version": "2.1.0",
            "components": {},
            "tests": {},
            "documentation": {},
            "overall_status": "unknown"
        }

    def validate_core_components(self) -> Dict[str, Any]:
        """Validate core components"""
        print("🔍 Validating core components...")

        core_components = {
            "dependency_manager": "src/reveng/core/dependency_manager.py",
            "errors": "src/reveng/core/errors.py",
            "logger": "src/reveng/core/logger.py"
        }

        results = {}
        for component, path in core_components.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[component] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[component] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_analyzers(self) -> Dict[str, Any]:
        """Validate analyzer components"""
        print("🔍 Validating analyzers...")

        analyzers = {
            "dotnet_analyzer": "src/reveng/analyzers/dotnet_analyzer.py",
            "business_logic_extractor": "src/reveng/analyzers/business_logic_extractor.py"
        }

        results = {}
        for analyzer, path in analyzers.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[analyzer] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[analyzer] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_pe_components(self) -> Dict[str, Any]:
        """Validate PE analysis components"""
        print("🔍 Validating PE components...")

        pe_components = {
            "resource_extractor": "src/reveng/pe/resource_extractor.py",
            "import_analyzer": "src/reveng/pe/import_analyzer.py"
        }

        results = {}
        for component, path in pe_components.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[component] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[component] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_tools(self) -> Dict[str, Any]:
        """Validate tool components"""
        print("🔍 Validating tools...")

        tools = {
            "hex_editor": "src/reveng/tools/hex_editor.py"
        }

        results = {}
        for tool, path in tools.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[tool] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[tool] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_ghidra_components(self) -> Dict[str, Any]:
        """Validate Ghidra components"""
        print("🔍 Validating Ghidra components...")

        ghidra_components = {
            "scripting_engine": "src/reveng/ghidra/scripting_engine.py"
        }

        results = {}
        for component, path in ghidra_components.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[component] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[component] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_pipeline_components(self) -> Dict[str, Any]:
        """Validate pipeline components"""
        print("🔍 Validating pipeline components...")

        pipeline_components = {
            "pipeline_engine": "src/reveng/pipeline/pipeline_engine.py"
        }

        results = {}
        for component, path in pipeline_components.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[component] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[component] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_ml_components(self) -> Dict[str, Any]:
        """Validate ML components"""
        print("🔍 Validating ML components...")

        ml_components = {
            "code_reconstruction": "src/reveng/ml/code_reconstruction.py",
            "anomaly_detection": "src/reveng/ml/anomaly_detection.py",
            "integration": "src/reveng/ml/integration.py",
            "ml_init": "src/reveng/ml/__init__.py"
        }

        results = {}
        for component, path in ml_components.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[component] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[component] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_cli_components(self) -> Dict[str, Any]:
        """Validate CLI components"""
        print("🔍 Validating CLI components...")

        cli_components = {
            "reveng_py": "reveng.py",
            "cli_module": "src/reveng/cli.py"
        }

        results = {}
        for component, path in cli_components.items():
            file_path = self.project_root / path
            if file_path.exists():
                results[component] = {
                    "status": "✅ Found",
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                }
            else:
                results[component] = {
                    "status": "❌ Missing",
                    "path": str(file_path)
                }

        return results

    def validate_tests(self) -> Dict[str, Any]:
        """Validate test components"""
        print("🔍 Validating tests...")

        test_categories = {
            "unit_tests": "tests/unit/",
            "integration_tests": "tests/integration/",
            "e2e_tests": "tests/e2e/",
            "test_runner": "tests/run_all_tests.py"
        }

        results = {}
        for category, path in test_categories.items():
            test_path = self.project_root / path
            if test_path.exists():
                if test_path.is_dir():
                    test_files = list(test_path.glob("test_*.py"))
                    results[category] = {
                        "status": "✅ Found",
                        "path": str(test_path),
                        "test_files": len(test_files),
                        "files": [f.name for f in test_files]
                    }
                else:
                    results[category] = {
                        "status": "✅ Found",
                        "path": str(test_path),
                        "size": test_path.stat().st_size
                    }
            else:
                results[category] = {
                    "status": "❌ Missing",
                    "path": str(test_path)
                }

        return results

    def validate_documentation(self) -> Dict[str, Any]:
        """Validate documentation"""
        print("🔍 Validating documentation...")

        doc_files = {
            "api_reference": "docs/api-reference.md",
            "user_guide": "docs/user-guide.md",
            "developer_guide": "docs/developer-guide.md",
            "overhaul_plan": "docs/REVENG_OVERHAUL_PLAN.md",
            "validation_report": "VALIDATION_REPORT.md",
            "transformation_summary": "TRANSFORMATION_SUMMARY.md",
            "case_study": "docs/case-studies/karp-analysis.md",
            "advanced_analysis": "docs/guides/advanced-analysis.md",
            "windows_analysis": "docs/guides/windows-analysis.md",
            "pipeline_development": "docs/guides/pipeline-development.md",
            "plugin_development": "docs/guides/plugin-development.md",
            "doc_generator": "docs/generate_documentation.py"
        }

        results = {}
        for doc_name, path in doc_files.items():
            doc_path = self.project_root / path
            if doc_path.exists():
                results[doc_name] = {
                    "status": "✅ Found",
                    "path": str(doc_path),
                    "size": doc_path.stat().st_size
                }
            else:
                results[doc_name] = {
                    "status": "❌ Missing",
                    "path": str(doc_path)
                }

        return results

    def run_tests(self) -> Dict[str, Any]:
        """Run test suite"""
        print("🧪 Running tests...")

        test_results = {}

        # Run unit tests
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "tests/unit/", "-v", "--tb=short"],
                capture_output=True, text=True, timeout=300
            )
            test_results["unit_tests"] = {
                "status": "✅ Passed" if result.returncode == 0 else "❌ Failed",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            test_results["unit_tests"] = {
                "status": "⏰ Timeout",
                "returncode": -1
            }
        except Exception as e:
            test_results["unit_tests"] = {
                "status": "❌ Error",
                "error": str(e)
            }

        # Run integration tests
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "tests/integration/", "-v", "--tb=short"],
                capture_output=True, text=True, timeout=300
            )
            test_results["integration_tests"] = {
                "status": "✅ Passed" if result.returncode == 0 else "❌ Failed",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            test_results["integration_tests"] = {
                "status": "⏰ Timeout",
                "returncode": -1
            }
        except Exception as e:
            test_results["integration_tests"] = {
                "status": "❌ Error",
                "error": str(e)
            }

        # Run E2E tests
        try:
            result = subprocess.run(
                ["python", "-m", "pytest", "tests/e2e/", "-v", "--tb=short"],
                capture_output=True, text=True, timeout=300
            )
            test_results["e2e_tests"] = {
                "status": "✅ Passed" if result.returncode == 0 else "❌ Failed",
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            test_results["e2e_tests"] = {
                "status": "⏰ Timeout",
                "returncode": -1
            }
        except Exception as e:
            test_results["e2e_tests"] = {
                "status": "❌ Error",
                "error": str(e)
            }

        return test_results

    def validate_imports(self) -> Dict[str, Any]:
        """Validate Python imports"""
        print("🔍 Validating imports...")

        import_results = {}

        # Test core imports
        try:
            import sys
            sys.path.insert(0, str(self.src_path))

            from reveng.core.dependency_manager import DependencyManager
            from reveng.core.errors import REVENGError
            from reveng.core.logger import REVENGLogger

            import_results["core_imports"] = "✅ Success"
        except Exception as e:
            import_results["core_imports"] = f"❌ Failed: {e}"

        # Test analyzer imports
        try:
            from reveng.analyzers.dotnet_analyzer import DotNetAnalyzer
            from reveng.analyzers.business_logic_extractor import BusinessLogicExtractor

            import_results["analyzer_imports"] = "✅ Success"
        except Exception as e:
            import_results["analyzer_imports"] = f"❌ Failed: {e}"

        # Test PE imports
        try:
            from reveng.pe.resource_extractor import PEResourceExtractor
            from reveng.pe.import_analyzer import ImportAnalyzer

            import_results["pe_imports"] = "✅ Success"
        except Exception as e:
            import_results["pe_imports"] = f"❌ Failed: {e}"

        # Test tool imports
        try:
            from reveng.tools.hex_editor import HexEditor

            import_results["tool_imports"] = "✅ Success"
        except Exception as e:
            import_results["tool_imports"] = f"❌ Failed: {e}"

        # Test Ghidra imports
        try:
            from reveng.ghidra.scripting_engine import GhidraScriptEngine

            import_results["ghidra_imports"] = "✅ Success"
        except Exception as e:
            import_results["ghidra_imports"] = f"❌ Failed: {e}"

        # Test pipeline imports
        try:
            from reveng.pipeline.pipeline_engine import AnalysisPipeline

            import_results["pipeline_imports"] = "✅ Success"
        except Exception as e:
            import_results["pipeline_imports"] = f"❌ Failed: {e}"

        # Test ML imports
        try:
            from reveng.ml.integration import MLIntegration
            from reveng.ml.code_reconstruction import MLCodeReconstruction
            from reveng.ml.anomaly_detection import MLAnomalyDetection

            import_results["ml_imports"] = "✅ Success"
        except Exception as e:
            import_results["ml_imports"] = f"❌ Failed: {e}"

        return import_results

    def generate_report(self) -> str:
        """Generate validation report"""
        report = f"""# REVENG Implementation Validation Report

**Validation Date:** {self.results['validation_date']}
**Project Version:** {self.results['project_version']}
**Overall Status:** {self.results['overall_status']}

## 📊 Summary

### Core Components
"""

        for component, result in self.results['components'].get('core', {}).items():
            report += f"- **{component}**: {result['status']}\n"

        report += "\n### Analyzers\n"
        for analyzer, result in self.results['components'].get('analyzers', {}).items():
            report += f"- **{analyzer}**: {result['status']}\n"

        report += "\n### PE Components\n"
        for component, result in self.results['components'].get('pe', {}).items():
            report += f"- **{component}**: {result['status']}\n"

        report += "\n### Tools\n"
        for tool, result in self.results['components'].get('tools', {}).items():
            report += f"- **{tool}**: {result['status']}\n"

        report += "\n### Ghidra Components\n"
        for component, result in self.results['components'].get('ghidra', {}).items():
            report += f"- **{component}**: {result['status']}\n"

        report += "\n### Pipeline Components\n"
        for component, result in self.results['components'].get('pipeline', {}).items():
            report += f"- **{component}**: {result['status']}\n"

        report += "\n### ML Components\n"
        for component, result in self.results['components'].get('ml', {}).items():
            report += f"- **{component}**: {result['status']}\n"

        report += "\n### CLI Components\n"
        for component, result in self.results['components'].get('cli', {}).items():
            report += f"- **{component}**: {result['status']}\n"

        report += "\n## 🧪 Test Results\n"
        for test_type, result in self.results['tests'].items():
            report += f"- **{test_type}**: {result['status']}\n"

        report += "\n## 📚 Documentation\n"
        for doc, result in self.results['documentation'].items():
            report += f"- **{doc}**: {result['status']}\n"

        report += "\n## 🔍 Import Validation\n"
        for import_type, result in self.results.get('imports', {}).items():
            report += f"- **{import_type}**: {result}\n"

        return report

    def run_validation(self) -> Dict[str, Any]:
        """Run complete validation"""
        print("🚀 Starting REVENG validation...")

        # Validate components
        self.results['components'] = {
            'core': self.validate_core_components(),
            'analyzers': self.validate_analyzers(),
            'pe': self.validate_pe_components(),
            'tools': self.validate_tools(),
            'ghidra': self.validate_ghidra_components(),
            'pipeline': self.validate_pipeline_components(),
            'ml': self.validate_ml_components(),
            'cli': self.validate_cli_components()
        }

        # Validate tests
        self.results['tests'] = self.validate_tests()

        # Validate documentation
        self.results['documentation'] = self.validate_documentation()

        # Validate imports
        self.results['imports'] = self.validate_imports()

        # Run tests
        self.results['test_results'] = self.run_tests()

        # Determine overall status
        all_components = []
        for category in self.results['components'].values():
            all_components.extend(category.values())

        all_found = all(comp.get('status') == '✅ Found' for comp in all_components)
        all_tests_passed = all(
            test.get('status') == '✅ Passed'
            for test in self.results['test_results'].values()
        )

        if all_found and all_tests_passed:
            self.results['overall_status'] = '✅ Complete'
        elif all_found:
            self.results['overall_status'] = '⚠️ Components Found, Tests Failed'
        else:
            self.results['overall_status'] = '❌ Incomplete'

        return self.results

    def save_results(self, output_path: Path):
        """Save validation results"""
        # Save JSON results
        json_path = output_path / "validation_results.json"
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        # Save markdown report
        report_path = output_path / "validation_report.md"
        with open(report_path, 'w') as f:
            f.write(self.generate_report())

        print(f"📁 Results saved to: {output_path}")
        print(f"📄 Files created:")
        print(f"  - {json_path.name}")
        print(f"  - {report_path.name}")


def main():
    """Main validation function"""
    project_root = Path(__file__).parent.parent
    validator = REVENGValidator(project_root)

    # Run validation
    results = validator.run_validation()

    # Save results
    output_dir = project_root / "validation_results"
    output_dir.mkdir(exist_ok=True)
    validator.save_results(output_dir)

    # Print summary
    print(f"\n{'='*60}")
    print(f"🎯 Validation Complete!")
    print(f"Overall Status: {results['overall_status']}")
    print(f"{'='*60}")

    if results['overall_status'] == '✅ Complete':
        print("🎉 All components validated successfully!")
        sys.exit(0)
    else:
        print("⚠️ Some components need attention!")
        sys.exit(1)


if __name__ == "__main__":
    main()
