#!/usr/bin/env python3
"""
REVENG Enhanced AI Analyzer
============================

Enhanced AI analysis with Ollama integration:
- Real LLM-powered function analysis
- Dynamic model selection
- Batch processing with progress bars
- Fallback to heuristics when needed
- Configurable via config.yaml
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict

import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    from tools.ollama_analyzer import OllamaAnalyzer, AnalysisResult
    from tools.config_manager import get_config
    from tools.progress_reporter import get_progress_reporter
    HAS_OLLAMA = True
except ImportError as e:
    HAS_OLLAMA = False
    logging.warning(f"Ollama analyzer not available: {e}")

logger = logging.getLogger(__name__)


class EnhancedAIAnalyzer:
    """Enhanced AI analyzer with Ollama support"""

    def __init__(self, binary_path: str):
        """Initialize enhanced AI analyzer"""
        self.binary_path = Path(binary_path)
        self.binary_name = self.binary_path.stem

        # Load configuration
        self.config = get_config()
        self.ai_config = self.config.get_ai_config()

        # Initialize AI analyzer if enabled
        self.ai_analyzer = None
        if self.ai_config.enable_ai and HAS_OLLAMA:
            self._init_ai_analyzer()

        # Progress reporter
        self.progress = get_progress_reporter(self.ai_config.show_progress)

        logger.info(f"Enhanced AI analyzer initialized for {self.binary_name}")
        if self.ai_analyzer:
            logger.info(f"AI provider: {self.ai_config.provider}")
            if self.ai_config.provider == 'ollama':
                logger.info(f"Ollama model: {self.ai_config.ollama_model}")

    def _init_ai_analyzer(self):
        """Initialize AI analyzer based on configuration"""
        if self.ai_config.provider == 'ollama':
            try:
                self.ai_analyzer = OllamaAnalyzer(
                    model_name=self.ai_config.ollama_model if self.ai_config.ollama_model != 'auto' else None,
                    ollama_host=self.ai_config.ollama_host,
                    timeout=self.ai_config.ollama_timeout,
                    temperature=self.ai_config.ollama_temperature,
                    max_tokens=self.ai_config.ollama_max_tokens
                )
                logger.info("Ollama analyzer initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Ollama: {e}")
                if self.ai_config.fallback_to_heuristics:
                    logger.info("Will use heuristic fallback")
                self.ai_analyzer = None

        elif self.ai_config.provider == 'anthropic':
            logger.warning("Anthropic provider not yet implemented")
            # TODO: Implement Anthropic integration
            self.ai_analyzer = None

        elif self.ai_config.provider == 'openai':
            logger.warning("OpenAI provider not yet implemented")
            # TODO: Implement OpenAI integration
            self.ai_analyzer = None

        else:
            logger.info("No AI provider configured")
            self.ai_analyzer = None

    def analyze_functions(
        self,
        functions: List[Dict[str, str]],
        output_folder: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Analyze multiple functions with AI

        Args:
            functions: List of dicts with 'name', 'code', 'address'
            output_folder: Where to save results

        Returns:
            Analysis report dict
        """
        if output_folder is None:
            output_folder = Path(f"ai_enhanced_analysis_{self.binary_name}")

        output_folder.mkdir(exist_ok=True, parents=True)

        # Limit number of functions if configured
        if self.ai_config.max_ai_functions > 0:
            functions = functions[:self.ai_config.max_ai_functions]
            logger.info(f"Limited to {len(functions)} functions")

        results = {}
        total = len(functions)

        logger.info(f"Analyzing {total} functions with {'AI' if self.ai_analyzer else 'heuristics'}")

        # Analyze each function
        for i, func in enumerate(self.progress.step(functions, "AI Analysis", unit="func")):
            func_name = func['name']

            if self.ai_analyzer:
                # Use AI analysis
                try:
                    result = self.ai_analyzer.analyze_function(
                        func['code'],
                        func_name,
                        func.get('context')
                    )
                    results[func_name] = asdict(result)
                except Exception as e:
                    logger.error(f"AI analysis failed for {func_name}: {e}")
                    if self.ai_config.fallback_to_heuristics:
                        results[func_name] = self._heuristic_analysis(func)
                    else:
                        results[func_name] = {'error': str(e)}
            else:
                # Use heuristic analysis
                results[func_name] = self._heuristic_analysis(func)

        # Generate summary report
        report = self._generate_report(results, total)

        # Save results
        self._save_results(results, report, output_folder)

        return report

    def _heuristic_analysis(self, func: Dict[str, str]) -> Dict[str, Any]:
        """Fallback heuristic analysis"""
        code = func['code'].lower()
        func_name = func['name']

        # Categorize by keywords
        category = "Unknown"
        purpose = f"Function {func_name}"

        if 'malloc' in code or 'free' in code or 'realloc' in code:
            category = "Memory"
            purpose = "Memory management operations"
        elif 'fopen' in code or 'fread' in code or 'fwrite' in code:
            category = "FileIO"
            purpose = "File I/O operations"
        elif 'socket' in code or 'connect' in code or 'recv' in code:
            category = "Network"
            purpose = "Network communication"
        elif 'js_' in func_name or 'javascript' in code:
            category = "JavaScript"
            purpose = "JavaScript engine operations"
        elif 'error' in func_name or 'exception' in code:
            category = "Error"
            purpose = "Error handling"

        # Assess complexity
        lines = len(func['code'].split('\n'))
        if lines > 100:
            complexity = "High"
        elif lines > 50:
            complexity = "Medium"
        else:
            complexity = "Low"

        # Security concerns
        security_concerns = []
        if 'strcpy' in code:
            security_concerns.append("Unsafe strcpy usage - potential buffer overflow")
        if 'sprintf' in code:
            security_concerns.append("Unsafe sprintf - use snprintf instead")
        if 'malloc' in code and 'bounds' not in code:
            security_concerns.append("Memory allocation without bounds checking")

        return {
            "purpose": purpose,
            "category": category,
            "complexity": complexity,
            "security_concerns": security_concerns,
            "suggested_name": None,
            "confidence": 0.4,  # Lower confidence for heuristics
            "reasoning": "Heuristic keyword-based analysis"
        }

    def _generate_report(self, results: Dict, total: int) -> Dict[str, Any]:
        """Generate summary report"""
        # Count categories
        categories = {}
        complexities = {'Low': 0, 'Medium': 0, 'High': 0, 'VeryHigh': 0}
        security_issues = []
        total_confidence = 0.0

        for func_name, analysis in results.items():
            if 'error' in analysis:
                continue

            # Category distribution
            category = analysis.get('category', 'Unknown')
            categories[category] = categories.get(category, 0) + 1

            # Complexity distribution
            complexity = analysis.get('complexity', 'Medium')
            complexities[complexity] = complexities.get(complexity, 0) + 1

            # Security concerns
            concerns = analysis.get('security_concerns', [])
            for concern in concerns:
                security_issues.append({
                    'function': func_name,
                    'concern': concern
                })

            # Confidence
            total_confidence += analysis.get('confidence', 0.0)

        avg_confidence = total_confidence / total if total > 0 else 0.0

        report = {
            'total_functions': total,
            'analyzed_functions': len(results),
            'ai_enabled': self.ai_analyzer is not None,
            'ai_provider': self.ai_config.provider if self.ai_analyzer else 'none',
            'ai_model': self.ai_config.ollama_model if self.ai_config.provider == 'ollama' else None,
            'average_confidence': round(avg_confidence, 2),
            'category_distribution': categories,
            'complexity_distribution': complexities,
            'security_issues_count': len(security_issues),
            'security_issues': security_issues[:10],  # Top 10
            'high_confidence_functions': [
                name for name, analysis in results.items()
                if analysis.get('confidence', 0) >= 0.8
            ]
        }

        return report

    def _save_results(
        self,
        results: Dict,
        report: Dict,
        output_folder: Path
    ):
        """Save analysis results to files"""
        # Save full results
        results_file = output_folder / "ai_analysis_results.json"
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2)

        logger.info(f"Saved results to {results_file}")

        # Save report
        report_file = output_folder / "ai_analysis_report.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Saved report to {report_file}")

        # Save markdown report
        md_file = output_folder / "ai_analysis_report.md"
        self._save_markdown_report(report, results, md_file)

        logger.info(f"Saved markdown report to {md_file}")

    def _save_markdown_report(
        self,
        report: Dict,
        results: Dict,
        output_file: Path
    ):
        """Save analysis report as markdown"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# Enhanced AI Analysis Report\n\n")

            f.write("## Summary\n\n")
            f.write(f"- **Total Functions**: {report['total_functions']}\n")
            f.write(f"- **Analyzed**: {report['analyzed_functions']}\n")
            f.write(f"- **AI Enabled**: {report['ai_enabled']}\n")
            if report['ai_enabled']:
                f.write(f"- **AI Provider**: {report['ai_provider']}\n")
                if report['ai_model']:
                    f.write(f"- **AI Model**: {report['ai_model']}\n")
            f.write(f"- **Average Confidence**: {report['average_confidence']:.2f}\n\n")

            f.write("## Category Distribution\n\n")
            for category, count in sorted(report['category_distribution'].items(), key=lambda x: -x[1]):
                f.write(f"- **{category}**: {count} functions\n")
            f.write("\n")

            f.write("## Complexity Distribution\n\n")
            for complexity, count in report['complexity_distribution'].items():
                if count > 0:
                    f.write(f"- **{complexity}**: {count} functions\n")
            f.write("\n")

            if report['security_issues_count'] > 0:
                f.write(f"## Security Issues ({report['security_issues_count']})\n\n")
                for issue in report['security_issues'][:10]:
                    f.write(f"- `{issue['function']}`: {issue['concern']}\n")
                f.write("\n")

            if report['high_confidence_functions']:
                f.write(f"## High Confidence Functions ({len(report['high_confidence_functions'])})\n\n")
                for func_name in report['high_confidence_functions'][:10]:
                    analysis = results[func_name]
                    f.write(f"### {func_name}\n\n")
                    f.write(f"- **Purpose**: {analysis['purpose']}\n")
                    f.write(f"- **Category**: {analysis['category']}\n")
                    f.write(f"- **Complexity**: {analysis['complexity']}\n")
                    f.write(f"- **Confidence**: {analysis['confidence']:.2f}\n")
                    if analysis.get('suggested_name'):
                        f.write(f"- **Suggested Name**: `{analysis['suggested_name']}`\n")
                    f.write("\n")

    def generate_implementations(
        self,
        functions: List[Dict[str, str]],
        output_folder: Optional[Path] = None
    ) -> int:
        """
        Generate function implementations using AI

        Args:
            functions: List of function specs
            output_folder: Where to save implementations

        Returns:
            Number of implementations generated
        """
        if not self.ai_analyzer:
            logger.warning("AI analyzer not available - cannot generate implementations")
            return 0

        if output_folder is None:
            output_folder = Path(f"ai_generated_implementations_{self.binary_name}")

        output_folder.mkdir(exist_ok=True, parents=True)

        count = 0

        for func in self.progress.step(functions, "Generating code", unit="func"):
            try:
                code = self.ai_analyzer.generate_implementation(func, language='c')

                output_file = output_folder / f"{func['name']}.c"
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(code)

                count += 1

            except Exception as e:
                logger.error(f"Failed to generate {func['name']}: {e}")

        logger.info(f"Generated {count} implementations")
        return count


# CLI interface
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    print("=" * 70)
    print("REVENG ENHANCED AI ANALYZER")
    print("=" * 70)
    print()

    if len(sys.argv) < 2:
        print("Usage: python ai_analyzer_enhanced.py <binary_path>")
        print()
        print("Example: python ai_analyzer_enhanced.py droid.exe")
        sys.exit(1)

    binary_path = sys.argv[1]

    analyzer = EnhancedAIAnalyzer(binary_path)

    # Test with sample functions
    print("Loading functions...")

    # Load from src_optimal_analysis folder
    binary_name = Path(binary_path).stem
    functions_folder = Path(f"src_optimal_analysis_{binary_name}/functions")

    if not functions_folder.exists():
        print(f"Error: Functions folder not found: {functions_folder}")
        print("Run main analysis first: python reveng_analyzer.py <binary>")
        sys.exit(1)

    functions = []
    for func_file in list(functions_folder.glob("*.c"))[:10]:  # Test with first 10
        with open(func_file, 'r', encoding='utf-8') as f:
            code = f.read()

        functions.append({
            'name': func_file.stem,
            'code': code,
            'address': '0x1000'  # Placeholder
        })

    print(f"Found {len(functions)} functions")
    print()

    # Run analysis
    report = analyzer.analyze_functions(functions)

    # Print summary
    print()
    print("=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)
    print(f"Total functions: {report['total_functions']}")
    print(f"AI enabled: {report['ai_enabled']}")
    if report['ai_enabled']:
        print(f"AI provider: {report['ai_provider']}")
        print(f"AI model: {report['ai_model']}")
    print(f"Average confidence: {report['average_confidence']:.2f}")
    print()
    print("Category distribution:")
    for category, count in sorted(report['category_distribution'].items(), key=lambda x: -x[1]):
        print(f"  {category}: {count}")
    print()
    print(f"Security issues found: {report['security_issues_count']}")
    print("=" * 70)
