#!/usr/bin/env python3
"""
REVENG Installation Verification Script
======================================

This script verifies that REVENG is properly installed and all dependencies are available.
"""

import sys
import subprocess
import importlib
from pathlib import Path
from typing import List, Dict, Any


class InstallationVerifier:
    """Verify REVENG installation and dependencies"""
    
    def __init__(self):
        self.results = {
            'python': False,
            'dependencies': False,
            'tools': False,
            'java': False,
            'ghidra': False,
            'compiler': False,
            'ai': False
        }
        self.errors = []
        self.warnings = []
    
    def check_python(self) -> bool:
        """Check Python installation"""
        try:
            version = sys.version_info
            if version < (3, 11):
                self.errors.append(f"Python 3.11+ required, got {version.major}.{version.minor}")
                return False
            
            print(f"✅ Python {version.major}.{version.minor}.{version.micro} found")
            self.results['python'] = True
            return True
        except Exception as e:
            self.errors.append(f"Python check failed: {e}")
            return False
    
    def check_dependencies(self) -> bool:
        """Check Python dependencies"""
        required_packages = [
            'requests', 'lief', 'keystone', 'capstone', 
            'networkx', 'pydot', 'tqdm', 'yaml'
        ]
        
        missing_packages = []
        for package in required_packages:
            try:
                importlib.import_module(package)
                print(f"✅ {package} found")
            except ImportError:
                missing_packages.append(package)
                print(f"❌ {package} missing")
        
        if missing_packages:
            self.errors.append(f"Missing packages: {', '.join(missing_packages)}")
            return False
        
        self.results['dependencies'] = True
        return True
    
    def check_tools(self) -> bool:
        """Check REVENG tools"""
        tools_dir = Path('tools')
        if not tools_dir.exists():
            self.errors.append("Tools directory not found")
            return False
        
        key_tools = [
            'language_detector.py',
            'ai_recompiler_converter.py',
            'optimal_binary_analysis.py',
            'binary_reassembler_v2.py',
            'human_readable_converter_fixed.py'
        ]
        
        missing_tools = []
        for tool in key_tools:
            tool_path = tools_dir / tool
            if tool_path.exists():
                print(f"✅ {tool} found")
            else:
                missing_tools.append(tool)
                print(f"❌ {tool} missing")
        
        if missing_tools:
            self.warnings.append(f"Missing tools: {', '.join(missing_tools)}")
            return False
        
        self.results['tools'] = True
        return True
    
    def check_java(self) -> bool:
        """Check Java installation"""
        try:
            result = subprocess.run(['java', '-version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print("✅ Java found")
                self.results['java'] = True
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        self.warnings.append("Java not found (optional for Ghidra integration)")
        return False
    
    def check_ghidra(self) -> bool:
        """Check Ghidra installation"""
        ghidra_paths = [
            Path('ghidra'),
            Path('C:/ghidra'),
            Path('/opt/ghidra'),
            Path('/usr/local/ghidra')
        ]
        
        for path in ghidra_paths:
            if path.exists():
                print(f"✅ Ghidra found at {path}")
                self.results['ghidra'] = True
                return True
        
        self.warnings.append("Ghidra not found (optional for advanced analysis)")
        return False
    
    def check_compiler(self) -> bool:
        """Check compiler toolchain"""
        compilers = ['gcc', 'clang', 'cl']
        available_compilers = []
        
        for compiler in compilers:
            try:
                result = subprocess.run([compiler, '--version'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    available_compilers.append(compiler)
                    print(f"✅ {compiler} found")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if available_compilers:
            self.results['compiler'] = True
            return True
        
        self.warnings.append("No compilers found (required for binary reassembly)")
        return False
    
    def check_ai(self) -> bool:
        """Check AI dependencies"""
        ai_providers = {
            'ollama': 'ollama --version',
            'anthropic': 'python -c "import anthropic"',
            'openai': 'python -c "import openai"'
        }
        
        available_providers = []
        for provider, command in ai_providers.items():
            try:
                if provider == 'ollama':
                    result = subprocess.run(command.split(), 
                                          capture_output=True, text=True, timeout=5)
                else:
                    result = subprocess.run(['python', '-c', command.split()[-1]], 
                                          capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    available_providers.append(provider)
                    print(f"✅ {provider} available")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        
        if available_providers:
            self.results['ai'] = True
            return True
        
        self.warnings.append("No AI providers found (optional for AI analysis)")
        return False
    
    def run_verification(self) -> Dict[str, Any]:
        """Run complete verification"""
        print("REVENG Installation Verification")
        print("=" * 40)
        print()
        
        # Check all components
        self.check_python()
        self.check_dependencies()
        self.check_tools()
        self.check_java()
        self.check_ghidra()
        self.check_compiler()
        self.check_ai()
        
        # Summary
        print("\n" + "=" * 40)
        print("Verification Summary")
        print("=" * 40)
        
        critical_components = ['python', 'dependencies', 'tools']
        optional_components = ['java', 'ghidra', 'compiler', 'ai']
        
        critical_passed = sum(1 for comp in critical_components if self.results[comp])
        optional_passed = sum(1 for comp in optional_components if self.results[comp])
        
        print(f"Critical components: {critical_passed}/{len(critical_components)}")
        print(f"Optional components: {optional_passed}/{len(optional_components)}")
        
        if self.errors:
            print("\n❌ Errors:")
            for error in self.errors:
                print(f"  - {error}")
        
        if self.warnings:
            print("\n⚠️  Warnings:")
            for warning in self.warnings:
                print(f"  - {warning}")
        
        if critical_passed == len(critical_components):
            print("\n✅ Installation verification passed!")
            print("REVENG is ready to use.")
            return {'status': 'success', 'results': self.results}
        else:
            print("\n❌ Installation verification failed!")
            print("Please fix the errors above before using REVENG.")
            return {'status': 'failed', 'results': self.results, 'errors': self.errors}
    
    def suggest_fixes(self) -> List[str]:
        """Suggest fixes for common issues"""
        suggestions = []
        
        if not self.results['python']:
            suggestions.append("Install Python 3.11+ from https://python.org")
        
        if not self.results['dependencies']:
            suggestions.append("Run: pip install -r requirements.txt")
        
        if not self.results['tools']:
            suggestions.append("Check that tools/ directory exists and contains required files")
        
        if not self.results['java']:
            suggestions.append("Install Java 21+ from https://adoptium.net/")
        
        if not self.results['ghidra']:
            suggestions.append("Download Ghidra from https://github.com/NationalSecurityAgency/ghidra/releases")
        
        if not self.results['compiler']:
            suggestions.append("Install Visual Studio Build Tools or MinGW-w64")
        
        if not self.results['ai']:
            suggestions.append("Install Ollama from https://ollama.ai or set up API keys")
        
        return suggestions


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Verify REVENG installation')
    parser.add_argument('--fix', action='store_true', help='Attempt to fix common issues')
    parser.add_argument('--json', action='store_true', help='Output results in JSON format')
    args = parser.parse_args()
    
    verifier = InstallationVerifier()
    results = verifier.run_verification()
    
    if args.json:
        import json
        print(json.dumps(results, indent=2))
        return
    
    if args.fix and results['status'] == 'failed':
        print("\n🔧 Suggested fixes:")
        suggestions = verifier.suggest_fixes()
        for i, suggestion in enumerate(suggestions, 1):
            print(f"  {i}. {suggestion}")
    
    # Exit with appropriate code
    sys.exit(0 if results['status'] == 'success' else 1)


if __name__ == "__main__":
    main()
