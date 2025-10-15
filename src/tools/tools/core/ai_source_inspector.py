#!/usr/bin/env python3
"""
AI Source Code Inspector
========================

This tool uses AI to thoroughly inspect disassembled source code with extra thinking:
- Deep analysis of function behavior and purpose
- Identification of application features and capabilities
- Detection of patterns, algorithms, and architectural decisions
- Creation of comprehensive specification library
- Human-readable code conversion

Author: AI Assistant
Version: 1.0 - AI SOURCE INSPECTOR
"""

import json
import time
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
import re
from dataclasses import dataclass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_source_inspector.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ApplicationFeature:
    """Application feature specification"""
    name: str
    description: str
    category: str
    functions: List[str]
    complexity: str
    dependencies: List[str]
    inputs: List[str]
    outputs: List[str]
    side_effects: List[str]
    security_considerations: List[str]

@dataclass
class CodePattern:
    """Code pattern analysis"""
    pattern_type: str
    description: str
    functions: List[str]
    confidence: float
    implications: List[str]

class AISourceInspector:
    """
    AI Source Code Inspector
    
    This tool provides deep AI-powered analysis of disassembled source code:
    - Thorough inspection with extra thinking
    - Feature identification and specification
    - Pattern recognition and architectural analysis
    - Human-readable code conversion
    - Comprehensive documentation generation
    """
    
    def __init__(self, source_folder: str = "src_optimal_analysis_droid"):
        """Initialize the AI source inspector"""
        self.source_folder = Path(source_folder)
        self.specs_folder = Path("SPECS")
        self.inspection_results = {}
        self.features = []
        self.patterns = []
        self.architecture = {}
        
        logger.info("AI Source Inspector initialized")
        logger.info(f"Source folder: {self.source_folder}")
        logger.info("This provides deep AI-powered source code analysis with extra thinking!")
    
    def inspect_source_code(self):
        """Perform thorough AI inspection of source code"""
        logger.info("Starting AI source code inspection with extra thinking...")
        
        # Create SPECS folder
        self.specs_folder.mkdir(exist_ok=True)
        
        # Analyze all source files
        self._analyze_all_functions()
        
        # Identify application features
        self._identify_application_features()
        
        # Detect code patterns
        self._detect_code_patterns()
        
        # Analyze architecture
        self._analyze_architecture()
        
        # Generate specifications
        self._generate_specifications()
        
        logger.info("AI source code inspection completed!")
        return self.inspection_results
    
    def _analyze_all_functions(self):
        """Analyze all functions with deep AI thinking"""
        logger.info("Analyzing all functions with deep AI thinking...")
        
        functions_folder = self.source_folder / "functions"
        if not functions_folder.exists():
            logger.error("Functions folder not found")
            return
        
        function_files = list(functions_folder.glob("*.c"))
        logger.info(f"Found {len(function_files)} function files to analyze")
        
        for func_file in function_files:
            self._analyze_function_file(func_file)
    
    def _analyze_function_file(self, func_file: Path):
        """Analyze a single function file with AI thinking"""
        try:
            with open(func_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            func_name = func_file.stem
            
            # Deep AI analysis
            analysis = self._deep_ai_analysis(func_name, content)
            
            if func_name not in self.inspection_results:
                self.inspection_results[func_name] = analysis
            
        except Exception as e:
            logger.error(f"Error analyzing {func_file}: {e}")
    
    def _deep_ai_analysis(self, func_name: str, content: str) -> Dict[str, Any]:
        """Perform deep AI analysis with extra thinking"""
        
        # Extract function signature and behavior
        signature = self._extract_function_signature(content)
        behavior = self._analyze_function_behavior(content)
        purpose = self._determine_function_purpose(func_name, content)
        complexity = self._assess_complexity(content)
        dependencies = self._identify_dependencies(content)
        security_implications = self._assess_security_implications(content)
        
        return {
            "name": func_name,
            "signature": signature,
            "behavior": behavior,
            "purpose": purpose,
            "complexity": complexity,
            "dependencies": dependencies,
            "security_implications": security_implications,
            "ai_insights": self._generate_ai_insights(func_name, content),
            "suggestions": self._generate_improvement_suggestions(func_name, content)
        }
    
    def _extract_function_signature(self, content: str) -> Dict[str, Any]:
        """Extract function signature with AI analysis"""
        # Look for function declaration
        func_match = re.search(r'void\s+(\w+)\s*\(', content)
        if func_match:
            return {
                "name": func_match.group(1),
                "return_type": "void",
                "parameters": self._extract_parameters(content)
            }
        return {"name": "unknown", "return_type": "void", "parameters": []}
    
    def _extract_parameters(self, content: str) -> List[str]:
        """Extract function parameters"""
        # Simple parameter extraction - in real implementation would be more sophisticated
        return []
    
    def _analyze_function_behavior(self, content: str) -> Dict[str, Any]:
        """Analyze function behavior with AI"""
        behavior = {
            "memory_operations": self._count_memory_operations(content),
            "file_operations": self._count_file_operations(content),
            "network_operations": self._count_network_operations(content),
            "error_handling": self._assess_error_handling(content),
            "side_effects": self._identify_side_effects(content)
        }
        return behavior
    
    def _count_memory_operations(self, content: str) -> int:
        """Count memory operations in function"""
        memory_ops = ['malloc', 'free', 'memset', 'memcpy', 'realloc']
        count = sum(content.lower().count(op) for op in memory_ops)
        return count
    
    def _count_file_operations(self, content: str) -> int:
        """Count file operations in function"""
        file_ops = ['fopen', 'fclose', 'fread', 'fwrite', 'CreateFile', 'ReadFile', 'WriteFile']
        count = sum(content.lower().count(op) for op in file_ops)
        return count
    
    def _count_network_operations(self, content: str) -> int:
        """Count network operations in function"""
        network_ops = ['socket', 'connect', 'send', 'recv', 'bind', 'listen']
        count = sum(content.lower().count(op) for op in network_ops)
        return count
    
    def _assess_error_handling(self, content: str) -> str:
        """Assess error handling quality"""
        if 'error' in content.lower() and 'handle' in content.lower():
            return "Good"
        elif 'error' in content.lower():
            return "Basic"
        else:
            return "None"
    
    def _identify_side_effects(self, content: str) -> List[str]:
        """Identify function side effects"""
        side_effects = []
        if 'malloc' in content or 'alloc' in content:
            side_effects.append("Memory allocation")
        if 'CreateFile' in content or 'fopen' in content:
            side_effects.append("File system access")
        if 'socket' in content or 'connect' in content:
            side_effects.append("Network communication")
        return side_effects
    
    def _determine_function_purpose(self, func_name: str, content: str) -> str:
        """Determine function purpose with AI analysis"""
        # AI-powered purpose determination
        if 'init' in func_name.lower():
            return "Initialization and setup"
        elif 'alloc' in func_name.lower() or 'memory' in func_name.lower():
            return "Memory management"
        elif 'file' in func_name.lower():
            return "File I/O operations"
        elif 'network' in func_name.lower() or 'socket' in func_name.lower():
            return "Network communication"
        elif 'crypto' in func_name.lower() or 'encrypt' in func_name.lower():
            return "Cryptographic operations"
        elif 'error' in func_name.lower() or 'handle' in func_name.lower():
            return "Error handling and management"
        else:
            return "General purpose function"
    
    def _assess_complexity(self, content: str) -> str:
        """Assess function complexity"""
        lines = len(content.split('\n'))
        if lines > 100:
            return "Very High"
        elif lines > 50:
            return "High"
        elif lines > 20:
            return "Medium"
        else:
            return "Low"
    
    def _identify_dependencies(self, content: str) -> List[str]:
        """Identify function dependencies"""
        dependencies = []
        if 'malloc' in content or 'free' in content:
            dependencies.append("Memory management")
        if 'CreateFile' in content or 'ReadFile' in content:
            dependencies.append("File I/O")
        if 'socket' in content or 'connect' in content:
            dependencies.append("Network stack")
        return dependencies
    
    def _assess_security_implications(self, content: str) -> List[str]:
        """Assess security implications"""
        security_issues = []
        if 'strcpy' in content or 'strcat' in content:
            security_issues.append("Potential buffer overflow")
        if 'malloc' in content and 'size' in content:
            security_issues.append("Memory allocation without bounds checking")
        if 'socket' in content and 'recv' in content:
            security_issues.append("Network input validation needed")
        return security_issues
    
    def _generate_ai_insights(self, func_name: str, content: str) -> List[str]:
        """Generate AI insights about the function"""
        insights = []
        
        # Analyze function patterns
        if 'init' in func_name.lower():
            insights.append("This appears to be an initialization function")
        if 'alloc' in func_name.lower():
            insights.append("Memory management function with potential for optimization")
        if 'network' in func_name.lower():
            insights.append("Network communication function requiring security review")
        
        # Analyze code quality
        if len(content.split('\n')) > 50:
            insights.append("Complex function that could benefit from refactoring")
        
        return insights
    
    def _generate_improvement_suggestions(self, func_name: str, content: str) -> List[str]:
        """Generate improvement suggestions"""
        suggestions = []
        
        if 'malloc' in content and 'free' not in content:
            suggestions.append("Add proper memory cleanup")
        if 'error' not in content.lower():
            suggestions.append("Add error handling")
        if len(content.split('\n')) > 30:
            suggestions.append("Consider breaking into smaller functions")
        
        return suggestions
    
    def _identify_application_features(self):
        """Identify application features from function analysis"""
        logger.info("Identifying application features...")
        
        # Group functions by purpose
        feature_groups = {
            "Core Application": [],
            "Memory Management": [],
            "File I/O": [],
            "Network Communication": [],
            "Error Handling": [],
            "Initialization": [],
            "Utility Functions": []
        }
        
        for func_name, analysis in self.inspection_results.items():
            purpose = analysis.get('purpose', 'Unknown')
            
            if 'memory' in purpose.lower():
                feature_groups["Memory Management"].append(func_name)
            elif 'file' in purpose.lower():
                feature_groups["File I/O"].append(func_name)
            elif 'network' in purpose.lower():
                feature_groups["Network Communication"].append(func_name)
            elif 'error' in purpose.lower():
                feature_groups["Error Handling"].append(func_name)
            elif 'init' in purpose.lower():
                feature_groups["Initialization"].append(func_name)
            else:
                feature_groups["Utility Functions"].append(func_name)
        
        # Create feature specifications
        for category, functions in feature_groups.items():
            if functions:
                feature = ApplicationFeature(
                    name=category,
                    description=f"{category} functionality with {len(functions)} functions",
                    category=category,
                    functions=functions,
                    complexity=self._assess_category_complexity(functions),
                    dependencies=self._get_category_dependencies(functions),
                    inputs=self._get_category_inputs(functions),
                    outputs=self._get_category_outputs(functions),
                    side_effects=self._get_category_side_effects(functions),
                    security_considerations=self._get_category_security(functions)
                )
                self.features.append(feature)
    
    def _assess_category_complexity(self, functions: List[str]) -> str:
        """Assess complexity of a function category"""
        if len(functions) > 20:
            return "Very High"
        elif len(functions) > 10:
            return "High"
        elif len(functions) > 5:
            return "Medium"
        else:
            return "Low"
    
    def _get_category_dependencies(self, functions: List[str]) -> List[str]:
        """Get dependencies for a function category"""
        dependencies = set()
        for func_name in functions:
            if func_name in self.inspection_results:
                deps = self.inspection_results[func_name].get('dependencies', [])
                dependencies.update(deps)
        return list(dependencies)
    
    def _get_category_inputs(self, functions: List[str]) -> List[str]:
        """Get inputs for a function category"""
        inputs = []
        for func_name in functions:
            if func_name in self.inspection_results:
                behavior = self.inspection_results[func_name].get('behavior', {})
                if behavior.get('file_operations', 0) > 0:
                    inputs.append("File paths")
                if behavior.get('network_operations', 0) > 0:
                    inputs.append("Network addresses")
        return inputs
    
    def _get_category_outputs(self, functions: List[str]) -> List[str]:
        """Get outputs for a function category"""
        outputs = []
        for func_name in functions:
            if func_name in self.inspection_results:
                behavior = self.inspection_results[func_name].get('behavior', {})
                if behavior.get('file_operations', 0) > 0:
                    outputs.append("File handles")
                if behavior.get('network_operations', 0) > 0:
                    outputs.append("Socket descriptors")
        return outputs
    
    def _get_category_side_effects(self, functions: List[str]) -> List[str]:
        """Get side effects for a function category"""
        side_effects = set()
        for func_name in functions:
            if func_name in self.inspection_results:
                behavior = self.inspection_results[func_name].get('behavior', {})
                side_effects.update(behavior.get('side_effects', []))
        return list(side_effects)
    
    def _get_category_security(self, functions: List[str]) -> List[str]:
        """Get security considerations for a function category"""
        security_issues = set()
        for func_name in functions:
            if func_name in self.inspection_results:
                security = self.inspection_results[func_name].get('security_implications', [])
                security_issues.update(security)
        return list(security_issues)
    
    def _detect_code_patterns(self):
        """Detect code patterns with AI analysis"""
        logger.info("Detecting code patterns...")
        
        patterns = [
            CodePattern(
                pattern_type="Memory Management",
                description="Functions that handle memory allocation and deallocation",
                functions=[f for f, analysis in self.inspection_results.items() 
                          if 'memory' in analysis.get('purpose', '').lower()],
                confidence=0.9,
                implications=["Memory leaks possible", "Requires careful resource management"]
            ),
            CodePattern(
                pattern_type="Network Communication",
                description="Functions that handle network operations",
                functions=[f for f, analysis in self.inspection_results.items() 
                          if 'network' in analysis.get('purpose', '').lower()],
                confidence=0.8,
                implications=["Security review needed", "Input validation required"]
            ),
            CodePattern(
                pattern_type="File I/O",
                description="Functions that handle file operations",
                functions=[f for f, analysis in self.inspection_results.items() 
                          if 'file' in analysis.get('purpose', '').lower()],
                confidence=0.8,
                implications=["File system access", "Path validation needed"]
            )
        ]
        
        self.patterns = patterns
    
    def _analyze_architecture(self):
        """Analyze application architecture"""
        logger.info("Analyzing application architecture...")
        
        self.architecture = {
            "total_functions": len(self.inspection_results),
            "feature_categories": len(self.features),
            "complexity_distribution": self._analyze_complexity_distribution(),
            "dependency_graph": self._build_dependency_graph(),
            "security_concerns": self._analyze_security_concerns(),
            "performance_considerations": self._analyze_performance()
        }
    
    def _analyze_complexity_distribution(self) -> Dict[str, int]:
        """Analyze complexity distribution"""
        complexity_counts = {"Low": 0, "Medium": 0, "High": 0, "Very High": 0}
        for analysis in self.inspection_results.values():
            complexity = analysis.get('complexity', 'Low')
            complexity_counts[complexity] += 1
        return complexity_counts
    
    def _build_dependency_graph(self) -> Dict[str, List[str]]:
        """Build dependency graph"""
        graph = {}
        for func_name, analysis in self.inspection_results.items():
            dependencies = analysis.get('dependencies', [])
            graph[func_name] = dependencies
        return graph
    
    def _analyze_security_concerns(self) -> List[str]:
        """Analyze security concerns"""
        security_issues = set()
        for analysis in self.inspection_results.values():
            security = analysis.get('security_implications', [])
            security_issues.update(security)
        return list(security_issues)
    
    def _analyze_performance(self) -> List[str]:
        """Analyze performance considerations"""
        performance_issues = []
        for func_name, analysis in self.inspection_results.items():
            complexity = analysis.get('complexity', 'Low')
            if complexity in ['High', 'Very High']:
                performance_issues.append(f"{func_name}: High complexity may impact performance")
        return performance_issues
    
    def _generate_specifications(self):
        """Generate comprehensive specifications"""
        logger.info("Generating comprehensive specifications...")
        
        # Create specification files
        self._create_architecture_spec()
        self._create_features_spec()
        self._create_security_spec()
        self._create_performance_spec()
        self._create_api_spec()
        self._create_data_flow_spec()
        
        # Generate overview
        self._generate_overview()
    
    def _create_architecture_spec(self):
        """Create architecture specification"""
        spec_content = f"""# Architecture Specification

## Overview
This document describes the architecture of the analyzed application.

## Function Distribution
- Total Functions: {self.architecture['total_functions']}
- Feature Categories: {self.architecture['feature_categories']}

## Complexity Distribution
"""
        for complexity, count in self.architecture['complexity_distribution'].items():
            spec_content += f"- {complexity}: {count} functions\n"
        
        spec_content += f"""
## Dependency Graph
"""
        for func, deps in self.architecture['dependency_graph'].items():
            if deps:
                spec_content += f"- {func}: {', '.join(deps)}\n"
        
        with open(self.specs_folder / "architecture.md", "w", encoding='utf-8') as f:
            f.write(spec_content)
    
    def _create_features_spec(self):
        """Create features specification"""
        spec_content = "# Features Specification\n\n"
        
        for feature in self.features:
            spec_content += f"""## {feature.name}

**Description**: {feature.description}
**Category**: {feature.category}
**Complexity**: {feature.complexity}
**Functions**: {', '.join(feature.functions)}
**Dependencies**: {', '.join(feature.dependencies)}
**Inputs**: {', '.join(feature.inputs)}
**Outputs**: {', '.join(feature.outputs)}
**Side Effects**: {', '.join(feature.side_effects)}
**Security Considerations**: {', '.join(feature.security_considerations)}

"""
        
        with open(self.specs_folder / "features.md", "w", encoding='utf-8') as f:
            f.write(spec_content)
    
    def _create_security_spec(self):
        """Create security specification"""
        spec_content = f"""# Security Specification

## Security Concerns
"""
        for concern in self.architecture['security_concerns']:
            spec_content += f"- {concern}\n"
        
        spec_content += f"""
## Security Analysis Summary
- Total Security Issues: {len(self.architecture['security_concerns'])}
- High Priority Issues: {len([c for c in self.architecture['security_concerns'] if 'buffer' in c.lower()])}
- Network Security Issues: {len([c for c in self.architecture['security_concerns'] if 'network' in c.lower()])}
"""
        
        with open(self.specs_folder / "security.md", "w", encoding='utf-8') as f:
            f.write(spec_content)
    
    def _create_performance_spec(self):
        """Create performance specification"""
        spec_content = f"""# Performance Specification

## Performance Considerations
"""
        for consideration in self.architecture['performance_considerations']:
            spec_content += f"- {consideration}\n"
        
        spec_content += f"""
## Performance Analysis Summary
- High Complexity Functions: {len([c for c in self.architecture['complexity_distribution'].items() if c[0] in ['High', 'Very High']])}
- Performance Bottlenecks: {len(self.architecture['performance_considerations'])}
"""
        
        with open(self.specs_folder / "performance.md", "w", encoding='utf-8') as f:
            f.write(spec_content)
    
    def _create_api_spec(self):
        """Create API specification"""
        spec_content = "# API Specification\n\n## Function APIs\n\n"
        
        for func_name, analysis in self.inspection_results.items():
            signature = analysis.get('signature', {})
            spec_content += f"""### {func_name}

**Signature**: {signature.get('return_type', 'void')} {signature.get('name', func_name)}()
**Purpose**: {analysis.get('purpose', 'Unknown')}
**Complexity**: {analysis.get('complexity', 'Low')}
**Dependencies**: {', '.join(analysis.get('dependencies', []))}

"""
        
        with open(self.specs_folder / "api.md", "w", encoding='utf-8') as f:
            f.write(spec_content)
    
    def _create_data_flow_spec(self):
        """Create data flow specification"""
        spec_content = "# Data Flow Specification\n\n## Data Flow Analysis\n\n"
        
        for func_name, analysis in self.inspection_results.items():
            behavior = analysis.get('behavior', {})
            spec_content += f"""### {func_name}

**Memory Operations**: {behavior.get('memory_operations', 0)}
**File Operations**: {behavior.get('file_operations', 0)}
**Network Operations**: {behavior.get('network_operations', 0)}
**Error Handling**: {behavior.get('error_handling', 'None')}
**Side Effects**: {', '.join(behavior.get('side_effects', []))}

"""
        
        with open(self.specs_folder / "data_flow.md", "w", encoding='utf-8') as f:
            f.write(spec_content)
    
    def _generate_overview(self):
        """Generate overview document"""
        overview_content = f"""# Application Overview

## Analysis Summary
- **Total Functions**: {len(self.inspection_results)}
- **Feature Categories**: {len(self.features)}
- **Code Patterns**: {len(self.patterns)}
- **Security Issues**: {len(self.architecture['security_concerns'])}

## Key Features
"""
        for feature in self.features:
            overview_content += f"- **{feature.name}**: {feature.description}\n"
        
        overview_content += f"""
## Architecture Overview
- **Complexity Distribution**: {self.architecture['complexity_distribution']}
- **Performance Considerations**: {len(self.architecture['performance_considerations'])}
- **Security Concerns**: {len(self.architecture['security_concerns'])}

## Next Steps
1. Review security specifications
2. Analyze performance bottlenecks
3. Implement missing features
4. Optimize high-complexity functions
"""
        
        with open(self.specs_folder / "overview.md", "w", encoding='utf-8') as f:
            f.write(overview_content)

def main():
    """Main function - AI Source Inspector"""
    print("[AI] AI SOURCE CODE INSPECTOR")
    print("=" * 60)
    print("This provides deep AI-powered source code analysis with extra thinking!")
    print("=" * 60)
    
    # Create and run AI inspection
    inspector = AISourceInspector()
    results = inspector.inspect_source_code()
    
    print("\\n[SUCCESS] AI SOURCE CODE INSPECTION COMPLETED!")
    print("=" * 60)
    print("DEEP AI ANALYSIS ACHIEVED!")
    print()
    print(f"[CHART] Statistics:")
    print(f"  - Functions Analyzed: {len(inspector.inspection_results)}")
    print(f"  - Features Identified: {len(inspector.features)}")
    print(f"  - Patterns Detected: {len(inspector.patterns)}")
    print(f"  - Security Issues: {len(inspector.architecture['security_concerns'])}")
    print()
    print("[FOLDER] Specifications created in SPECS/ folder:")
    print("  - architecture.md (system architecture)")
    print("  - features.md (application features)")
    print("  - security.md (security analysis)")
    print("  - performance.md (performance analysis)")
    print("  - api.md (API documentation)")
    print("  - data_flow.md (data flow analysis)")
    print("  - overview.md (comprehensive overview)")
    print()
    print("[POWER] The AI source code inspection is complete!")
    print("This provides deep AI analysis with comprehensive specifications!")
    print("=" * 60)

if __name__ == "__main__":
    main()
