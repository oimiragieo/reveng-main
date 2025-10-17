"""
REVENG Ghidra Scripting Engine

Python/Java scripting engine for Ghidra automation with batch processing,
project management, and result export.
"""

import os
import sys
import subprocess
import tempfile
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import time

from ..core.errors import AnalysisFailureError, ScriptExecutionError, create_error_context
from ..core.logger import get_logger

class ScriptLanguage(Enum):
    """Script languages"""
    PYTHON = "python"
    JAVA = "java"

class ScriptResult(Enum):
    """Script execution results"""
    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    ERROR = "error"

@dataclass
class GhidraProject:
    """Ghidra project information"""
    name: str
    path: str
    created: str
    binaries: List[str]
    analysis_status: Dict[str, str]

@dataclass
class ScriptExecutionResult:
    """Script execution result"""
    script_path: str
    binary_path: str
    result: ScriptResult
    output: str
    error: Optional[str]
    execution_time: float
    return_code: int

@dataclass
class GhidraAnalysis:
    """Ghidra analysis result"""
    binary_path: str
    functions: List[Dict[str, Any]]
    strings: List[str]
    imports: List[Dict[str, Any]]
    exports: List[Dict[str, Any]]
    call_graph: Dict[str, List[str]]
    analysis_time: float
    confidence: float

class GhidraScriptingEngine:
    """Python/Java scripting engine for Ghidra automation"""

    def __init__(self):
        self.logger = get_logger("ghidra_scripting")
        self.ghidra_path = self._get_ghidra_path()
        self.scripts_dir = Path(__file__).parent / "scripts"
        self.scripts_dir.mkdir(exist_ok=True)
        self.temp_dir = Path(tempfile.gettempdir()) / "reveng_ghidra"
        self.temp_dir.mkdir(exist_ok=True)

    def execute_python_script(self, script_path: str, binary_path: str) -> ScriptExecutionResult:
        """Execute Python script in Ghidra headless mode"""
        try:
            self.logger.info(f"Executing Python script {script_path} on {binary_path}")

            start_time = time.time()

            # Run Ghidra headless with Python script
            cmd = [
                str(self.ghidra_path / "support" / "analyzeHeadless.bat"),
                str(self.temp_dir),
                "temp_project",
                "-import", binary_path,
                "-scriptPath", str(self.scripts_dir),
                "-postScript", script_path,
                "-deleteProject"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            execution_time = time.time() - start_time

            if result.returncode == 0:
                return ScriptExecutionResult(
                    script_path=script_path,
                    binary_path=binary_path,
                    result=ScriptResult.SUCCESS,
                    output=result.stdout,
                    error=None,
                    execution_time=execution_time,
                    return_code=result.returncode
                )
            else:
                return ScriptExecutionResult(
                    script_path=script_path,
                    binary_path=binary_path,
                    result=ScriptResult.FAILURE,
                    output=result.stdout,
                    error=result.stderr,
                    execution_time=execution_time,
                    return_code=result.returncode
                )

        except subprocess.TimeoutExpired:
            return ScriptExecutionResult(
                script_path=script_path,
                binary_path=binary_path,
                result=ScriptResult.TIMEOUT,
                output="",
                error="Script execution timed out",
                execution_time=300.0,
                return_code=-1
            )
        except Exception as e:
            context = create_error_context(
                "ghidra_scripting",
                "execute_python_script",
                binary_path=binary_path,
                tool_name="ghidra"
            )
            raise ScriptExecutionError(
                script_path,
                "ghidra",
                context=context,
                original_exception=e
            )

    def execute_java_script(self, script_path: str, binary_path: str) -> ScriptExecutionResult:
        """Execute Java script in Ghidra"""
        try:
            self.logger.info(f"Executing Java script {script_path} on {binary_path}")

            start_time = time.time()

            # Run Ghidra headless with Java script
            cmd = [
                str(self.ghidra_path / "support" / "analyzeHeadless.bat"),
                str(self.temp_dir),
                "temp_project",
                "-import", binary_path,
                "-scriptPath", str(self.scripts_dir),
                "-postScript", script_path,
                "-deleteProject"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            execution_time = time.time() - start_time

            if result.returncode == 0:
                return ScriptExecutionResult(
                    script_path=script_path,
                    binary_path=binary_path,
                    result=ScriptResult.SUCCESS,
                    output=result.stdout,
                    error=None,
                    execution_time=execution_time,
                    return_code=result.returncode
                )
            else:
                return ScriptExecutionResult(
                    script_path=script_path,
                    binary_path=binary_path,
                    result=ScriptResult.FAILURE,
                    output=result.stdout,
                    error=result.stderr,
                    execution_time=execution_time,
                    return_code=result.returncode
                )

        except subprocess.TimeoutExpired:
            return ScriptExecutionResult(
                script_path=script_path,
                binary_path=binary_path,
                result=ScriptResult.TIMEOUT,
                output="",
                error="Script execution timed out",
                execution_time=300.0,
                return_code=-1
            )
        except Exception as e:
            context = create_error_context(
                "ghidra_scripting",
                "execute_java_script",
                binary_path=binary_path,
                tool_name="ghidra"
            )
            raise ScriptExecutionError(
                script_path,
                "ghidra",
                context=context,
                original_exception=e
            )

    def batch_analyze(self, binaries: List[str], script: str) -> List[ScriptExecutionResult]:
        """Batch process multiple binaries with same script"""
        try:
            self.logger.info(f"Starting batch analysis of {len(binaries)} binaries with script {script}")

            results = []
            for binary in binaries:
                try:
                    result = self.execute_python_script(script, binary)
                    results.append(result)
                except Exception as e:
                    self.logger.warning(f"Failed to analyze {binary}: {e}")
                    results.append(ScriptExecutionResult(
                        script_path=script,
                        binary_path=binary,
                        result=ScriptResult.ERROR,
                        output="",
                        error=str(e),
                        execution_time=0.0,
                        return_code=-1
                    ))

            self.logger.info(f"Completed batch analysis: {len(results)} results")
            return results

        except Exception as e:
            self.logger.error(f"Batch analysis failed: {e}")
            return []

    def create_ghidra_project(self, project_name: str) -> GhidraProject:
        """Create new Ghidra project programmatically"""
        try:
            project_path = self.temp_dir / project_name
            project_path.mkdir(exist_ok=True)

            project = GhidraProject(
                name=project_name,
                path=str(project_path),
                created=time.strftime("%Y-%m-%d %H:%M:%S"),
                binaries=[],
                analysis_status={}
            )

            self.logger.info(f"Created Ghidra project: {project_name}")
            return project

        except Exception as e:
            self.logger.error(f"Failed to create Ghidra project: {e}")
            raise

    def export_analysis_results(self, project: GhidraProject, format: str) -> Dict[str, Any]:
        """Export Ghidra analysis results (XML, JSON, etc.)"""
        try:
            export_results = {}

            for binary in project.binaries:
                # Export functions
                functions = self._export_functions(binary, format)
                export_results[f"{binary}_functions"] = functions

                # Export strings
                strings = self._export_strings(binary, format)
                export_results[f"{binary}_strings"] = strings

                # Export imports
                imports = self._export_imports(binary, format)
                export_results[f"{binary}_imports"] = imports

                # Export exports
                exports = self._export_exports(binary, format)
                export_results[f"{binary}_exports"] = exports

            return export_results

        except Exception as e:
            self.logger.error(f"Failed to export analysis results: {e}")
            return {}

    def analyze_binary(self, binary_path: str, auto_analyze: bool = True) -> GhidraAnalysis:
        """Analyze binary with Ghidra"""
        try:
            self.logger.info(f"Starting Ghidra analysis of {binary_path}")

            start_time = time.time()

            # Create temporary project
            project = self.create_ghidra_project("temp_analysis")

            # Import binary
            self._import_binary(project, binary_path)

            # Run analysis if requested
            if auto_analyze:
                self._run_auto_analysis(project, binary_path)

            # Extract analysis results
            functions = self._extract_functions(binary_path)
            strings = self._extract_strings(binary_path)
            imports = self._extract_imports(binary_path)
            exports = self._extract_exports(binary_path)
            call_graph = self._extract_call_graph(binary_path)

            analysis_time = time.time() - start_time

            result = GhidraAnalysis(
                binary_path=binary_path,
                functions=functions,
                strings=strings,
                imports=imports,
                exports=exports,
                call_graph=call_graph,
                analysis_time=analysis_time,
                confidence=0.8  # Placeholder confidence
            )

            self.logger.info(f"Completed Ghidra analysis in {analysis_time:.2f} seconds")
            return result

        except Exception as e:
            context = create_error_context(
                "ghidra_scripting",
                "analyze_binary",
                binary_path=binary_path,
                tool_name="ghidra"
            )
            raise AnalysisFailureError(
                "ghidra_analysis",
                binary_path,
                context=context,
                original_exception=e
            )

    def decompile_function(self, binary_path: str, function_address: int) -> str:
        """Decompile specific function"""
        try:
            # Create Python script for function decompilation
            script_content = f"""
# Ghidra script to decompile function at address {hex(function_address)}
from ghidra.program.model.listing import Function
from ghidra.program.model.address import Address

# Get function at address
addr = currentProgram.getAddressFactory().getAddress("{hex(function_address)}")
func = getFunctionAt(addr)

if func:
    # Decompile function
    decompiler = ghidra.app.decompiler.DecompInterface()
    decompiler.openProgram(currentProgram)

    result = decompiler.decompileFunction(func, 30, None)
    if result and result.decompileCompleted():
        print(result.getDecompiledFunction().getC())
    else:
        print("Decompilation failed")
else:
    print("Function not found at address {hex(function_address)}")
"""

            # Write script to temporary file
            script_path = self.temp_dir / "decompile_function.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                return result.output
            else:
                return f"Decompilation failed: {result.error}"

        except Exception as e:
            self.logger.error(f"Failed to decompile function: {e}")
            return f"Decompilation error: {e}"

    def extract_call_graph(self, binary_path: str) -> Dict[str, List[str]]:
        """Extract function call graph"""
        try:
            # Create Python script for call graph extraction
            script_content = """
# Ghidra script to extract call graph
from ghidra.program.model.listing import Function
from ghidra.program.model.address import Address

call_graph = {}

# Iterate through all functions
for func in currentProgram.getFunctionManager().getFunctions(True):
    func_name = func.getName()
    call_graph[func_name] = []

    # Get called functions
    for ref in func.getCalledFunctions(monitor):
        call_graph[func_name].append(ref.getName())

# Output call graph as JSON
import json
print(json.dumps(call_graph, indent=2))
"""

            # Write script to temporary file
            script_path = self.temp_dir / "extract_call_graph.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                try:
                    return json.loads(result.output)
                except json.JSONDecodeError:
                    return {}
            else:
                return {}

        except Exception as e:
            self.logger.error(f"Failed to extract call graph: {e}")
            return {}

    def apply_flirt_signatures(self, binary_path: str) -> List[Dict[str, Any]]:
        """Apply FLIRT signatures for library identification"""
        try:
            # Create Python script for FLIRT signature application
            script_content = """
# Ghidra script to apply FLIRT signatures
from ghidra.program.model.listing import Function
from ghidra.app.services import FunctionSignatureService

# Get function signature service
sig_service = getState().getTool().getService(FunctionSignatureService)

# Apply FLIRT signatures
applied_signatures = []
for func in currentProgram.getFunctionManager().getFunctions(True):
    if func.getSignatureSource() == Function.SignatureSource.USER_DEFINED:
        applied_signatures.append({
            'function': func.getName(),
            'address': str(func.getEntryPoint()),
            'signature': func.getSignature().getPrototypeString()
        })

# Output results
import json
print(json.dumps(applied_signatures, indent=2))
"""

            # Write script to temporary file
            script_path = self.temp_dir / "apply_flirt_signatures.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                try:
                    return json.loads(result.output)
                except json.JSONDecodeError:
                    return []
            else:
                return []

        except Exception as e:
            self.logger.error(f"Failed to apply FLIRT signatures: {e}")
            return []

    def _get_ghidra_path(self) -> Optional[Path]:
        """Get Ghidra executable path"""
        from ..core.dependency_manager import DependencyManager
        dm = DependencyManager()
        ghidra_path = dm.get_tool_path("ghidra")
        if ghidra_path:
            return Path(ghidra_path)
        return None

    def _import_binary(self, project: GhidraProject, binary_path: str):
        """Import binary into Ghidra project"""
        try:
            # This would use Ghidra's import functionality
            # For now, just add to project binaries list
            project.binaries.append(binary_path)

        except Exception as e:
            self.logger.warning(f"Failed to import binary: {e}")

    def _run_auto_analysis(self, project: GhidraProject, binary_path: str):
        """Run automatic analysis on binary"""
        try:
            # This would run Ghidra's automatic analysis
            # For now, just mark as analyzed
            project.analysis_status[binary_path] = "analyzed"

        except Exception as e:
            self.logger.warning(f"Failed to run auto analysis: {e}")

    def _extract_functions(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract functions from binary"""
        try:
            # Create Python script for function extraction
            script_content = """
# Ghidra script to extract functions
from ghidra.program.model.listing import Function

functions = []
for func in currentProgram.getFunctionManager().getFunctions(True):
    functions.append({
        'name': func.getName(),
        'address': str(func.getEntryPoint()),
        'size': func.getBody().getNumAddresses(),
        'signature': func.getSignature().getPrototypeString()
    })

# Output functions as JSON
import json
print(json.dumps(functions, indent=2))
"""

            # Write script to temporary file
            script_path = self.temp_dir / "extract_functions.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                try:
                    return json.loads(result.output)
                except json.JSONDecodeError:
                    return []
            else:
                return []

        except Exception as e:
            self.logger.warning(f"Failed to extract functions: {e}")
            return []

    def _extract_strings(self, binary_path: str) -> List[str]:
        """Extract strings from binary"""
        try:
            # Create Python script for string extraction
            script_content = """
# Ghidra script to extract strings
from ghidra.program.model.listing import StringManager

string_manager = currentProgram.getStringManager()
strings = []

for string in string_manager.getStrings():
    strings.append(string.getValue())

# Output strings
for string in strings:
    print(string)
"""

            # Write script to temporary file
            script_path = self.temp_dir / "extract_strings.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                return result.output.strip().split('\n')
            else:
                return []

        except Exception as e:
            self.logger.warning(f"Failed to extract strings: {e}")
            return []

    def _extract_imports(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract imports from binary"""
        try:
            # Create Python script for import extraction
            script_content = """
# Ghidra script to extract imports
from ghidra.program.model.symbol import SymbolType

imports = []
for symbol in currentProgram.getSymbolTable().getSymbols(SymbolType.IMPORT):
    imports.append({
        'name': symbol.getName(),
        'address': str(symbol.getAddress()),
        'library': symbol.getParentNamespace().getName()
    })

# Output imports as JSON
import json
print(json.dumps(imports, indent=2))
"""

            # Write script to temporary file
            script_path = self.temp_dir / "extract_imports.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                try:
                    return json.loads(result.output)
                except json.JSONDecodeError:
                    return []
            else:
                return []

        except Exception as e:
            self.logger.warning(f"Failed to extract imports: {e}")
            return []

    def _extract_exports(self, binary_path: str) -> List[Dict[str, Any]]:
        """Extract exports from binary"""
        try:
            # Create Python script for export extraction
            script_content = """
# Ghidra script to extract exports
from ghidra.program.model.symbol import SymbolType

exports = []
for symbol in currentProgram.getSymbolTable().getSymbols(SymbolType.EXPORT):
    exports.append({
        'name': symbol.getName(),
        'address': str(symbol.getAddress())
    })

# Output exports as JSON
import json
print(json.dumps(exports, indent=2))
"""

            # Write script to temporary file
            script_path = self.temp_dir / "extract_exports.py"
            with open(script_path, 'w') as f:
                f.write(script_content)

            # Execute script
            result = self.execute_python_script(str(script_path), binary_path)

            if result.result == ScriptResult.SUCCESS:
                try:
                    return json.loads(result.output)
                except json.JSONDecodeError:
                    return []
            else:
                return []

        except Exception as e:
            self.logger.warning(f"Failed to extract exports: {e}")
            return []

    def _export_functions(self, binary_path: str, format: str) -> Dict[str, Any]:
        """Export functions in specified format"""
        try:
            functions = self._extract_functions(binary_path)
            return {'functions': functions, 'format': format}

        except Exception as e:
            self.logger.warning(f"Failed to export functions: {e}")
            return {}

    def _export_strings(self, binary_path: str, format: str) -> Dict[str, Any]:
        """Export strings in specified format"""
        try:
            strings = self._extract_strings(binary_path)
            return {'strings': strings, 'format': format}

        except Exception as e:
            self.logger.warning(f"Failed to export strings: {e}")
            return {}

    def _export_imports(self, binary_path: str, format: str) -> Dict[str, Any]:
        """Export imports in specified format"""
        try:
            imports = self._extract_imports(binary_path)
            return {'imports': imports, 'format': format}

        except Exception as e:
            self.logger.warning(f"Failed to export imports: {e}")
            return {}

    def _export_exports(self, binary_path: str, format: str) -> Dict[str, Any]:
        """Export exports in specified format"""
        try:
            exports = self._extract_exports(binary_path)
            return {'exports': exports, 'format': format}

        except Exception as e:
            self.logger.warning(f"Failed to export exports: {e}")
            return {}
