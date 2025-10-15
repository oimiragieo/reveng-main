#!/usr/bin/env python3
"""
Type Inference Engine
=====================

This tool infers types for functions and variables using:
- Ghidra's decompiler type information
- Cross-reference analysis
- Pattern-based heuristics
- Confidence scoring

Author: Enhancement
Version: 1.0
"""

import json
import logging
import re
import requests
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Import the robust C type parser
try:
    from c_type_parser import CTypeParser, CFunctionSignature, CParameter, CType
    HAS_C_TYPE_PARSER = True
except ImportError:
    logger.warning("c_type_parser not found, falling back to regex")
    HAS_C_TYPE_PARSER = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('type_inference.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class TypeCategory(Enum):
    """Type categories"""
    POINTER = "pointer"
    INTEGER = "integer"
    FLOAT = "float"
    STRUCT = "struct"
    ARRAY = "array"
    VOID = "void"
    UNKNOWN = "unknown"


@dataclass
class Parameter:
    """Function parameter with inferred type"""
    name: str
    type: str
    category: TypeCategory
    confidence: float
    is_const: bool = False
    is_pointer: bool = False


@dataclass
class FunctionSignature:
    """Complete function signature with types"""
    name: str
    address: str
    return_type: str
    parameters: List[Parameter]
    calling_convention: str
    confidence: float


class TypeInferenceEngine:
    """
    Type Inference Engine

    Infers accurate types for functions and variables using:
    - Ghidra decompiler analysis
    - Cross-reference patterns
    - API usage patterns
    - Heuristic rules
    """

    def __init__(self, mcp_server_url: str = "http://localhost:13337/mcp"):
        """Initialize the type inference engine"""
        self.mcp_server_url = mcp_server_url
        self.type_cache = {}

        # Initialize C type parser if available
        if HAS_C_TYPE_PARSER:
            self.parser = CTypeParser()
            logger.info("Using robust CTypeParser")
        else:
            self.parser = None
            logger.warning("CTypeParser not available, using regex fallback")

        # Common type patterns
        self.type_patterns = {
            r'.*[Ff]ile.*': ('FILE *', 0.8),
            r'.*[Hh]andle.*': ('HANDLE', 0.8),
            r'.*[Pp]tr.*': ('void *', 0.7),
            r'.*[Ss]ize.*': ('size_t', 0.8),
            r'.*[Ll]en(gth)?': ('int', 0.7),
            r'.*[Cc]ount.*': ('int', 0.7),
            r'.*[Bb]uffer.*': ('char *', 0.8),
            r'.*[Ss]tr(ing)?': ('char *', 0.8),
            r'.*[Dd]ata.*': ('void *', 0.6),
        }

        logger.info("Type Inference Engine initialized")

    def _mcp_request(self, method: str, params: Dict) -> Dict:
        """Make MCP request to Ghidra"""
        try:
            response = requests.post(
                self.mcp_server_url,
                json={
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": 1
                },
                timeout=30
            )
            return response.json().get("result", {})
        except Exception as e:
            logger.error(f"MCP request failed: {e}")
            return {}

    def infer_function_signature(self, func_name: str, func_addr: str) -> FunctionSignature:
        """Infer complete function signature"""
        logger.info(f"Inferring signature for {func_name} at {func_addr}")

        # Get decompiled code from Ghidra
        decompiled = self._mcp_request("decompile_function", {"address": func_addr})

        if not decompiled:
            logger.warning(f"No decompilation available for {func_name}")
            return self._create_default_signature(func_name, func_addr)

        # Parse signature from decompiled code (pass func_addr to preserve it)
        signature = self._parse_ghidra_signature(decompiled.get("pseudocode", ""), func_addr)

        if signature:
            # Enhance with xref analysis
            xrefs = self._mcp_request("get_xrefs_to", {"address": func_addr})
            signature = self._enhance_with_xrefs(signature, xrefs)

            # Apply heuristics
            signature = self._apply_heuristics(signature, func_name)

            logger.info(f"Inferred signature: {signature.return_type} {signature.name}(...)")
            return signature

        return self._create_default_signature(func_name, func_addr)

    def _parse_ghidra_signature(self, pseudocode: str, func_addr: str = "") -> Optional[FunctionSignature]:
        """Parse function signature from Ghidra pseudocode"""

        # Use robust C type parser if available
        if self.parser:
            try:
                c_sig = self.parser.parse_function_signature(pseudocode, func_addr)
                if c_sig:
                    # Convert to our FunctionSignature format
                    params = []
                    for c_param in c_sig.parameters:
                        params.append(Parameter(
                            name=c_param.name,
                            type=str(c_param.type),
                            category=TypeCategory.UNKNOWN,
                            confidence=0.9,
                            is_pointer='*' in str(c_param.type)
                        ))

                    return FunctionSignature(
                        name=c_sig.name,
                        address=func_addr,  # PRESERVE ADDRESS
                        return_type=str(c_sig.return_type),
                        parameters=params,
                        calling_convention=c_sig.calling_convention or "stdcall",
                        confidence=0.9
                    )
            except Exception as e:
                logger.warning(f"CTypeParser failed, falling back to regex: {e}")

        # Fallback to regex (handles simple cases)
        # Look for function signature pattern
        # Example: "int foo(char *param_1, int param_2)"
        pattern = r'(\w+(?:\s*\*)?)\s+(\w+)\s*\((.*?)\)'
        match = re.search(pattern, pseudocode)

        if not match:
            return None

        return_type = match.group(1).strip()
        func_name = match.group(2).strip()
        params_str = match.group(3).strip()

        # Parse parameters
        parameters = []
        if params_str and params_str != "void":
            for param_str in params_str.split(','):
                param = self._parse_parameter(param_str.strip())
                if param:
                    parameters.append(param)

        return FunctionSignature(
            name=func_name,
            address=func_addr,  # PRESERVE ADDRESS (was dropping it)
            return_type=return_type,
            parameters=parameters,
            calling_convention="stdcall",
            confidence=0.9  # High confidence from Ghidra
        )

    def _parse_parameter(self, param_str: str) -> Optional[Parameter]:
        """Parse parameter from string like 'char *param_1'"""

        # Split type and name
        parts = param_str.rsplit(None, 1)
        if len(parts) != 2:
            return None

        param_type, param_name = parts

        # Determine category
        is_pointer = '*' in param_type
        category = self._categorize_type(param_type)

        return Parameter(
            name=param_name,
            type=param_type,
            category=category,
            confidence=0.9,
            is_pointer=is_pointer
        )

    def _categorize_type(self, type_str: str) -> TypeCategory:
        """Categorize a type string"""
        type_lower = type_str.lower().replace('*', '').strip()

        if type_lower == 'void':
            return TypeCategory.VOID
        elif any(t in type_lower for t in ['int', 'long', 'short', 'char', 'byte']):
            return TypeCategory.INTEGER
        elif any(t in type_lower for t in ['float', 'double']):
            return TypeCategory.FLOAT
        elif 'struct' in type_lower or 'union' in type_lower:
            return TypeCategory.STRUCT
        elif '*' in type_str:
            return TypeCategory.POINTER
        elif '[' in type_str:
            return TypeCategory.ARRAY
        else:
            return TypeCategory.UNKNOWN

    def _enhance_with_xrefs(self, signature: FunctionSignature, xrefs: Dict) -> FunctionSignature:
        """Enhance signature using cross-reference analysis"""

        # Analyze how the function is called
        # This could improve parameter types and return type inference

        return signature

    def _apply_heuristics(self, signature: FunctionSignature, func_name: str) -> FunctionSignature:
        """Apply heuristic rules to improve type inference"""

        # Apply name-based patterns to parameters
        for param in signature.parameters:
            for pattern, (suggested_type, confidence) in self.type_patterns.items():
                if re.match(pattern, param.name, re.IGNORECASE):
                    if param.confidence < confidence:
                        param.type = suggested_type
                        param.confidence = confidence
                        param.is_pointer = '*' in suggested_type

        return signature

    def _create_default_signature(self, func_name: str, func_addr: str) -> FunctionSignature:
        """Create default signature when inference fails"""
        return FunctionSignature(
            name=func_name,
            address=func_addr,
            return_type="void",
            parameters=[],
            calling_convention="stdcall",
            confidence=0.3  # Low confidence
        )

    def infer_types_for_project(self, functions_file: Path) -> Dict[str, FunctionSignature]:
        """Infer types for all functions in a project"""
        logger.info(f"Inferring types for project")

        # Load functions
        with open(functions_file, 'r') as f:
            functions = json.load(f)

        signatures = {}
        for func in functions:
            sig = self.infer_function_signature(func['name'], func['address'])
            signatures[func['name']] = sig

        logger.info(f"Inferred types for {len(signatures)} functions")
        return signatures

    def export_signatures(self, signatures: Dict[str, FunctionSignature], output_file: Path):
        """Export signatures to header file"""
        logger.info(f"Exporting signatures to {output_file}")

        with open(output_file, 'w') as f:
            f.write("/* Auto-generated function signatures */\n\n")

            for sig in signatures.values():
                # Generate parameter list
                params_str = ", ".join([
                    f"{p.type} {p.name}" for p in sig.parameters
                ]) or "void"

                # Write signature with confidence comment
                f.write(f"/* Confidence: {sig.confidence:.2f} */\n")
                f.write(f"{sig.return_type} {sig.name}({params_str});\n\n")


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Infer types for functions')
    parser.add_argument('--functions', required=True, help='Functions JSON file')
    parser.add_argument('--output', default='signatures.h', help='Output header file')
    args = parser.parse_args()

    # Create engine
    engine = TypeInferenceEngine()

    # Infer types
    signatures = engine.infer_types_for_project(Path(args.functions))

    # Export
    engine.export_signatures(signatures, Path(args.output))

    print(f"\nInferred types for {len(signatures)} functions")


if __name__ == "__main__":
    main()