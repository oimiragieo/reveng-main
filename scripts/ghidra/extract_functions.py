#!/usr/bin/env python3
"""
Ghidra script to extract all function signatures and metadata

This script analyzes a binary in Ghidra and extracts:
- Function addresses and names
- Function signatures
- Cross-references
- Basic block information
- Function complexity metrics

Usage:
    ghidraRun headless extract_functions.py <binary_path>
"""

import json
import sys
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.listing import Function
from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import AddressSet
from ghidra.util.task import ConsoleTaskMonitor

def extract_functions():
    """Extract all function information from the current program"""

    # Get current program
    program = getCurrentProgram()
    if not program:
        print("Error: No program loaded")
        return

    # Get function manager
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True = forward iteration

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(program)

    # Results storage
    results = {
        'program_name': program.getName(),
        'program_language': str(program.getLanguage()),
        'function_count': 0,
        'functions': []
    }

    print(f"Analyzing {program.getName()}...")
    print(f"Found {len(list(functions))} functions")

    # Process each function
    for function in functions:
        try:
            function_info = extract_function_info(function, decompiler)
            results['functions'].append(function_info)
            results['function_count'] += 1

        except Exception as e:
            print(f"Error processing function {function.getName()}: {e}")
            continue

    # Output results
    output_file = f"{program.getName()}_functions.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"Results saved to {output_file}")
    print(f"Extracted {results['function_count']} functions")

def extract_function_info(function, decompiler):
    """Extract information for a single function"""

    # Basic function information
    function_info = {
        'name': function.getName(),
        'address': str(function.getEntryPoint()),
        'size': function.getBody().getNumAddresses(),
        'signature': str(function.getSignature()),
        'calling_convention': str(function.getCallingConvention()),
        'return_type': str(function.getReturnType()),
        'parameter_count': function.getParameterCount(),
        'local_variable_count': function.getLocalVariableCount(),
        'stack_depth': function.getStackFrame().getFrameSize(),
        'is_external': function.isExternal(),
        'is_thunk': function.isThunk(),
        'is_inline': function.isInline(),
        'complexity_score': 0,
        'basic_blocks': [],
        'cross_references': [],
        'parameters': [],
        'local_variables': []
    }

    # Extract parameters
    for i, param in enumerate(function.getParameters()):
        param_info = {
            'index': i,
            'name': param.getName(),
            'type': str(param.getDataType()),
            'storage': str(param.getStorage())
        }
        function_info['parameters'].append(param_info)

    # Extract local variables
    for var in function.getLocalVariables():
        var_info = {
            'name': var.getName(),
            'type': str(var.getDataType()),
            'storage': str(var.getStorage()),
            'offset': var.getStackOffset()
        }
        function_info['local_variables'].append(var_info)

    # Extract basic blocks
    basic_blocks = function.getBody().getBasicBlocks()
    for block in basic_blocks:
        block_info = {
            'start_address': str(block.getStart()),
            'end_address': str(block.getEnd()),
            'size': block.getNumAddresses(),
            'instruction_count': block.getNumAddresses()
        }
        function_info['basic_blocks'].append(block_info)

    # Calculate complexity score
    function_info['complexity_score'] = calculate_complexity(function)

    # Extract cross-references
    xrefs = function.getSymbol().getReferences()
    for xref in xrefs:
        xref_info = {
            'type': str(xref.getReferenceType()),
            'from_address': str(xref.getFromAddress()),
            'to_address': str(xref.getToAddress()),
            'source': str(xref.getSource())
        }
        function_info['cross_references'].append(xref_info)

    return function_info

def calculate_complexity(function):
    """Calculate function complexity score"""

    # Simple complexity metric based on:
    # - Number of basic blocks
    # - Function size
    # - Number of parameters
    # - Number of local variables

    basic_blocks = function.getBody().getBasicBlocks()
    num_blocks = len(list(basic_blocks))
    function_size = function.getBody().getNumAddresses()
    param_count = function.getParameterCount()
    local_var_count = function.getLocalVariableCount()

    # Weighted complexity score
    complexity = (
        num_blocks * 2 +           # Basic blocks are important
        function_size * 0.1 +      # Size matters but less weight
        param_count * 1.5 +        # Parameters add complexity
        local_var_count * 0.5      # Local variables add some complexity
    )

    return round(complexity, 2)

def main():
    """Main script entry point"""
    try:
        extract_functions()
    except Exception as e:
        print(f"Script error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
