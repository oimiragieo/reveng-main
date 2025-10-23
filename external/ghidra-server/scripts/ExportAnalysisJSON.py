# ExportAnalysisJSON.py - Export Ghidra analysis to JSON
# @category Analysis
# @author REVENG Team

import json
import sys
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def export_analysis(output_file):
    """Export complete Ghidra analysis to JSON"""

    # Initialize decompiler
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)

    # Get program info
    program = currentProgram
    listing = program.getListing()
    memory = program.getMemory()

    result = {
        "status": "success",
        "program_name": program.getName(),
        "language": str(program.getLanguageID()),
        "compiler": str(program.getCompilerSpec().getCompilerSpecID()),
        "functions": [],
        "strings": [],
        "imports": [],
        "exports": [],
        "xrefs": []
    }

    # Extract functions
    function_manager = program.getFunctionManager()
    functions = function_manager.getFunctions(True)  # True = forward iteration

    for func in functions:
        func_data = {
            "name": func.getName(),
            "entry_point": str(func.getEntryPoint()),
            "body": [],
            "decompiled": None,
            "signature": str(func.getSignature()),
            "calling_convention": str(func.getCallingConventionName())
        }

        # Get assembly instructions
        instructions = listing.getInstructions(func.getBody(), True)
        for instr in instructions:
            func_data["body"].append({
                "address": str(instr.getAddress()),
                "mnemonic": str(instr.getMnemonicString()),
                "operands": str(instr.getDefaultOperandRepresentation(0)) if instr.getNumOperands() > 0 else ""
            })

        # Decompile function
        try:
            decompile_results = decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
            if decompile_results and decompile_results.decompileCompleted():
                func_data["decompiled"] = str(decompile_results.getDecompiledFunction().getC())
        except:
            pass  # Decompilation failed, skip

        result["functions"].append(func_data)

    # Extract strings
    defined_data = listing.getDefinedData(True)
    for data in defined_data:
        if data.hasStringValue():
            result["strings"].append({
                "address": str(data.getAddress()),
                "value": str(data.getValue()),
                "length": data.getLength()
            })

    # Extract imports
    external_manager = program.getExternalManager()
    ext_names = external_manager.getExternalLibraryNames()
    for lib_name in ext_names:
        externals = external_manager.getExternalLocations(lib_name)
        while externals.hasNext():
            ext_loc = externals.next()
            result["imports"].append({
                "name": ext_loc.getLabel(),
                "library": lib_name,
                "address": str(ext_loc.getExternalSpaceAddress()) if ext_loc.getExternalSpaceAddress() else "external"
            })

    # Extract exports - skip for now to avoid API issues
    # TODO: Fix exports extraction
    pass

    # Write JSON output
    with open(output_file, 'w') as f:
        json.dump(result, f, indent=2)

    print("Analysis exported to: " + output_file)
    print("Functions found: " + str(len(result["functions"])))
    print("Strings found: " + str(len(result["strings"])))
    print("Imports found: " + str(len(result["imports"])))

# Main execution
if __name__ == "__main__":
    # Get output file from script arguments
    args = getScriptArgs()
    if args and len(args) > 0:
        output_file = args[0]
    else:
        output_file = "/tmp/analysis.json"

    export_analysis(output_file)
