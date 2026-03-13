/* ###
 * Export Ghidra analysis to JSON.
 */
//@category Analysis

import java.io.FileWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalLocationIterator;
import ghidra.program.model.symbol.ExternalManager;

public class ExportAnalysisJSON extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		String outputFile = (args != null && args.length > 0) ? args[0] : "analysis.json";

		Map<String, Object> result = exportAnalysis();
		Gson gson = new GsonBuilder().setPrettyPrinting().create();

		try (Writer writer = new FileWriter(outputFile)) {
			gson.toJson(result, writer);
		}

		println("Analysis exported to: " + outputFile);
		println("Functions found: " + ((List<?>) result.get("functions")).size());
		println("Strings found: " + ((List<?>) result.get("strings")).size());
		println("Imports found: " + ((List<?>) result.get("imports")).size());
	}

	private Map<String, Object> exportAnalysis() throws Exception {
		Program program = currentProgram;
		Listing listing = program.getListing();
		DecompInterface decompiler = new DecompInterface();
		decompiler.openProgram(program);

		Map<String, Object> result = new LinkedHashMap<>();
		result.put("status", "success");
		result.put("program_name", program.getName());
		result.put("language", program.getLanguageID().toString());
		result.put("compiler", program.getCompilerSpec().getCompilerSpecID().toString());

		List<Map<String, Object>> functions = new ArrayList<>();
		List<Map<String, Object>> strings = new ArrayList<>();
		List<Map<String, Object>> imports = new ArrayList<>();
		result.put("functions", functions);
		result.put("strings", strings);
		result.put("imports", imports);
		result.put("exports", new ArrayList<Map<String, Object>>());
		result.put("xrefs", new ArrayList<Map<String, Object>>());

		try {
			FunctionIterator functionIterator = program.getFunctionManager().getFunctions(true);
			while (functionIterator.hasNext() && !monitor.isCancelled()) {
				Function function = functionIterator.next();
				Map<String, Object> functionData = new LinkedHashMap<>();
				String entryPoint = function.getEntryPoint().toString();

				functionData.put("name", function.getName());
				functionData.put("entry_point", entryPoint);
				functionData.put("address", entryPoint);
				functionData.put("signature", function.getSignature().toString());
				functionData.put("calling_convention", String.valueOf(function.getCallingConventionName()));
				functionData.put("source", "");
				functionData.put("decompiled", "");

				List<Map<String, Object>> body = new ArrayList<>();
				functionData.put("body", body);
				InstructionIterator instructions = listing.getInstructions(function.getBody(), true);
				while (instructions.hasNext() && !monitor.isCancelled()) {
					Instruction instruction = instructions.next();
					Map<String, Object> instructionData = new LinkedHashMap<>();
					instructionData.put("address", instruction.getAddress().toString());
					instructionData.put("mnemonic", instruction.getMnemonicString());
					instructionData.put(
						"operands",
						instruction.getNumOperands() > 0 ? instruction.getDefaultOperandRepresentation(0) : ""
					);
					body.add(instructionData);
				}

				try {
					DecompileResults decompileResults = decompiler.decompileFunction(function, 30, monitor);
					if (decompileResults != null && decompileResults.decompileCompleted() && decompileResults.getDecompiledFunction() != null) {
						String source = decompileResults.getDecompiledFunction().getC();
						functionData.put("source", source != null ? source : "");
						functionData.put("decompiled", source != null ? source : "");
					}
					else if (decompileResults != null) {
						String errorMessage = decompileResults.getErrorMessage();
						functionData.put("decompile_error", errorMessage != null ? errorMessage : "Unknown decompilation error");
					}
				}
				catch (Exception exception) {
					functionData.put("decompile_error", exception.toString());
				}

				functions.add(functionData);
			}

			functions.sort(
				(left, right) -> Integer.compare(
					String.valueOf(right.get("source")).length(),
					String.valueOf(left.get("source")).length()
				)
			);

			DataIterator definedData = listing.getDefinedData(true);
			while (definedData.hasNext() && !monitor.isCancelled()) {
				Data data = definedData.next();
				try {
					if (data != null && data.hasStringValue()) {
						Map<String, Object> stringData = new LinkedHashMap<>();
						stringData.put("address", data.getAddress().toString());
						stringData.put("value", String.valueOf(data.getValue()));
						stringData.put("length", data.getLength());
						strings.add(stringData);
					}
				}
				catch (Exception exception) {
					// Ignore malformed string values and continue exporting other data.
				}
			}

			ExternalManager externalManager = program.getExternalManager();
			for (String libraryName : externalManager.getExternalLibraryNames()) {
				ExternalLocationIterator externalLocations = externalManager.getExternalLocations(libraryName);
				while (externalLocations.hasNext()) {
					ExternalLocation externalLocation = externalLocations.next();
					Map<String, Object> importData = new LinkedHashMap<>();
					importData.put("name", externalLocation.getLabel());
					importData.put("library", libraryName);
					importData.put(
						"address",
						externalLocation.getExternalSpaceAddress() != null
							? externalLocation.getExternalSpaceAddress().toString()
							: "external"
					);
					imports.add(importData);
				}
			}
		}
		finally {
			decompiler.dispose();
		}

		return result;
	}
}
