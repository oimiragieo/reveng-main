"""
PE Analyzer Plugin for REVENG

Plugin for analyzing Portable Executable (PE) files.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

from ..base import AnalysisPlugin, PluginMetadata, PluginContext, PluginCategory, PluginPriority
from ...core.errors import PluginError
from ...core.logger import get_logger

logger = get_logger()

class PEAnalyzerPlugin(AnalysisPlugin):
    """PE file analysis plugin"""

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata"""
        return PluginMetadata(
            name="pe_analyzer",
            version="1.0.0",
            description="Analyzes Portable Executable (PE) files for structure, imports, exports, and resources",
            author="REVENG Team",
            category=PluginCategory.CORE_ANALYSIS,
            priority=PluginPriority.HIGH,
            dependencies=[],
            requirements=["pefile"],
            tags=["pe", "windows", "executable", "analysis"],
            homepage="https://github.com/reveng/reveng",
            license="MIT",
            min_reveng_version="1.0.0"
        )

    def initialize(self, context: PluginContext) -> bool:
        """Initialize the plugin"""
        try:
            # Check if pefile is available
            try:
                import pefile
                self.pefile = pefile
            except ImportError:
                logger.error("pefile library not available")
                return False

            logger.info("PE Analyzer plugin initialized")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize PE Analyzer plugin: {e}")
            return False

    def analyze(self, context: PluginContext) -> Dict[str, Any]:
        """Perform PE analysis"""

        try:
            binary_path = context.binary_path
            if not Path(binary_path).exists():
                raise PluginError(f"Binary file not found: {binary_path}", plugin_name=self.metadata.name)

            logger.info(f"Analyzing PE file: {binary_path}")

            # Load PE file
            pe = self.pefile.PE(binary_path)

            # Basic PE information
            pe_info = {
                "file_path": binary_path,
                "file_size": Path(binary_path).stat().st_size,
                "pe_type": "PE32" if pe.PE_TYPE == 0x10b else "PE32+",
                "machine": hex(pe.FILE_HEADER.Machine),
                "characteristics": hex(pe.FILE_HEADER.Characteristics),
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "image_size": pe.OPTIONAL_HEADER.SizeOfImage,
                "subsystem": hex(pe.OPTIONAL_HEADER.Subsystem),
                "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics)
            }

            # Sections
            sections = []
            for section in pe.sections:
                sections.append({
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_address": hex(section.PointerToRawData),
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics)
                })
            pe_info["sections"] = sections

            # Imports
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    for imp in entry.imports:
                        if imp.name:
                            imports.append({
                                "dll": dll_name,
                                "function": imp.name.decode('utf-8', errors='ignore'),
                                "address": hex(imp.address)
                            })
                        else:
                            imports.append({
                                "dll": dll_name,
                                "function": f"Ordinal_{imp.ordinal}",
                                "address": hex(imp.address)
                            })
            pe_info["imports"] = imports

            # Exports
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append({
                        "name": exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}",
                        "address": hex(exp.address),
                        "ordinal": exp.ordinal
                    })
            pe_info["exports"] = exports

            # Resources
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name:
                        type_name = str(resource_type.name)
                    else:
                        type_name = f"Type_{resource_type.id}"

                    for resource_id in resource_type.directory.entries:
                        if resource_id.name:
                            id_name = str(resource_id.name)
                        else:
                            id_name = f"ID_{resource_id.id}"

                        for resource_lang in resource_id.directory.entries:
                            resources.append({
                                "type": type_name,
                                "id": id_name,
                                "language": resource_lang.id,
                                "address": hex(resource_lang.data.struct.OffsetToData),
                                "size": resource_lang.data.struct.Size
                            })
            pe_info["resources"] = resources

            # Strings
            strings = []
            try:
                # Simple string extraction (in a real implementation, you'd use a proper string extractor)
                with open(binary_path, 'rb') as f:
                    data = f.read()

                current_string = ""
                for byte in data:
                    if 32 <= byte <= 126:  # Printable ASCII
                        current_string += chr(byte)
                    else:
                        if len(current_string) >= 4:
                            strings.append(current_string)
                        current_string = ""

                if len(current_string) >= 4:
                    strings.append(current_string)

            except Exception as e:
                logger.warning(f"Failed to extract strings: {e}")

            pe_info["strings"] = strings[:100]  # Limit to first 100 strings

            logger.info(f"PE analysis completed: {len(sections)} sections, {len(imports)} imports, {len(exports)} exports")

            return {
                "pe_info": pe_info,
                "analysis_type": "pe_analysis",
                "success": True
            }

        except Exception as e:
            logger.error(f"PE analysis failed: {e}")
            return {
                "analysis_type": "pe_analysis",
                "success": False,
                "error": str(e)
            }

    def cleanup(self, context: PluginContext) -> bool:
        """Cleanup plugin resources"""
        try:
            logger.info("PE Analyzer plugin cleanup completed")
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup PE Analyzer plugin: {e}")
            return False
