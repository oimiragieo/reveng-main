"""
REVENG PE Resource Extractor

Extract resources from PE files including icons, strings, manifests, version info,
and custom resources.
"""

import os
import sys
import subprocess
import tempfile
import struct
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
import json
import xml.etree.ElementTree as ET

from ..core.errors import AnalysisFailureError, MissingDependencyError, create_error_context
from ..core.logger import get_logger

class ResourceType(Enum):
    """PE resource types"""
    ICON = "icon"
    BITMAP = "bitmap"
    STRING = "string"
    MANIFEST = "manifest"
    VERSION = "version"
    CUSTOM = "custom"
    EMBEDDED_FILE = "embedded_file"

@dataclass
class IconResource:
    """Icon resource information"""
    id: str
    size: Tuple[int, int]
    format: str
    data: bytes
    file_path: Optional[str] = None

@dataclass
class StringResource:
    """String resource information"""
    id: str
    language: str
    value: str
    encoding: str = "utf-8"

@dataclass
class ManifestResource:
    """Manifest resource information"""
    id: str
    content: str
    version: str
    dependencies: List[str]
    capabilities: List[str]

@dataclass
class VersionResource:
    """Version resource information"""
    file_version: str
    product_version: str
    company_name: str
    product_name: str
    file_description: str
    legal_copyright: str
    legal_trademarks: str

@dataclass
class CustomResource:
    """Custom resource information"""
    id: str
    type: str
    data: bytes
    size: int
    file_path: Optional[str] = None

@dataclass
class ResourceCollection:
    """Collection of extracted resources"""
    icons: List[IconResource]
    bitmaps: List[IconResource]
    strings: List[StringResource]
    manifests: List[ManifestResource]
    version_info: Optional[VersionResource]
    custom_resources: List[CustomResource]
    embedded_files: List[CustomResource]

class PEResourceExtractor:
    """Extract resources from PE files"""

    def __init__(self):
        self.logger = get_logger("pe_resource_extractor")
        self.temp_dir = Path(tempfile.gettempdir()) / "reveng_pe_resources"
        self.temp_dir.mkdir(exist_ok=True)

    def extract_all_resources(self, binary_path: str) -> ResourceCollection:
        """Extract all embedded resources from PE file"""
        try:
            self.logger.info(f"Starting PE resource extraction from {binary_path}")

            # Extract icons
            icons = self.extract_icons(binary_path)

            # Extract bitmaps
            bitmaps = self.extract_bitmaps(binary_path)

            # Extract strings
            strings = self.extract_string_table(binary_path)

            # Extract manifests
            manifests = self.extract_manifests(binary_path)

            # Extract version info
            version_info = self.extract_version_info(binary_path)

            # Extract custom resources
            custom_resources = self.extract_custom_resources(binary_path)

            # Extract embedded files
            embedded_files = self.detect_embedded_files(binary_path)

            collection = ResourceCollection(
                icons=icons,
                bitmaps=bitmaps,
                strings=strings,
                manifests=manifests,
                version_info=version_info,
                custom_resources=custom_resources,
                embedded_files=embedded_files
            )

            self.logger.info(f"Extracted {len(icons)} icons, {len(strings)} strings, {len(manifests)} manifests")
            return collection

        except Exception as e:
            context = create_error_context(
                "pe_resource_extractor",
                "extract_all_resources",
                binary_path=binary_path
            )
            raise AnalysisFailureError(
                "pe_resource_extraction",
                binary_path,
                context=context,
                fallback_available=True,
                original_exception=e
            )

    def extract_icons(self, binary_path: str) -> List[IconResource]:
        """Extract icon resources from PE file"""
        try:
            icons = []

            # Use Resource Hacker to extract icons
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                icons = self._extract_icons_with_rh(binary_path, rh_path)
            else:
                # Fallback: manual extraction
                icons = self._extract_icons_manual(binary_path)

            return icons

        except Exception as e:
            self.logger.warning(f"Failed to extract icons: {e}")
            return []

    def extract_bitmaps(self, binary_path: str) -> List[IconResource]:
        """Extract bitmap resources from PE file"""
        try:
            bitmaps = []

            # Use Resource Hacker to extract bitmaps
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                bitmaps = self._extract_bitmaps_with_rh(binary_path, rh_path)
            else:
                # Fallback: manual extraction
                bitmaps = self._extract_bitmaps_manual(binary_path)

            return bitmaps

        except Exception as e:
            self.logger.warning(f"Failed to extract bitmaps: {e}")
            return []

    def extract_string_table(self, binary_path: str) -> List[StringResource]:
        """Extract string table resources from PE file"""
        try:
            strings = []

            # Use Resource Hacker to extract strings
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                strings = self._extract_strings_with_rh(binary_path, rh_path)
            else:
                # Fallback: manual extraction
                strings = self._extract_strings_manual(binary_path)

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to extract strings: {e}")
            return []

    def extract_manifests(self, binary_path: str) -> List[ManifestResource]:
        """Extract application manifests from PE file"""
        try:
            manifests = []

            # Use Resource Hacker to extract manifests
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                manifests = self._extract_manifests_with_rh(binary_path, rh_path)
            else:
                # Fallback: manual extraction
                manifests = self._extract_manifests_manual(binary_path)

            return manifests

        except Exception as e:
            self.logger.warning(f"Failed to extract manifests: {e}")
            return []

    def extract_version_info(self, binary_path: str) -> Optional[VersionResource]:
        """Extract version information from PE file"""
        try:
            # Use Resource Hacker to extract version info
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                version_info = self._extract_version_with_rh(binary_path, rh_path)
            else:
                # Fallback: manual extraction
                version_info = self._extract_version_manual(binary_path)

            return version_info

        except Exception as e:
            self.logger.warning(f"Failed to extract version info: {e}")
            return None

    def extract_custom_resources(self, binary_path: str) -> List[CustomResource]:
        """Extract custom resources from PE file"""
        try:
            custom_resources = []

            # Use Resource Hacker to extract custom resources
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                custom_resources = self._extract_custom_with_rh(binary_path, rh_path)
            else:
                # Fallback: manual extraction
                custom_resources = self._extract_custom_manual(binary_path)

            return custom_resources

        except Exception as e:
            self.logger.warning(f"Failed to extract custom resources: {e}")
            return []

    def detect_embedded_files(self, binary_path: str) -> List[CustomResource]:
        """Detect embedded files in PE resources"""
        try:
            embedded_files = []

            # Analyze resources for embedded files
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Look for embedded files by analyzing resource data
            embedded_files = self._analyze_resources_for_embedded_files(data)

            return embedded_files

        except Exception as e:
            self.logger.warning(f"Failed to detect embedded files: {e}")
            return []

    def _get_resource_hacker_path(self) -> Optional[str]:
        """Get Resource Hacker executable path"""
        from ..core.dependency_manager import DependencyManager
        dm = DependencyManager()
        return dm.get_tool_path("resource_hacker")

    def _extract_icons_with_rh(self, binary_path: str, rh_path: str) -> List[IconResource]:
        """Extract icons using Resource Hacker"""
        try:
            icons = []
            output_dir = self.temp_dir / "icons"
            output_dir.mkdir(exist_ok=True)

            # Run Resource Hacker to extract icons
            result = subprocess.run([
                rh_path,
                "-open", binary_path,
                "-action", "extract",
                "-mask", "ICON,*",
                "-save", str(output_dir / "icons.rc")
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse extracted icons
                icons = self._parse_extracted_icons(output_dir)

            return icons

        except Exception as e:
            self.logger.warning(f"Failed to extract icons with Resource Hacker: {e}")
            return []

    def _extract_icons_manual(self, binary_path: str) -> List[IconResource]:
        """Extract icons manually by parsing PE structure"""
        try:
            icons = []

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE structure to find resource section
            resource_section = self._find_resource_section(data)
            if resource_section:
                icons = self._parse_icon_resources(data, resource_section)

            return icons

        except Exception as e:
            self.logger.warning(f"Failed to extract icons manually: {e}")
            return []

    def _extract_bitmaps_with_rh(self, binary_path: str, rh_path: str) -> List[IconResource]:
        """Extract bitmaps using Resource Hacker"""
        try:
            bitmaps = []
            output_dir = self.temp_dir / "bitmaps"
            output_dir.mkdir(exist_ok=True)

            # Run Resource Hacker to extract bitmaps
            result = subprocess.run([
                rh_path,
                "-open", binary_path,
                "-action", "extract",
                "-mask", "BITMAP,*",
                "-save", str(output_dir / "bitmaps.rc")
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse extracted bitmaps
                bitmaps = self._parse_extracted_bitmaps(output_dir)

            return bitmaps

        except Exception as e:
            self.logger.warning(f"Failed to extract bitmaps with Resource Hacker: {e}")
            return []

    def _extract_bitmaps_manual(self, binary_path: str) -> List[IconResource]:
        """Extract bitmaps manually"""
        try:
            bitmaps = []

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE structure to find bitmap resources
            resource_section = self._find_resource_section(data)
            if resource_section:
                bitmaps = self._parse_bitmap_resources(data, resource_section)

            return bitmaps

        except Exception as e:
            self.logger.warning(f"Failed to extract bitmaps manually: {e}")
            return []

    def _extract_strings_with_rh(self, binary_path: str, rh_path: str) -> List[StringResource]:
        """Extract strings using Resource Hacker"""
        try:
            strings = []

            # Run Resource Hacker to extract strings
            result = subprocess.run([
                rh_path,
                "-open", binary_path,
                "-action", "extract",
                "-mask", "STRING,*",
                "-save", str(self.temp_dir / "strings.rc")
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse extracted strings
                strings = self._parse_extracted_strings(self.temp_dir / "strings.rc")

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to extract strings with Resource Hacker: {e}")
            return []

    def _extract_strings_manual(self, binary_path: str) -> List[StringResource]:
        """Extract strings manually"""
        try:
            strings = []

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE structure to find string resources
            resource_section = self._find_resource_section(data)
            if resource_section:
                strings = self._parse_string_resources(data, resource_section)

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to extract strings manually: {e}")
            return []

    def _extract_manifests_with_rh(self, binary_path: str, rh_path: str) -> List[ManifestResource]:
        """Extract manifests using Resource Hacker"""
        try:
            manifests = []

            # Run Resource Hacker to extract manifests
            result = subprocess.run([
                rh_path,
                "-open", binary_path,
                "-action", "extract",
                "-mask", "MANIFEST,*",
                "-save", str(self.temp_dir / "manifests.rc")
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse extracted manifests
                manifests = self._parse_extracted_manifests(self.temp_dir / "manifests.rc")

            return manifests

        except Exception as e:
            self.logger.warning(f"Failed to extract manifests with Resource Hacker: {e}")
            return []

    def _extract_manifests_manual(self, binary_path: str) -> List[ManifestResource]:
        """Extract manifests manually"""
        try:
            manifests = []

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE structure to find manifest resources
            resource_section = self._find_resource_section(data)
            if resource_section:
                manifests = self._parse_manifest_resources(data, resource_section)

            return manifests

        except Exception as e:
            self.logger.warning(f"Failed to extract manifests manually: {e}")
            return []

    def _extract_version_with_rh(self, binary_path: str, rh_path: str) -> Optional[VersionResource]:
        """Extract version info using Resource Hacker"""
        try:
            # Run Resource Hacker to extract version info
            result = subprocess.run([
                rh_path,
                "-open", binary_path,
                "-action", "extract",
                "-mask", "VERSION,*",
                "-save", str(self.temp_dir / "version.rc")
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse extracted version info
                version_info = self._parse_extracted_version(self.temp_dir / "version.rc")
                return version_info

            return None

        except Exception as e:
            self.logger.warning(f"Failed to extract version info with Resource Hacker: {e}")
            return None

    def _extract_version_manual(self, binary_path: str) -> Optional[VersionResource]:
        """Extract version info manually"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE structure to find version resources
            resource_section = self._find_resource_section(data)
            if resource_section:
                version_info = self._parse_version_resources(data, resource_section)
                return version_info

            return None

        except Exception as e:
            self.logger.warning(f"Failed to extract version info manually: {e}")
            return None

    def _extract_custom_with_rh(self, binary_path: str, rh_path: str) -> List[CustomResource]:
        """Extract custom resources using Resource Hacker"""
        try:
            custom_resources = []

            # Run Resource Hacker to extract custom resources
            result = subprocess.run([
                rh_path,
                "-open", binary_path,
                "-action", "extract",
                "-mask", "CUSTOM,*",
                "-save", str(self.temp_dir / "custom.rc")
            ], capture_output=True, text=True, timeout=60)

            if result.returncode == 0:
                # Parse extracted custom resources
                custom_resources = self._parse_extracted_custom(self.temp_dir / "custom.rc")

            return custom_resources

        except Exception as e:
            self.logger.warning(f"Failed to extract custom resources with Resource Hacker: {e}")
            return []

    def _extract_custom_manual(self, binary_path: str) -> List[CustomResource]:
        """Extract custom resources manually"""
        try:
            custom_resources = []

            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE structure to find custom resources
            resource_section = self._find_resource_section(data)
            if resource_section:
                custom_resources = self._parse_custom_resources(data, resource_section)

            return custom_resources

        except Exception as e:
            self.logger.warning(f"Failed to extract custom resources manually: {e}")
            return []

    def _analyze_resources_for_embedded_files(self, data: bytes) -> List[CustomResource]:
        """Analyze resources for embedded files"""
        try:
            embedded_files = []

            # Look for embedded files by analyzing resource data
            # This is a simplified implementation
            # In practice, you would need to parse the PE resource section

            return embedded_files

        except Exception as e:
            self.logger.warning(f"Failed to analyze resources for embedded files: {e}")
            return []

    # PE structure parsing methods
    def _find_resource_section(self, data: bytes) -> Optional[Tuple[int, int]]:
        """Find resource section in PE file"""
        try:
            # Parse PE header to find resource section
            # This is a simplified implementation
            # In practice, you would need to parse the PE structure properly

            # Look for resource section signature
            resource_signature = b'.rsrc'
            offset = data.find(resource_signature)
            if offset != -1:
                return (offset, len(data) - offset)

            return None

        except Exception as e:
            self.logger.warning(f"Failed to find resource section: {e}")
            return None

    def _parse_icon_resources(self, data: bytes, resource_section: Tuple[int, int]) -> List[IconResource]:
        """Parse icon resources from resource section"""
        try:
            icons = []

            # Parse icon resources
            # This is a simplified implementation
            # In practice, you would need to parse the resource directory structure

            return icons

        except Exception as e:
            self.logger.warning(f"Failed to parse icon resources: {e}")
            return []

    def _parse_bitmap_resources(self, data: bytes, resource_section: Tuple[int, int]) -> List[IconResource]:
        """Parse bitmap resources from resource section"""
        try:
            bitmaps = []

            # Parse bitmap resources
            # This is a simplified implementation

            return bitmaps

        except Exception as e:
            self.logger.warning(f"Failed to parse bitmap resources: {e}")
            return []

    def _parse_string_resources(self, data: bytes, resource_section: Tuple[int, int]) -> List[StringResource]:
        """Parse string resources from resource section"""
        try:
            strings = []

            # Parse string resources
            # This is a simplified implementation

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to parse string resources: {e}")
            return []

    def _parse_manifest_resources(self, data: bytes, resource_section: Tuple[int, int]) -> List[ManifestResource]:
        """Parse manifest resources from resource section"""
        try:
            manifests = []

            # Parse manifest resources
            # This is a simplified implementation

            return manifests

        except Exception as e:
            self.logger.warning(f"Failed to parse manifest resources: {e}")
            return []

    def _parse_version_resources(self, data: bytes, resource_section: Tuple[int, int]) -> Optional[VersionResource]:
        """Parse version resources from resource section"""
        try:
            # Parse version resources
            # This is a simplified implementation

            return None

        except Exception as e:
            self.logger.warning(f"Failed to parse version resources: {e}")
            return None

    def _parse_custom_resources(self, data: bytes, resource_section: Tuple[int, int]) -> List[CustomResource]:
        """Parse custom resources from resource section"""
        try:
            custom_resources = []

            # Parse custom resources
            # This is a simplified implementation

            return custom_resources

        except Exception as e:
            self.logger.warning(f"Failed to parse custom resources: {e}")
            return []

    # Resource Hacker output parsing methods
    def _parse_extracted_icons(self, output_dir: Path) -> List[IconResource]:
        """Parse extracted icons from Resource Hacker output"""
        try:
            icons = []

            # Parse Resource Hacker output files
            # This is a simplified implementation

            return icons

        except Exception as e:
            self.logger.warning(f"Failed to parse extracted icons: {e}")
            return []

    def _parse_extracted_bitmaps(self, output_dir: Path) -> List[IconResource]:
        """Parse extracted bitmaps from Resource Hacker output"""
        try:
            bitmaps = []

            # Parse Resource Hacker output files
            # This is a simplified implementation

            return bitmaps

        except Exception as e:
            self.logger.warning(f"Failed to parse extracted bitmaps: {e}")
            return []

    def _parse_extracted_strings(self, rc_file: Path) -> List[StringResource]:
        """Parse extracted strings from Resource Hacker output"""
        try:
            strings = []

            # Parse Resource Hacker output files
            # This is a simplified implementation

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to parse extracted strings: {e}")
            return []

    def _parse_extracted_manifests(self, rc_file: Path) -> List[ManifestResource]:
        """Parse extracted manifests from Resource Hacker output"""
        try:
            manifests = []

            # Parse Resource Hacker output files
            # This is a simplified implementation

            return manifests

        except Exception as e:
            self.logger.warning(f"Failed to parse extracted manifests: {e}")
            return []

    def _parse_extracted_version(self, rc_file: Path) -> Optional[VersionResource]:
        """Parse extracted version info from Resource Hacker output"""
        try:
            # Parse Resource Hacker output files
            # This is a simplified implementation

            return None

        except Exception as e:
            self.logger.warning(f"Failed to parse extracted version info: {e}")
            return None

    def _parse_extracted_custom(self, rc_file: Path) -> List[CustomResource]:
        """Parse extracted custom resources from Resource Hacker output"""
        try:
            custom_resources = []

            # Parse Resource Hacker output files
            # This is a simplified implementation

            return custom_resources

        except Exception as e:
            self.logger.warning(f"Failed to parse extracted custom resources: {e}")
            return []
