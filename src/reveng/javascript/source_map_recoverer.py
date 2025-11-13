"""
Source Map Recovery

Recovers original source code from webpack/browserify bundles
when source maps (.map files) are available.

This is the "perfect" recovery method - 100% accurate when maps exist.

Based on research:
- unwebpack-sourcemap (GitHub: rarecoil/unwebpack-sourcemap)
- Most production sites accidentally ship source maps
"""

import os
import re
import json
import logging
import requests
from typing import List, Dict, Optional
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class SourceMapResult:
    """Result from source map recovery"""

    success: bool
    sources: Dict[str, str]  # filename -> source code
    error: Optional[str] = None


class SourceMapRecoverer:
    """
    Recover original source from webpack/browserify source maps

    Security Note:
    Many production websites accidentally ship .map files,
    which completely exposes the original source code.

    This is equivalent to shipping your source alongside the "binary".
    """

    def find_sourcemaps(self, url_or_file: str) -> List[str]:
        """
        Find source map files

        Args:
            url_or_file: URL to JavaScript file or local file path

        Returns:
            List of source map URLs/paths
        """
        maps = []

        if url_or_file.startswith("http"):
            # URL - check for .map file
            maps = self._find_sourcemaps_url(url_or_file)
        else:
            # Local file
            maps = self._find_sourcemaps_local(url_or_file)

        logger.info(f"Found {len(maps)} source map(s)")
        return maps

    def _find_sourcemaps_url(self, url: str) -> List[str]:
        """Find source maps from URL"""
        maps = []

        try:
            # Download JS file
            response = requests.get(url, timeout=10)
            content = response.text

            # Check for sourceMappingURL comment
            # //# sourceMappingURL=file.js.map
            match = re.search(r"//[@#]\s*sourceMappingURL=(.+)", content)

            if match:
                map_url = match.group(1).strip()

                # Resolve relative URL
                if not map_url.startswith("http"):
                    map_url = urljoin(url, map_url)

                maps.append(map_url)

            # Also try .map extension directly
            map_url_direct = url + ".map"
            try:
                response = requests.head(map_url_direct, timeout=5)
                if response.status_code == 200:
                    if map_url_direct not in maps:
                        maps.append(map_url_direct)
            except:
                pass

        except Exception as e:
            logger.error(f"Error finding source maps from URL: {e}")

        return maps

    def _find_sourcemaps_local(self, filepath: str) -> List[str]:
        """Find source maps from local file"""
        maps = []

        try:
            with open(filepath, "r") as f:
                content = f.read()

            # Check for sourceMappingURL
            match = re.search(r"//[@#]\s*sourceMappingURL=(.+)", content)

            if match:
                map_file = match.group(1).strip()

                # Resolve relative path
                base_dir = Path(filepath).parent
                map_path = base_dir / map_file

                if map_path.exists():
                    maps.append(str(map_path))

            # Also try .map extension
            map_path_direct = Path(filepath).with_suffix(filepath + ".map")
            if map_path_direct.exists():
                if str(map_path_direct) not in maps:
                    maps.append(str(map_path_direct))

        except Exception as e:
            logger.error(f"Error finding source maps from file: {e}")

        return maps

    def recover(self, sourcemap_url_or_file: str) -> SourceMapResult:
        """
        Recover original sources from source map

        Args:
            sourcemap_url_or_file: URL or file path to .map file

        Returns:
            SourceMapResult with recovered source files
        """
        logger.info(f"Recovering sources from: {sourcemap_url_or_file}")

        try:
            # Load source map
            if sourcemap_url_or_file.startswith("http"):
                response = requests.get(sourcemap_url_or_file, timeout=10)
                sourcemap = response.json()
            else:
                with open(sourcemap_url_or_file, "r") as f:
                    sourcemap = json.load(f)

            # Extract sources
            sources = {}

            # Source map format:
            # {
            #   "version": 3,
            #   "sources": ["file1.js", "file2.js", ...],
            #   "sourcesContent": ["content1", "content2", ...],
            #   ...
            # }

            source_files = sourcemap.get("sources", [])
            source_contents = sourcemap.get("sourcesContent", [])

            if len(source_files) != len(source_contents):
                logger.warning(
                    f"Source files ({len(source_files)}) and contents "
                    f"({len(source_contents)}) count mismatch"
                )

            for i, filename in enumerate(source_files):
                if i < len(source_contents) and source_contents[i]:
                    # Clean up filename (remove webpack:// prefix, etc.)
                    clean_name = self._clean_filename(filename)
                    sources[clean_name] = source_contents[i]

            logger.info(f"Recovered {len(sources)} source files")

            return SourceMapResult(success=True, sources=sources)

        except Exception as e:
            logger.error(f"Source map recovery failed: {e}")
            return SourceMapResult(success=False, sources={}, error=str(e))

    def _clean_filename(self, filename: str) -> str:
        """Clean up source map filename"""
        # Remove webpack:// prefix
        filename = re.sub(r"^webpack:///?", "", filename)

        # Remove leading ./
        filename = re.sub(r"^\./", "", filename)

        # Convert to valid path
        filename = filename.replace("..", "_")

        return filename

    def save_directory(self, sources: Dict[str, str], output_dir: str) -> None:
        """
        Save recovered sources to directory structure

        Args:
            sources: Dict of filename -> source code
            output_dir: Output directory
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        for filename, content in sources.items():
            # Create subdirectories if needed
            file_path = output_path / filename
            file_path.parent.mkdir(parents=True, exist_ok=True)

            # Write source
            with open(file_path, "w") as f:
                f.write(content)

        logger.info(f"Saved {len(sources)} files to {output_dir}")

    def scan_webapp(self, base_url: str) -> List[str]:
        """
        Scan web application for exposed source maps

        This is a security audit feature - finds accidentally shipped maps.

        Args:
            base_url: Base URL of web app (e.g., https://example.com)

        Returns:
            List of found source map URLs
        """
        logger.info(f"Scanning {base_url} for exposed source maps...")

        maps = []

        try:
            # Download main HTML
            response = requests.get(base_url, timeout=10)
            html = response.text

            # Find all .js script tags
            js_urls = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', html)

            # Also find .js files directly linked
            js_urls += re.findall(r'href=["\']([^"\']+\.js)["\']', html)

            # Resolve relative URLs
            js_urls = [urljoin(base_url, url) for url in js_urls]

            # Check each JS file for source maps
            for js_url in js_urls:
                found = self._find_sourcemaps_url(js_url)
                maps.extend(found)

            logger.info(f"Scan complete: found {len(maps)} source maps")

        except Exception as e:
            logger.error(f"Web app scan failed: {e}")

        return maps
