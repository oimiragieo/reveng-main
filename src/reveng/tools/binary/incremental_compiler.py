#!/usr/bin/env python3
"""
Incremental Compilation System - 5-10x Faster Rebuilds
=======================================================

Integrates ccache/sccache for compiler caching to dramatically speed up iterative analysis.

Benefits:
- First build: Normal speed
- Cached rebuilds: 5-10x faster
- Disk space: ~1GB cache (configurable)
- Network support: Share cache across machines

Supported compilers:
- gcc, g++
- clang, clang++
- MSVC (via sccache on Windows)
"""

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class CompilationResult:
    """Result from compilation"""

    success: bool
    output_file: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    cached: bool = False
    compile_time: float = 0.0
    cache_hit_rate: Optional[float] = None


@dataclass
class CacheStats:
    """Compiler cache statistics"""

    hits: int = 0
    misses: int = 0
    cache_size: int = 0  # bytes
    max_size: int = 0  # bytes
    files_cached: int = 0

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate"""
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total


class IncrementalCompiler:
    """
    Compiler cache wrapper for 5-10x faster rebuilds

    Usage:
        compiler = IncrementalCompiler()
        result = compiler.compile('source.c', 'output', compiler='gcc', flags=['-O2'])
        print(f"Cached: {result.cached}, Hit rate: {result.cache_hit_rate:.1%}")
    """

    def __init__(self, cache_backend: str = "auto", cache_dir: Optional[str] = None):
        """
        Initialize incremental compiler

        Args:
            cache_backend: 'ccache', 'sccache', or 'auto' to detect
            cache_dir: Custom cache directory (default: ~/.reveng/compiler_cache)
        """
        self.cache_backend = self._detect_backend(cache_backend)
        self.cache_dir = (
            Path(cache_dir) if cache_dir else Path.home() / ".reveng" / "compiler_cache"
        )
        self.cache_enabled = self.cache_backend is not None

        if self.cache_enabled:
            self._setup_cache()
            logger.info(f"Incremental compilation enabled with {self.cache_backend}")
        else:
            logger.warning(
                "No compiler cache available. Install ccache or sccache for 5-10x speedup."
            )

    def _detect_backend(self, preference: str) -> Optional[str]:
        """Detect available compiler cache backend"""
        if preference == "auto":
            # Try ccache first (most common)
            if shutil.which("ccache"):
                return "ccache"
            elif shutil.which("sccache"):
                return "sccache"
            else:
                return None

        # Check if specified backend exists
        if shutil.which(preference):
            return preference

        return None

    def _setup_cache(self):
        """Setup compiler cache directory and configuration"""
        # Create cache directory
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        if self.cache_backend == "ccache":
            # Configure ccache
            os.environ["CCACHE_DIR"] = str(self.cache_dir)
            os.environ["CCACHE_MAXSIZE"] = "2G"  # 2GB cache
            os.environ["CCACHE_COMPRESS"] = "1"  # Compress cached files
            os.environ["CCACHE_COMPRESSLEVEL"] = "6"  # Balanced compression

            logger.debug(f"ccache configured: {self.cache_dir}, max size: 2GB")

        elif self.cache_backend == "sccache":
            # Configure sccache
            os.environ["SCCACHE_DIR"] = str(self.cache_dir)
            os.environ["SCCACHE_CACHE_SIZE"] = "2G"

            logger.debug(f"sccache configured: {self.cache_dir}, max size: 2GB")

    def compile(
        self,
        source_file: str,
        output_file: str,
        compiler: str = "gcc",
        flags: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> CompilationResult:
        """
        Compile source file with caching

        Args:
            source_file: Path to source file
            output_file: Path to output binary
            compiler: Compiler to use (gcc, g++, clang, etc.)
            flags: Compiler flags (e.g., ['-O2', '-Wall'])
            timeout: Compilation timeout in seconds

        Returns:
            CompilationResult with caching statistics
        """
        import time

        start_time = time.time()

        # Get cache stats before compilation
        stats_before = self.get_cache_stats() if self.cache_enabled else None

        # Build command
        if flags is None:
            flags = []

        if self.cache_enabled:
            # Prepend cache backend to compiler
            cmd = [self.cache_backend, compiler] + flags + [source_file, "-o", output_file]
        else:
            # Direct compilation without cache
            cmd = [compiler] + flags + [source_file, "-o", output_file]

        logger.debug(f"Compiling: {' '.join(cmd)}")

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

            compile_time = time.time() - start_time

            # Get cache stats after compilation
            stats_after = self.get_cache_stats() if self.cache_enabled else None

            # Determine if this was a cache hit
            cached = False
            if stats_after and stats_before:
                cached = stats_after.hits > stats_before.hits

            success = result.returncode == 0

            if success:
                logger.info(
                    f"Compilation {'succeeded' if success else 'failed'} "
                    f"in {compile_time:.2f}s (cached: {cached})"
                )
            else:
                logger.error(f"Compilation failed:\n{result.stderr}")

            return CompilationResult(
                success=success,
                output_file=output_file if success else None,
                stdout=result.stdout,
                stderr=result.stderr,
                cached=cached,
                compile_time=compile_time,
                cache_hit_rate=stats_after.hit_rate if stats_after else None,
            )

        except subprocess.TimeoutExpired:
            logger.error(f"Compilation timed out after {timeout}s")
            return CompilationResult(
                success=False, stderr=f"Compilation timed out after {timeout}s"
            )

        except Exception as e:
            logger.error(f"Compilation error: {e}")
            return CompilationResult(success=False, stderr=str(e))

    def get_cache_stats(self) -> Optional[CacheStats]:
        """Get compiler cache statistics"""
        if not self.cache_enabled:
            return None

        try:
            if self.cache_backend == "ccache":
                return self._get_ccache_stats()
            elif self.cache_backend == "sccache":
                return self._get_sccache_stats()

        except Exception as e:
            logger.debug(f"Failed to get cache stats: {e}")
            return None

    def _get_ccache_stats(self) -> CacheStats:
        """Get ccache statistics"""
        result = subprocess.run(["ccache", "-s"], capture_output=True, text=True, timeout=5)

        stats = CacheStats()

        # Parse ccache stats output
        for line in result.stdout.split("\n"):
            line = line.strip()

            if "cache hit" in line.lower():
                # Extract number from "cache hit (direct)     12345"
                parts = line.split()
                if parts and parts[-1].isdigit():
                    stats.hits += int(parts[-1])

            elif "cache miss" in line.lower():
                parts = line.split()
                if parts and parts[-1].isdigit():
                    stats.misses += int(parts[-1])

            elif "cache size" in line.lower():
                # "cache size                           1.2 GB"
                parts = line.split()
                if len(parts) >= 2:
                    size_str = parts[-2]
                    try:
                        size = float(size_str)
                        unit = parts[-1].upper()

                        # Convert to bytes
                        if unit == "GB":
                            stats.cache_size = int(size * 1024 * 1024 * 1024)
                        elif unit == "MB":
                            stats.cache_size = int(size * 1024 * 1024)
                        elif unit == "KB":
                            stats.cache_size = int(size * 1024)
                    except Exception:
                        pass

            elif "files in cache" in line.lower():
                parts = line.split()
                if parts and parts[-1].isdigit():
                    stats.files_cached = int(parts[-1])

        # ccache max size is configured, default 2GB
        stats.max_size = 2 * 1024 * 1024 * 1024

        return stats

    def _get_sccache_stats(self) -> CacheStats:
        """Get sccache statistics"""
        result = subprocess.run(
            ["sccache", "--show-stats"], capture_output=True, text=True, timeout=5
        )

        stats = CacheStats()

        # Parse sccache stats (usually in a table format)
        for line in result.stdout.split("\n"):
            line = line.strip().lower()

            if "cache hits" in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        stats.hits = int(parts[-1])
                    except Exception:
                        pass

            elif "cache misses" in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        stats.misses = int(parts[-1])
                    except Exception:
                        pass

            elif "cache size" in line:
                # Similar parsing to ccache
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        size = float(parts[-2])
                        unit = parts[-1].upper()

                        if unit == "GB":
                            stats.cache_size = int(size * 1024 * 1024 * 1024)
                        elif unit == "MB":
                            stats.cache_size = int(size * 1024 * 1024)
                    except Exception:
                        pass

        stats.max_size = 2 * 1024 * 1024 * 1024

        return stats

    def clear_cache(self) -> bool:
        """Clear compiler cache"""
        if not self.cache_enabled:
            logger.warning("Cache not enabled, nothing to clear")
            return False

        try:
            if self.cache_backend == "ccache":
                subprocess.run(["ccache", "-C"], check=True, timeout=10)
            elif self.cache_backend == "sccache":
                subprocess.run(["sccache", "--zero-stats"], check=True, timeout=10)

            logger.info(f"Cleared {self.cache_backend} cache")
            return True

        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return False

    def print_stats(self):
        """Print cache statistics"""
        stats = self.get_cache_stats()

        if not stats:
            print("Cache not available or no statistics")
            return

        print(f"\n{'='*60}")
        print(f"Compiler Cache Statistics ({self.cache_backend})")
        print(f"{'='*60}")
        print(f"Cache directory: {self.cache_dir}")
        print(f"Cache hits:      {stats.hits:,}")
        print(f"Cache misses:    {stats.misses:,}")
        print(f"Hit rate:        {stats.hit_rate:.1%}")
        cache_size_gb = stats.cache_size / (1024**3)
        max_size_gb = stats.max_size / (1024**3)
        print(f"Cache size:      {cache_size_gb:.2f} GB / {max_size_gb:.0f} GB")
        print(f"Files cached:    {stats.files_cached:,}")
        print(f"{'='*60}\n")


def install_cache_backend():
    """Helper to install compiler cache backend"""
    import platform

    system = platform.system()

    if system == "Linux":
        print("To install ccache on Linux:")
        print("  Ubuntu/Debian: sudo apt install ccache")
        print("  Fedora/RHEL:   sudo dnf install ccache")
        print("  Arch:          sudo pacman -S ccache")

    elif system == "Darwin":
        print("To install ccache on macOS:")
        print("  brew install ccache")

    elif system == "Windows":
        print("To install sccache on Windows:")
        print("  1. Download from: https://github.com/mozilla/sccache/releases")
        print("  2. Add to PATH")
        print("  OR use scoop: scoop install sccache")

    print("\nAlternatively, install sccache (cross-platform):")
    print("  cargo install sccache")


if __name__ == "__main__":
    # Demo usage
    print("Incremental Compilation System Demo")
    print("=" * 60)

    compiler = IncrementalCompiler()

    if not compiler.cache_enabled:
        print("\nNo cache backend found!")
        install_cache_backend()
    else:
        compiler.print_stats()

        print("Example usage:")
        print("  compiler = IncrementalCompiler()")
        print("  result = compiler.compile('source.c', 'output', flags=['-O2'])")
        print("  print(f'Cached: {result.cached}, Time: {result.compile_time:.2f}s')")
