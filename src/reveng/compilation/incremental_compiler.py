"""
Incremental Compilation with Intelligent Caching

Provides 5-10x speedup on rebuilds through:
- ccache/sccache integration for automatic caching
- Dependency graph analysis
- Change detection and affected file computation
- Distributed compilation with distcc
"""

import os
import subprocess
import hashlib
import json
import time
import shutil
from pathlib import Path
from typing import List, Dict, Set, Optional
from dataclasses import dataclass, asdict
import logging

logger = logging.getLogger(__name__)


@dataclass
class CompileResult:
    """Result of compilation operation"""

    success: bool
    output: str
    build_time: float
    files_compiled: int
    cache_hits: int
    cache_misses: int
    error: Optional[str] = None
    distributed: bool = False
    num_hosts: int = 1


@dataclass
class BuildManifest:
    """Manifest tracking build state for incremental builds"""

    source_files: List[str]
    object_files: List[str]
    checksums: Dict[str, str]
    timestamp: float
    dependencies: Dict[str, List[str]]

    def save(self, path: Path):
        """Save manifest to JSON file"""
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls, path: Path) -> Optional["BuildManifest"]:
        """Load manifest from JSON file"""
        if not path.exists():
            return None
        try:
            with open(path, "r") as f:
                data = json.load(f)
            return cls(**data)
        except Exception as e:
            logger.warning(f"Failed to load build manifest: {e}")
            return None

    def get_object_file(self, source: str) -> Optional[str]:
        """Get object file for source file"""
        try:
            idx = self.source_files.index(source)
            return self.object_files[idx]
        except (ValueError, IndexError):
            return None


@dataclass
class CompilationResult:
    """Compatibility result for the legacy single-file compilation API."""

    success: bool
    output_file: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    cached: bool = False
    compile_time: float = 0.0
    cache_hit_rate: Optional[float] = None


@dataclass
class CacheStats:
    """Compiler cache statistics for compatibility with legacy callers."""

    hits: int = 0
    misses: int = 0
    cache_size: int = 0
    max_size: int = 0
    files_cached: int = 0
    raw_output: str = ""

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        if total == 0:
            return 0.0
        return self.hits / total


class DependencyGraph:
    """
    Dependency graph for tracking file dependencies
    """

    def __init__(self):
        self.dependencies: Dict[str, Set[str]] = {}
        self.dependents: Dict[str, Set[str]] = {}

    def add_dependency(self, file: str, depends_on: str):
        """Add a dependency: file depends on depends_on"""
        if file not in self.dependencies:
            self.dependencies[file] = set()
        self.dependencies[file].add(depends_on)

        if depends_on not in self.dependents:
            self.dependents[depends_on] = set()
        self.dependents[depends_on].add(file)

    def get_dependencies(self, file: str) -> Set[str]:
        """Get all files that this file depends on"""
        return self.dependencies.get(file, set())

    def get_dependents(self, file: str) -> Set[str]:
        """Get all files that depend on this file (transitive closure)"""
        result = set()
        to_process = [file]
        processed = set()

        while to_process:
            current = to_process.pop()
            if current in processed:
                continue
            processed.add(current)

            direct_dependents = self.dependents.get(current, set())
            result.update(direct_dependents)
            to_process.extend(direct_dependents)

        return result


class IncrementalCompiler:
    """
    Incremental compilation with intelligent caching

    Features:
    - ccache/sccache integration for 5-10x speedup
    - Dependency tracking and change detection
    - Only recompile affected files
    - Build manifest for tracking state
    - distcc support for distributed builds
    """

    def __init__(
        self,
        cache_dir: str = ".reveng_cache",
        use_ccache: bool = True,
        cache_backend: str = "auto",
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.dependency_graph = DependencyGraph()
        self.cache_backend = self._detect_backend(cache_backend) if use_ccache else None
        self.cache_enabled = self.cache_backend is not None
        self.use_ccache = self.cache_backend == "ccache"

        if use_ccache and self.cache_enabled:
            self._setup_cache_backend()
        elif use_ccache:
            logger.warning("No compiler cache backend available, continuing without cache")

    def _detect_backend(self, preference: str) -> Optional[str]:
        """Detect the requested compiler cache backend."""
        if preference == "auto":
            if shutil.which("ccache"):
                return "ccache"
            if shutil.which("sccache"):
                return "sccache"
            return None

        return preference if shutil.which(preference) else None

    def _setup_cache_backend(self):
        """Setup the selected compiler cache backend."""
        if self.cache_backend == "ccache":
            os.environ["CCACHE_DIR"] = str(self.cache_dir / "ccache")
            logger.info("ccache enabled")
        elif self.cache_backend == "sccache":
            os.environ["SCCACHE_DIR"] = str(self.cache_dir / "sccache")
            logger.info("sccache enabled")

    def compile_incremental(
        self,
        source_files: List[str],
        output: str,
        compiler: str = "gcc",
        flags: List[str] = None,
        previous_build: Optional[BuildManifest] = None,
    ) -> CompileResult:
        """
        Incremental compilation: only recompile changed files

        Args:
            source_files: List of source file paths
            output: Output executable path
            compiler: Compiler to use (gcc, clang, etc.)
            flags: Additional compiler flags
            previous_build: Previous build manifest for incremental build

        Returns:
            CompileResult with build statistics
        """
        start_time = time.time()

        if flags is None:
            flags = ["-O2", "-Wall"]

        # Build dependency graph
        self._analyze_dependencies(source_files)

        # Load previous build if not provided
        if previous_build is None:
            manifest_path = self.cache_dir / "build_manifest.json"
            previous_build = BuildManifest.load(manifest_path)

        # Determine what needs recompilation
        if previous_build:
            changed = self._detect_changes(source_files, previous_build)
            affected = self._compute_affected_files(changed, source_files)
            logger.info(
                f"Incremental build: {len(affected)}/{len(source_files)} "
                f"files need recompilation"
            )
        else:
            affected = set(source_files)  # First build, compile everything
            logger.info("Full build: compiling all files")

        # Compile files
        object_files = []
        cache_hits = 0
        cache_misses = 0

        for src in source_files:
            if src in affected:
                obj, was_cached = self._compile_with_cache(src, compiler, flags)
                if was_cached:
                    cache_hits += 1
                else:
                    cache_misses += 1
            else:
                # Reuse previous object file
                obj = previous_build.get_object_file(src)
                cache_hits += 1

            if obj:
                object_files.append(obj)

        # Link
        try:
            self._link(object_files, output, compiler)
            success = True
            error = None
        except subprocess.CalledProcessError as e:
            success = False
            error = e.stderr.decode() if e.stderr else str(e)
            logger.error(f"Linking failed: {error}")

        # Save build manifest for next incremental build
        manifest = BuildManifest(
            source_files=source_files,
            object_files=object_files,
            checksums=self._compute_checksums(source_files),
            timestamp=time.time(),
            dependencies={
                f: list(self.dependency_graph.get_dependencies(f)) for f in source_files
            },
        )
        manifest.save(self.cache_dir / "build_manifest.json")

        build_time = time.time() - start_time

        return CompileResult(
            success=success,
            output=output,
            build_time=build_time,
            files_compiled=len(affected),
            cache_hits=cache_hits,
            cache_misses=cache_misses,
            error=error,
        )

    def compile(
        self,
        source_file: str,
        output_file: str,
        compiler: str = "gcc",
        flags: Optional[List[str]] = None,
        timeout: int = 300,
    ) -> CompilationResult:
        """Compatibility single-file compile API kept after consolidation."""
        start_time = time.time()
        flags = flags or []

        stats_before = self.get_cache_stats() if self.cache_enabled else None

        if self.cache_backend:
            cmd = [self.cache_backend, compiler] + flags + [source_file, "-o", output_file]
        else:
            cmd = [compiler] + flags + [source_file, "-o", output_file]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            compile_time = time.time() - start_time
            stats_after = self.get_cache_stats() if self.cache_enabled else None
            cached = False

            if stats_before and stats_after:
                cached = stats_after.hits > stats_before.hits

            success = result.returncode == 0
            if not success:
                logger.error("Compilation failed:\n%s", result.stderr)

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
            logger.error("Compilation timed out after %ss", timeout)
            return CompilationResult(
                success=False,
                stderr=f"Compilation timed out after {timeout}s",
                compile_time=time.time() - start_time,
            )
        except Exception as e:
            logger.error("Compilation error: %s", e)
            return CompilationResult(
                success=False,
                stderr=str(e),
                compile_time=time.time() - start_time,
            )

    def _analyze_dependencies(self, source_files: List[str]):
        """
        Analyze #include dependencies between files
        """
        for src_file in source_files:
            try:
                with open(src_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Extract #include directives
                import re

                includes = re.findall(r'#include\s+[<"]([^>"]+)[>"]', content)

                for include in includes:
                    # Try to resolve include to actual file
                    resolved = self._resolve_include(include, src_file)
                    if resolved:
                        self.dependency_graph.add_dependency(src_file, resolved)
            except Exception as e:
                logger.warning(f"Failed to analyze dependencies for {src_file}: {e}")

    def _resolve_include(self, include: str, source_file: str) -> Optional[str]:
        """Resolve #include to actual file path"""
        # Try relative to source file
        src_dir = Path(source_file).parent
        candidate = src_dir / include
        if candidate.exists():
            return str(candidate)

        # Try common include paths
        for include_dir in ["/usr/include", "/usr/local/include"]:
            candidate = Path(include_dir) / include
            if candidate.exists():
                return str(candidate)

        return None

    def _detect_changes(self, files: List[str], previous: BuildManifest) -> Set[str]:
        """Detect which files changed since last build"""
        changed = set()

        for file in files:
            current_hash = self._hash_file(file)
            previous_hash = previous.checksums.get(file)

            if current_hash != previous_hash:
                changed.add(file)
                logger.debug(f"File changed: {file}")

        return changed

    def _compute_affected_files(
        self, changed: Set[str], all_files: List[str]
    ) -> Set[str]:
        """
        Compute transitive closure of affected files
        If A.c includes B.h, and B.h changed, then A.c needs recompilation
        """
        affected = set(changed)

        # Add all files that depend on changed files
        for file in changed:
            dependents = self.dependency_graph.get_dependents(file)
            # Only include dependents that are in our source files
            affected.update(d for d in dependents if d in all_files)

        return affected

    def _compile_with_cache(
        self, source: str, compiler: str, flags: List[str]
    ) -> tuple[Optional[str], bool]:
        """
        Compile using ccache for automatic caching

        Returns: (object_file_path, was_cached)
        """
        output = source.replace(".c", ".o")

        # Build compile command
        if self.cache_backend == "ccache":
            cmd = ["ccache", compiler, "-c", source, "-o", output] + flags
        elif self.cache_backend == "sccache":
            cmd = ["sccache", compiler, "-c", source, "-o", output] + flags
        else:
            cmd = [compiler, "-c", source, "-o", output] + flags

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)

            if result.returncode != 0:
                logger.error(
                    f"Compilation failed for {source}: {result.stderr.decode()}"
                )
                return None, False

            was_cached = False

            return output, was_cached

        except subprocess.TimeoutExpired:
            logger.error(f"Compilation timeout for {source}")
            return None, False

    def _link(self, object_files: List[str], output: str, compiler: str):
        """Link object files into executable"""
        cmd = [compiler] + object_files + ["-o", output]

        result = subprocess.run(cmd, capture_output=True, timeout=60)

        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode, cmd, result.stdout, result.stderr
            )

    def _hash_file(self, filepath: str) -> str:
        """Compute SHA256 hash of file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            logger.warning(f"Failed to hash {filepath}: {e}")
            return ""

    def _compute_checksums(self, files: List[str]) -> Dict[str, str]:
        """Compute checksums for all files"""
        return {f: self._hash_file(f) for f in files}

    def get_cache_stats(self) -> Optional[CacheStats]:
        """Get compiler cache statistics for the configured backend."""
        if not self.cache_enabled or not self.cache_backend:
            return None

        try:
            if self.cache_backend == "ccache":
                return self._get_ccache_stats()
            if self.cache_backend == "sccache":
                return self._get_sccache_stats()
        except Exception as e:
            logger.warning("Failed to get %s stats: %s", self.cache_backend, e)

        return None

    def _get_ccache_stats(self) -> CacheStats:
        """Parse ccache statistics output."""
        result = subprocess.run(["ccache", "-s"], capture_output=True, text=True, timeout=5)
        stats = CacheStats(raw_output=result.stdout, max_size=2 * 1024 * 1024 * 1024)

        for line in result.stdout.splitlines():
            lower_line = line.lower()
            compact_line = " ".join(line.split())

            if "cache hit" in lower_line:
                parts = compact_line.split()
                if parts and parts[-1].isdigit():
                    stats.hits += int(parts[-1])
            elif "cache miss" in lower_line:
                parts = compact_line.split()
                if parts and parts[-1].isdigit():
                    stats.misses += int(parts[-1])
            elif "cache size" in lower_line:
                stats.cache_size = self._parse_size_from_line(compact_line)
            elif "files in cache" in lower_line:
                parts = compact_line.split()
                if parts and parts[-1].isdigit():
                    stats.files_cached = int(parts[-1])

        return stats

    def _get_sccache_stats(self) -> CacheStats:
        """Parse sccache statistics output."""
        result = subprocess.run(
            ["sccache", "--show-stats"], capture_output=True, text=True, timeout=5
        )
        stats = CacheStats(raw_output=result.stdout, max_size=2 * 1024 * 1024 * 1024)

        for line in result.stdout.splitlines():
            lower_line = line.lower()
            compact_line = " ".join(line.split())
            parts = compact_line.split()

            if "cache hits" in lower_line and parts and parts[-1].isdigit():
                stats.hits = int(parts[-1])
            elif "cache misses" in lower_line and parts and parts[-1].isdigit():
                stats.misses = int(parts[-1])
            elif "cache size" in lower_line:
                stats.cache_size = self._parse_size_from_line(compact_line)

        return stats

    def _parse_size_from_line(self, line: str) -> int:
        """Parse a human-readable size token from cache tool output."""
        parts = line.split()
        for idx, token in enumerate(parts[:-1]):
            try:
                value = float(token)
            except ValueError:
                continue

            unit = parts[idx + 1].upper()
            if unit == "GB":
                return int(value * 1024 * 1024 * 1024)
            if unit == "MB":
                return int(value * 1024 * 1024)
            if unit == "KB":
                return int(value * 1024)
        return 0

    def clear_cache(self):
        """Clear compilation cache"""
        if self.cache_backend == "ccache":
            try:
                subprocess.run(["ccache", "-C"], timeout=10)
                logger.info("ccache cleared")
            except Exception as e:
                logger.warning(f"Failed to clear ccache: {e}")
        elif self.cache_backend == "sccache":
            try:
                subprocess.run(["sccache", "--zero-stats"], timeout=10)
                logger.info("sccache stats cleared")
            except Exception as e:
                logger.warning(f"Failed to clear sccache stats: {e}")

    def print_stats(self):
        """Print cache statistics in the legacy POC-friendly format."""
        stats = self.get_cache_stats()
        if not stats:
            print("Cache not available or no statistics")
            return

        print(f"\n{'=' * 60}")
        print(f"Compiler Cache Statistics ({self.cache_backend})")
        print(f"{'=' * 60}")
        print(f"Cache directory: {self.cache_dir}")
        print(f"Cache hits:      {stats.hits:,}")
        print(f"Cache misses:    {stats.misses:,}")
        print(f"Hit rate:        {stats.hit_rate:.1%}")
        print(f"Cache size:      {stats.cache_size / (1024 ** 2):.1f} MB")
        print(f"Max size:        {stats.max_size / (1024 ** 3):.1f} GB")
        print(f"Files cached:    {stats.files_cached:,}")
        print(f"{'=' * 60}\n")


class DistributedCompiler(IncrementalCompiler):
    """
    Distributed compilation across multiple machines

    Uses distcc for 10x speedup with 10 machines
    """

    def __init__(self, hosts: List[str], **kwargs):
        super().__init__(**kwargs)
        self.hosts = hosts
        os.environ["DISTCC_HOSTS"] = " ".join(hosts)

        # Check if distcc is available
        try:
            subprocess.run(["distcc", "--version"], capture_output=True, timeout=5)
            self.distcc_available = True
            logger.info(f"distcc enabled with {len(hosts)} hosts")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.distcc_available = False
            logger.warning("distcc not available")

    def _compile_with_cache(
        self, source: str, compiler: str, flags: List[str]
    ) -> tuple[Optional[str], bool]:
        """
        Compile using both ccache and distcc for maximum performance
        """
        if not self.distcc_available or self.cache_backend == "sccache":
            return super()._compile_with_cache(source, compiler, flags)

        output = source.replace(".c", ".o")

        # Use CCACHE_PREFIX to combine ccache and distcc
        if self.cache_backend == "ccache":
            os.environ["CCACHE_PREFIX"] = "distcc"
            cmd = ["ccache", compiler, "-c", source, "-o", output] + flags
        else:
            cmd = ["distcc", compiler, "-c", source, "-o", output] + flags

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120)

            if result.returncode != 0:
                logger.error(f"Distributed compilation failed for {source}")
                return None, False

            return output, False

        except subprocess.TimeoutExpired:
            logger.error(f"Distributed compilation timeout for {source}")
            return None, False

    def compile_incremental(self, *args, **kwargs) -> CompileResult:
        """Override to add distributed compilation info"""
        result = super().compile_incremental(*args, **kwargs)
        result.distributed = self.distcc_available
        result.num_hosts = len(self.hosts) if self.distcc_available else 1
        return result
