"""
Intelligent Caching System for JavaScript Deobfuscation

Caches deobfuscation results to avoid re-processing:
- Content-based hashing (SHA256)
- LRU cache with size limits
- Persistent disk cache
- Cache invalidation strategies
- Performance analytics

Dramatically improves performance for repeated analysis.
"""

import os
import json
import hashlib
import time
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from dataclasses import dataclass, asdict
from collections import OrderedDict

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    """A cache entry"""

    code_hash: str
    deobfuscated_code: str
    confidence: float
    obfuscation_types: list
    timestamp: float
    hit_count: int = 0
    processing_time: float = 0.0


class DeobfuscationCache:
    """
    LRU cache for deobfuscation results

    Features:
    - In-memory LRU cache for speed
    - Persistent disk cache for durability
    - Content-based hashing
    - Automatic cleanup of old entries
    - Cache hit rate tracking
    """

    def __init__(
        self,
        cache_dir: Optional[str] = None,
        max_memory_entries: int = 100,
        max_disk_size_mb: int = 500,
    ):
        """
        Initialize cache

        Args:
            cache_dir: Directory for persistent cache
            max_memory_entries: Max entries in memory
            max_disk_size_mb: Max disk cache size in MB
        """
        self.cache_dir = Path(cache_dir or os.path.expanduser("~/.reveng/js_cache"))
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        self.max_memory_entries = max_memory_entries
        self.max_disk_size_mb = max_disk_size_mb

        # In-memory LRU cache
        self.memory_cache: OrderedDict[str, CacheEntry] = OrderedDict()

        # Cache statistics
        self.stats = {"hits": 0, "misses": 0, "evictions": 0}

        logger.info(f"Cache initialized: {self.cache_dir}")

    def get(self, code: str) -> Optional[CacheEntry]:
        """
        Get cached result for code

        Args:
            code: JavaScript code

        Returns:
            CacheEntry if cached, None otherwise
        """
        code_hash = self._hash_code(code)

        # Check memory cache first
        if code_hash in self.memory_cache:
            entry = self.memory_cache[code_hash]
            entry.hit_count += 1

            # Move to end (most recently used)
            self.memory_cache.move_to_end(code_hash)

            self.stats["hits"] += 1
            logger.debug(f"Cache HIT (memory): {code_hash[:8]}...")
            return entry

        # Check disk cache
        entry = self._load_from_disk(code_hash)
        if entry:
            # Add to memory cache
            self._add_to_memory(code_hash, entry)

            self.stats["hits"] += 1
            logger.debug(f"Cache HIT (disk): {code_hash[:8]}...")
            return entry

        self.stats["misses"] += 1
        logger.debug(f"Cache MISS: {code_hash[:8]}...")
        return None

    def put(
        self,
        code: str,
        deobfuscated_code: str,
        confidence: float,
        obfuscation_types: list,
        processing_time: float,
    ) -> None:
        """
        Cache deobfuscation result

        Args:
            code: Original code
            deobfuscated_code: Deobfuscated result
            confidence: Confidence score
            obfuscation_types: Detected obfuscation types
            processing_time: Time taken to deobfuscate
        """
        code_hash = self._hash_code(code)

        entry = CacheEntry(
            code_hash=code_hash,
            deobfuscated_code=deobfuscated_code,
            confidence=confidence,
            obfuscation_types=obfuscation_types,
            timestamp=time.time(),
            processing_time=processing_time,
        )

        # Add to memory
        self._add_to_memory(code_hash, entry)

        # Save to disk
        self._save_to_disk(code_hash, entry)

        logger.debug(f"Cached result: {code_hash[:8]}...")

    def _hash_code(self, code: str) -> str:
        """Generate content hash"""
        return hashlib.sha256(code.encode()).hexdigest()

    def _add_to_memory(self, code_hash: str, entry: CacheEntry) -> None:
        """Add entry to memory cache with LRU eviction"""
        # Check if already exists
        if code_hash in self.memory_cache:
            self.memory_cache.move_to_end(code_hash)
            return

        # Add new entry
        self.memory_cache[code_hash] = entry

        # Evict oldest if over limit
        if len(self.memory_cache) > self.max_memory_entries:
            evicted = self.memory_cache.popitem(last=False)
            self.stats["evictions"] += 1
            logger.debug(f"Evicted from memory: {evicted[0][:8]}...")

    def _save_to_disk(self, code_hash: str, entry: CacheEntry) -> None:
        """Save entry to disk"""
        try:
            cache_file = self.cache_dir / f"{code_hash}.json"

            with open(cache_file, "w") as f:
                # Convert to dict, handle non-serializable types
                data = asdict(entry)
                data["obfuscation_types"] = [
                    t.value if hasattr(t, "value") else str(t)
                    for t in entry.obfuscation_types
                ]
                json.dump(data, f)

        except Exception as e:
            logger.warning(f"Failed to save to disk cache: {e}")

    def _load_from_disk(self, code_hash: str) -> Optional[CacheEntry]:
        """Load entry from disk"""
        try:
            cache_file = self.cache_dir / f"{code_hash}.json"

            if not cache_file.exists():
                return None

            with open(cache_file, "r") as f:
                data = json.load(f)

            return CacheEntry(**data)

        except Exception as e:
            logger.warning(f"Failed to load from disk cache: {e}")
            return None

    def clear(self) -> None:
        """Clear all caches"""
        self.memory_cache.clear()

        # Clear disk cache
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except:
                pass

        logger.info("Cache cleared")

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / total_requests if total_requests > 0 else 0

        # Calculate disk cache size
        disk_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.json"))

        return {
            "memory_entries": len(self.memory_cache),
            "disk_entries": len(list(self.cache_dir.glob("*.json"))),
            "disk_size_mb": disk_size / (1024 * 1024),
            "hits": self.stats["hits"],
            "misses": self.stats["misses"],
            "hit_rate": hit_rate,
            "evictions": self.stats["evictions"],
        }

    def cleanup_old_entries(self, max_age_days: int = 30) -> int:
        """
        Remove old cache entries

        Args:
            max_age_days: Max age in days

        Returns:
            Number of entries removed
        """
        removed = 0
        cutoff = time.time() - (max_age_days * 24 * 60 * 60)

        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, "r") as f:
                    data = json.load(f)

                if data.get("timestamp", 0) < cutoff:
                    cache_file.unlink()
                    removed += 1

            except:
                pass

        logger.info(f"Cleaned up {removed} old cache entries")
        return removed
