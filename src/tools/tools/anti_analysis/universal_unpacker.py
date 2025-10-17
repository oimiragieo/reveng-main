"""
Universal Unpacker for REVENG

Generic unpacking for packed binaries using multiple strategies:
- Specialized unpacking for known packers (UPX, etc.)
- Generic unpacking via memory dumping at OEP
- Heuristic unpacking based on execution patterns
"""

import hashlib
import logging
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .packer_detector import PackerDetector, PackerInfo

logger = logging.getLogger(__name__)


@dataclass
class UnpackResult:
    """Result of unpacking operation"""
    success: bool
    unpacked_path: Optional[str]
    method_used: str
    original_hash: str
    unpacked_hash: Optional[str]
    error_message: Optional[str]
    packer_info: PackerInfo


class UniversalUnpacker:
    """
    Universal unpacker for packed binaries.

    Attempts multiple unpacking strategies:
    1. Known packer unpacking (UPX, MPRESS, etc.)
    2. Generic memory dump unpacking
    3. Heuristic unpacking
    """

    def __init__(self):
        """Initialize universal unpacker"""
        self.detector = PackerDetector()
        logger.info("Universal unpacker initialized")

    def unpack(
        self,
        packed_binary: str,
        output_path: Optional[str] = None,
        method: str = 'auto'
    ) -> UnpackResult:
        """
        Unpack a packed binary.

        Args:
            packed_binary: Path to packed binary
            output_path: Optional path for unpacked binary
            method: Unpacking method ('auto', 'specialized', 'generic')

        Returns:
            UnpackResult with unpacking status
        """
        logger.info(f"Attempting to unpack: {packed_binary}")

        # Detect packer first
        packer_info = self.detector.detect(packed_binary)

        if not packer_info.packed:
            logger.info("Binary does not appear to be packed")
            return UnpackResult(
                success=False,
                unpacked_path=None,
                method_used='none',
                original_hash=self._calculate_hash(packed_binary),
                unpacked_hash=None,
                error_message="Binary is not packed",
                packer_info=packer_info
            )

        # Calculate original hash
        original_hash = self._calculate_hash(packed_binary)

        # Determine output path
        if not output_path:
            packed_path = Path(packed_binary)
            output_path = str(packed_path.parent / f"{packed_path.stem}_unpacked{packed_path.suffix}")

        # Try unpacking methods based on detected packer
        result = None

        if method == 'auto' or method == 'specialized':
            # Try specialized unpacking for known packers
            if packer_info.packer_name:
                result = self._specialized_unpack(
                    packed_binary,
                    output_path,
                    packer_info.packer_name
                )

                if result and result.success:
                    logger.info(f"Successfully unpacked using specialized method for {packer_info.packer_name}")
                    return result

        if (method == 'auto' or method == 'generic') and not (result and result.success):
            # Try generic unpacking
            result = self._generic_unpack(
                packed_binary,
                output_path
            )

            if result and result.success:
                logger.info("Successfully unpacked using generic method")
                return result

        # Unpacking failed
        return UnpackResult(
            success=False,
            unpacked_path=None,
            method_used='none',
            original_hash=original_hash,
            unpacked_hash=None,
            error_message="All unpacking methods failed",
            packer_info=packer_info
        )

    def _specialized_unpack(
        self,
        packed_binary: str,
        output_path: str,
        packer_name: str
    ) -> Optional[UnpackResult]:
        """Specialized unpacking for known packers"""
        logger.info(f"Attempting specialized unpacking for {packer_name}")

        original_hash = self._calculate_hash(packed_binary)

        # UPX unpacking
        if packer_name == 'UPX':
            return self._unpack_upx(packed_binary, output_path, original_hash)

        # MPRESS unpacking
        elif packer_name == 'MPRESS':
            return self._unpack_mpress(packed_binary, output_path, original_hash)

        # Other packers would need specialized tools
        else:
            logger.warning(f"No specialized unpacker available for {packer_name}")
            return None

    def _unpack_upx(
        self,
        packed_binary: str,
        output_path: str,
        original_hash: str
    ) -> UnpackResult:
        """Unpack UPX-packed binary"""
        try:
            # First, copy to output path
            shutil.copy2(packed_binary, output_path)

            # Try to run UPX unpacker
            result = subprocess.run(
                ['upx', '-d', output_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                # Verify unpacked file exists and is different
                if Path(output_path).exists():
                    unpacked_hash = self._calculate_hash(output_path)

                    if unpacked_hash != original_hash:
                        logger.info("UPX unpacking successful")
                        return UnpackResult(
                            success=True,
                            unpacked_path=output_path,
                            method_used='upx',
                            original_hash=original_hash,
                            unpacked_hash=unpacked_hash,
                            error_message=None,
                            packer_info=self.detector.detect(packed_binary)
                        )

            # Unpacking failed
            error_msg = result.stderr if result.stderr else "UPX unpacking failed"
            logger.warning(f"UPX unpacking failed: {error_msg}")

        except FileNotFoundError:
            error_msg = "UPX tool not found. Install with: apt-get install upx-ucl (Linux) or download from upx.github.io"
            logger.warning(error_msg)

        except Exception as e:
            error_msg = f"UPX unpacking error: {e}"
            logger.error(error_msg)

        return UnpackResult(
            success=False,
            unpacked_path=None,
            method_used='upx',
            original_hash=original_hash,
            unpacked_hash=None,
            error_message=error_msg,
            packer_info=self.detector.detect(packed_binary)
        )

    def _unpack_mpress(
        self,
        packed_binary: str,
        output_path: str,
        original_hash: str
    ) -> UnpackResult:
        """Unpack MPRESS-packed binary"""
        # MPRESS unpacking would require specialized tool
        # This is a placeholder for the implementation

        logger.warning("MPRESS unpacking not yet implemented")

        return UnpackResult(
            success=False,
            unpacked_path=None,
            method_used='mpress',
            original_hash=original_hash,
            unpacked_hash=None,
            error_message="MPRESS unpacking not implemented",
            packer_info=self.detector.detect(packed_binary)
        )

    def _generic_unpack(
        self,
        packed_binary: str,
        output_path: str
    ) -> UnpackResult:
        """
        Generic unpacking via memory dumping.

        This would typically involve:
        1. Running binary in controlled environment
        2. Monitoring for OEP (Original Entry Point)
        3. Dumping process memory at OEP
        4. Reconstructing PE file from dump

        For safety and complexity reasons, this is a simplified implementation.
        """
        logger.info("Attempting generic unpacking (memory dump method)")

        original_hash = self._calculate_hash(packed_binary)

        # NOTE: Generic unpacking is complex and requires:
        # - Debugging infrastructure (gdb, WinDbg, etc.)
        # - Ability to detect OEP reliably
        # - Memory dump to PE reconstruction
        # - Proper section alignment and fixing

        # This is a placeholder indicating the approach
        # Real implementation would integrate with debugging tools

        logger.warning(
            "Generic unpacking requires dynamic analysis infrastructure. "
            "Consider using: "
            "\n  1. Manual unpacking with debugger"
            "\n  2. Automated tools like unpac.me"
            "\n  3. Integration with Frida/debugging framework"
        )

        return UnpackResult(
            success=False,
            unpacked_path=None,
            method_used='generic',
            original_hash=original_hash,
            unpacked_hash=None,
            error_message="Generic unpacking requires dynamic analysis (not yet implemented)",
            packer_info=self.detector.detect(packed_binary)
        )

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def batch_unpack(
        self,
        packed_binaries: List[str],
        output_dir: str
    ) -> List[UnpackResult]:
        """
        Unpack multiple binaries.

        Args:
            packed_binaries: List of packed binary paths
            output_dir: Output directory for unpacked binaries

        Returns:
            List of UnpackResult
        """
        results = []
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        logger.info(f"Batch unpacking {len(packed_binaries)} binaries")

        for packed_binary in packed_binaries:
            try:
                binary_name = Path(packed_binary).name
                output_file = output_path / f"unpacked_{binary_name}"

                result = self.unpack(packed_binary, str(output_file))
                results.append(result)

            except Exception as e:
                logger.error(f"Failed to unpack {packed_binary}: {e}")

        success_count = sum(1 for r in results if r.success)
        logger.info(f"Batch unpacking complete: {success_count}/{len(results)} successful")

        return results

    def generate_report(self, result: UnpackResult, format: str = 'text') -> str:
        """Generate unpacking report"""
        if format == 'markdown':
            report = f"# Unpacking Report\n\n"
            report += f"**Status:** {'✅ SUCCESS' if result.success else '❌ FAILED'}\n"
            report += f"**Method:** {result.method_used}\n\n"

            report += f"## Packer Detection\n\n"
            report += f"- **Packed:** {result.packer_info.packed}\n"
            if result.packer_info.packer_name:
                report += f"- **Packer:** {result.packer_info.packer_name}\n"
            report += f"- **Confidence:** {result.packer_info.confidence:.1%}\n"
            report += f"- **Entropy:** {result.packer_info.entropy:.2f}\n\n"

            if result.packer_info.indicators:
                report += f"**Indicators:**\n"
                for indicator in result.packer_info.indicators:
                    report += f"- {indicator}\n"
                report += "\n"

            report += f"## Hashes\n\n"
            report += f"- **Original:** `{result.original_hash}`\n"
            if result.unpacked_hash:
                report += f"- **Unpacked:** `{result.unpacked_hash}`\n"
            report += "\n"

            if result.unpacked_path:
                report += f"**Unpacked File:** `{result.unpacked_path}`\n\n"

            if result.error_message:
                report += f"**Error:** {result.error_message}\n"

        else:  # text format
            report = f"Unpacking Report\n"
            report += f"{'=' * 60}\n\n"
            report += f"Status: {'SUCCESS' if result.success else 'FAILED'}\n"
            report += f"Method: {result.method_used}\n\n"

            report += f"Packer Detection:\n"
            report += f"  Packed: {result.packer_info.packed}\n"
            if result.packer_info.packer_name:
                report += f"  Packer: {result.packer_info.packer_name}\n"
            report += f"  Confidence: {result.packer_info.confidence:.1%}\n"
            report += f"  Entropy: {result.packer_info.entropy:.2f}\n\n"

            if result.packer_info.indicators:
                report += f"Indicators:\n"
                for indicator in result.packer_info.indicators:
                    report += f"  - {indicator}\n"
                report += "\n"

            report += f"Hashes:\n"
            report += f"  Original: {result.original_hash}\n"
            if result.unpacked_hash:
                report += f"  Unpacked: {result.unpacked_hash}\n"
            report += "\n"

            if result.unpacked_path:
                report += f"Unpacked File: {result.unpacked_path}\n\n"

            if result.error_message:
                report += f"Error: {result.error_message}\n"

        return report


# Convenience function
def quick_unpack(packed_binary: str, output_path: Optional[str] = None) -> UnpackResult:
    """Quick unpacking of a packed binary"""
    unpacker = UniversalUnpacker()
    return unpacker.unpack(packed_binary, output_path)
