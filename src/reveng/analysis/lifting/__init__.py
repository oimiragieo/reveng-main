"""
REVENG v4.0 - Binary Lifting to LLVM IR

Cross-architecture binary transformation:
- Dynamic binary lifting to LLVM IR
- LLVM optimization passes for deobfuscation
- Cross-compilation support (x86 <-> ARM <-> MIPS)
- Security hardening without source code
"""

from .llvm_lifter import LiftingResult, LLVMBinaryLifter, SecurityHardeningOptions

__all__ = [
    "LLVMBinaryLifter",
    "LiftingResult",
    "SecurityHardeningOptions",
]
