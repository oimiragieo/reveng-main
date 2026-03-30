# Architecture Notes

This file contains architectural decisions and patterns discovered during the REVENG upgrade mission.

**Pipeline Engine**: Now uses `asyncio.gather` and DAG evaluation to run independent stages concurrently.
**Compiler-in-the-loop**: Uses an iterative feedback loop where `stderr` from gcc/clang is fed back to the LLM agent.
**Forensics**: Uses ML models in `behavioral_monitor.py` instead of static byte matching.
