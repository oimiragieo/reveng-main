"""angr-based CFG preprocessing for binary recompilation context."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class CFGExtractionError(RuntimeError):
    """Raised when CFG extraction cannot produce a usable payload."""


class AngrCFGPreprocessor:
    """Extract and serialize a structured control-flow graph with angr."""

    def __init__(self, normalize: bool = True):
        self.normalize = normalize

    def extract_cfg_payload(self, binary_path: str) -> Dict[str, Any]:
        """Extract a serialized CFG payload for a binary."""
        try:
            import angr
        except ImportError as exc:  # pragma: no cover - dependency handled by runtime
            raise CFGExtractionError(
                "angr is required for CFG preprocessing. Install with: pip install angr"
            ) from exc

        binary = Path(binary_path)
        if not binary.exists():
            raise CFGExtractionError(f"Binary not found for CFG extraction: {binary}")

        logger.info("Initializing angr project for CFG preprocessing: %s", binary)

        try:
            project = angr.Project(
                str(binary),
                auto_load_libs=False,
                load_options={"auto_load_libs": False},
            )
            cfg = project.analyses.CFGFast(
                normalize=self.normalize,
                data_references=False,
                cross_references=False,
            )
        except Exception as exc:
            raise CFGExtractionError(f"angr CFG extraction failed for {binary}: {exc}") from exc

        functions = [
            self._serialize_function(cfg, function)
            for _, function in sorted(cfg.kb.functions.items(), key=lambda item: item[0])
        ]
        node_count = len(list(cfg.graph.nodes()))
        edge_count = len(list(cfg.graph.edges()))

        if not functions or node_count == 0:
            raise CFGExtractionError(
                f"angr produced an empty CFG payload for {binary.name}"
            )

        payload = {
            "status": "success",
            "source": "angr",
            "binary_path": str(binary.resolve()),
            "binary_name": binary.name,
            "architecture": project.arch.name,
            "entry_point": self._format_address(project.entry),
            "graph_metrics": {
                "node_count": node_count,
                "edge_count": edge_count,
            },
            "function_count": len(functions),
            "functions": functions,
        }

        logger.info(
            "Serialized angr CFG for %s (%d functions, %d nodes, %d edges)",
            binary.name,
            payload["function_count"],
            node_count,
            edge_count,
        )
        return payload

    def build_llm_context(
        self,
        payload: Dict[str, Any],
        max_functions: int = 20,
        max_blocks_per_function: int = 4,
    ) -> str:
        """Build a concise text summary suitable for LLM context windows."""
        if payload.get("status") != "success":
            return "CFG preprocessing failed; no control-flow graph summary is available."

        metrics = payload.get("graph_metrics", {})
        functions = payload.get("functions", [])
        prioritized_functions = sorted(functions, key=self._function_priority)

        lines = [
            f"Binary: {payload.get('binary_name', '<unknown>')}",
            f"Architecture: {payload.get('architecture', '<unknown>')}",
            f"Entry point: {payload.get('entry_point', '<unknown>')}",
            (
                "Graph metrics: "
                f"{metrics.get('node_count', 0)} nodes, "
                f"{metrics.get('edge_count', 0)} edges, "
                f"{payload.get('function_count', 0)} functions"
            ),
        ]

        for function in prioritized_functions[:max_functions]:
            flags = []
            if function.get("is_entrypoint"):
                flags.append("entrypoint")
            if function.get("is_simprocedure"):
                flags.append("simprocedure")
            if function.get("is_plt"):
                flags.append("plt")
            flag_text = f" [{' | '.join(flags)}]" if flags else ""

            lines.append(
                f"Function {function['name']} @ {function['address']}{flag_text}: "
                f"{function['block_count']} basic blocks"
            )

            callees = ", ".join(
                callee["name"] for callee in function.get("callees", [])[:6]
            )
            if callees:
                lines.append(f"  Calls: {callees}")

            callers = ", ".join(
                caller["name"] for caller in function.get("callers", [])[:6]
            )
            if callers:
                lines.append(f"  Called by: {callers}")

            for block in function.get("basic_blocks", [])[:max_blocks_per_function]:
                successors = ", ".join(block.get("successors", [])[:6]) or "<terminal>"
                lines.append(
                    f"  Block {block['address']} (size={block['size']}): successors -> {successors}"
                )

        remaining = max(len(prioritized_functions) - max_functions, 0)
        if remaining:
            lines.append(
                f"... {remaining} additional functions omitted from this summary; refer to cfg_payload.json for the full graph."
            )

        return "\n".join(lines)

    def _serialize_function(self, cfg: Any, function: Any) -> Dict[str, Any]:
        basic_blocks = self._serialize_basic_blocks(function)

        return {
            "name": function.name or self._default_function_name(function.addr),
            "address": self._format_address(function.addr),
            "size": getattr(function, "size", None),
            "is_entrypoint": bool(function.addr == cfg.project.entry),
            "is_simprocedure": bool(getattr(function, "is_simprocedure", False)),
            "is_plt": bool(getattr(function, "is_plt", False)),
            "block_count": len(basic_blocks),
            "callers": self._serialize_related_functions(
                cfg, cfg.kb.callgraph.predecessors(function.addr)
            ),
            "callees": self._serialize_related_functions(
                cfg, cfg.kb.callgraph.successors(function.addr)
            ),
            "basic_blocks": basic_blocks,
        }

    def _serialize_basic_blocks(self, function: Any) -> List[Dict[str, Any]]:
        block_nodes = {}
        for node in function.transition_graph.nodes():
            address = getattr(node, "addr", None)
            size = getattr(node, "size", None)
            if address is None or size is None:
                continue
            block_nodes[address] = node

        serialized_blocks: List[Dict[str, Any]] = []
        for address, node in sorted(block_nodes.items()):
            successors = sorted(
                {
                    self._format_address(successor.addr)
                    for successor in function.transition_graph.successors(node)
                    if getattr(successor, "addr", None) is not None
                }
            )
            predecessors = sorted(
                {
                    self._format_address(predecessor.addr)
                    for predecessor in function.transition_graph.predecessors(node)
                    if getattr(predecessor, "addr", None) is not None
                }
            )
            serialized_blocks.append(
                {
                    "address": self._format_address(address),
                    "size": int(node.size),
                    "successors": successors,
                    "predecessors": predecessors,
                }
            )

        return serialized_blocks

    def _serialize_related_functions(
        self,
        cfg: Any,
        function_addresses: Any,
    ) -> List[Dict[str, str]]:
        related = []
        for address in sorted(function_addresses):
            function = cfg.kb.functions.get(address)
            related.append(
                {
                    "name": (
                        function.name
                        if function is not None and function.name
                        else self._default_function_name(address)
                    ),
                    "address": self._format_address(address),
                }
            )
        return related

    def _function_priority(self, function: Dict[str, Any]) -> tuple[int, int, int, str]:
        name = function.get("name", "")
        is_primary = 0 if name in {"main", "WinMain", "WinMainCRTStartup"} else 1
        is_runtime = 1 if function.get("is_simprocedure") or function.get("is_plt") else 0
        block_penalty = -int(function.get("block_count", 0))
        return (is_primary, is_runtime, block_penalty, name)

    @staticmethod
    def _default_function_name(address: int) -> str:
        return f"sub_{address:x}"

    @staticmethod
    def _format_address(address: int) -> str:
        return hex(int(address))
