import logging
import json
from typing import List, Dict, Optional, Any
from ..models import StaticFinding, FindingSeverity

logger = logging.getLogger(__name__)

class Explainer:
    """
    Agent responsible for explaining vulnerabilities by tracing paths in the Code Property Graph (CPG).
    """

    def __init__(self, llm_gateway=None):
        self.llm = llm_gateway

    async def explain_finding(self, finding: StaticFinding, code_graph: Dict[str, Any]) -> str:
        """
        Generates a human-readable explanation of the vulnerability path.
        """
        logger.info(f"[Explainer] Explaining finding {finding.id}...")

        # 1. Trace the path in the graph
        trace = self.trace_path(finding, code_graph)
        
        if not trace:
            return "Could not trace the data flow path in the code graph."

        # 2. Store trace in finding
        finding.taint_trace = trace

        # 3. Call LLM to narrate the trace
        if self.llm:
            return await self.llm.explain_vulnerability_path(finding, trace)
        
        return self._format_trace_manually(trace)

    def trace_path(self, finding: StaticFinding, code_graph: Dict[str, Any]) -> List[Dict]:
        """
        Traces a path from the sink (finding location) back to a potential source.
        """
        nodes = code_graph.get("nodes", [])
        edges = code_graph.get("edges", [])
        
        # 1. Find the starting node (Sink)
        # Match based on file and line
        target_file = finding.location.split(":")[0]
        try:
            target_line = int(finding.location.split(":")[1])
        except (IndexError, ValueError):
            target_line = -1

        start_node = None
        for node in nodes:
            if node.get("file") == target_file and node.get("line") == target_line:
                start_node = node
                break
        
        # Fallback: if line match fails, try to find a function containing the location
        if not start_node:
            for node in nodes:
                if node.get("type") == "function" and node.get("file") == target_file:
                    # Very basic check: assuming function covers the line (needs better CPG data)
                    start_node = node
                    break

        if not start_node:
            logger.warning(f"[Explainer] Could not find starting node for {finding.location}")
            return []

        # 2. Simple BFS/DFS to find a path to a "source"
        # Since our graph is currently mostly call edges, we trace call hierarchy
        path = []
        visited = set()
        queue = [(start_node, [start_node])]
        
        while queue:
            current_node, current_path = queue.pop(0)
            if current_node["id"] in visited:
                continue
            visited.add(current_node["id"])

            # Check if this node is a known source
            if self._is_source(current_node):
                return current_path

            # Find incoming edges (who calls this?)
            for edge in edges:
                if edge["to"] == current_node["name"] or edge["to"] == current_node["id"]:
                    # Find the "from" node
                    from_node = next((n for n in nodes if n["id"] == edge["from"]), None)
                    if from_node:
                        queue.append((from_node, current_path + [from_node]))

        # If no source found, return whatever path we found (even if partial)
        return path or [start_node]

    def _is_source(self, node: Dict) -> bool:
        """Determines if a node is a potential user input source."""
        # This should be synchronized with the YAML Adapter sources
        source_indicators = ["HTTP", "Request", "input", "param", "GET", "POST"]
        name = node.get("name", "").upper()
        return any(ind in name for ind in source_indicators)

    def _format_trace_manually(self, trace: List[Dict]) -> str:
        """Fallback manual formatting of the trace."""
        lines = ["Vulnerability Flow:"]
        for i, node in enumerate(reversed(trace)):
            prefix = "Source -> " if i == 0 else "          -> "
            suffix = "(Sink)" if i == len(trace) - 1 else ""
            lines.append(f"{prefix}{node.get('name')} in {node.get('file')}:{node.get('line')} {suffix}")
        return "\n".join(lines)
