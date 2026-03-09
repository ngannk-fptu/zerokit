import json
import logging
import uuid
from typing import List, Optional, Dict, Any
from ..models import AttackSurface, Hypothesis, EntryPointType
from ..llm_gateway import LLMGateway

logger = logging.getLogger(__name__)

class ThreatModeler:
    """
    AI-Powered Threat Modeling Agent.
    Uses LLMGateway to analyze entry points and generate security hypotheses.
    """
    
    def __init__(self, llm_gateway: Optional[LLMGateway] = None):
        self.llm = llm_gateway or LLMGateway()

    async def generate_hypotheses(self, surface: AttackSurface, security_profile: Optional[Any] = None, code_graph: Optional[Dict] = None) -> List[Hypothesis]:
        hypotheses = []
        logger.info(f"Threat Modeling started for {len(surface.entry_points)} entry points")
        
        # Pre-calculate Reachable Sinks from code_graph
        reachable_sinks = []
        if code_graph:
            reachable_sinks = self._get_reachable_sinks(code_graph)
            logger.info(f"  [Semantic] Identified {len(reachable_sinks)} reachable sinks from graph.")

        for ep in surface.entry_points:
            # Skip trivial entry points (simple assets, empty files)
            if self._is_trivial(ep.code_location):
                continue

            try:
                # Prepare summary of code graph for this specific entry point
                graph_summary = "No graph data"
                if code_graph:
                    # Find potential sinks reachable from this EP
                    reachable = [s for s in reachable_sinks if s.get('entry_point') == ep.code_location]
                    if reachable:
                        graph_summary = f"Reachable Sinks: {', '.join([s['name'] for s in reachable])}"
                    else:
                        graph_summary = "No obvious direct paths to sinks found in call graph."

                # Call LLM with enriched context
                # OPTIMIZATION: Only pass the relevant language skill to prevent context explosion
                lang = security_profile.language if security_profile else "Unknown"
                lang_skill_ref = f"@[skills/{lang}-security-patterns]" if lang != "Unknown" else ""
                
                response = self.llm.generate_hypotheses(
                    filename=ep.code_location,
                    function_signature=ep.code_location,
                    route_info=ep.description or "Internal Function",
                    language=lang,
                    security_profile=f"{security_profile.json() if security_profile else '{}'}\nRelevant Patterns: {lang_skill_ref}",
                    code_graph_summary=graph_summary
                )
                
                # Parse JSON Response
                # Clean markdown code blocks if present
                if "```json" in response:
                    response = response.split("```json")[1].split("```")[0].strip()
                elif "```" in response:
                    response = response.split("```")[1].split("```")[0].strip()
                    
                risks = json.loads(response)
                
                for risk in risks:
                    h = Hypothesis(
                        id=str(uuid.uuid4()),
                        description=f"{risk.get('risk', 'Risk')}: {risk.get('reasoning', '')}",
                        target_code=ep.code_location,
                        verification_plan=risk.get('suggested_check', "Standard Verification"),
                        metadata={
                            "priority": risk.get('severity', "MEDIUM"),
                            "original_entry_point_type": ep.category,
                            "llm_reasoning": risk.get('reasoning'),
                            "cwe_id": risk.get('cwe_id', "UNKNOWN"),
                            "trust_boundary": risk.get('trust_boundary', "Unknown"),
                            "source": risk.get('source', "Unknown"),
                            "sink": risk.get('sink', "Unknown")
                        }
                    )
                    hypotheses.append(h)
                    logger.info(f"Generated Hypothesis: {h.description} ({h.metadata['priority']})")
                    
            except Exception as e:
                logger.error(f"Failed to generate hypothesis for {ep.code_location}: {e}")
                # Fallback to Basic Heuristic if LLM fails
                self._fallback_heuristic(ep, hypotheses)
        
        # Sort hypotheses by priority: CRITICAL -> HIGH -> MEDIUM -> LOW
        priority_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        hypotheses.sort(key=lambda h: priority_rank.get(h.metadata.get("priority", "LOW"), 99))
        
        return hypotheses

    def _get_reachable_sinks(self, code_graph: Dict) -> List[Dict]:
        """
        Identify sinks that have a path from identified entry points/sources.
        """
        nodes = code_graph.get("nodes", [])
        edges = code_graph.get("edges", [])
        
        sinks = [n for n in nodes if n.get("type") == "sink"]
        reachable = []
        
        # Build reverse adjacency list (to trace back from sinks)
        from collections import defaultdict
        incoming = defaultdict(list)
        for edge in edges:
            incoming[edge["to"]].append(edge["from"])
            
        def find_entry_point(node_name, visited):
            if node_name in visited: return None
            visited.add(node_name)
            
            # Check if current node is a known entry point (matches profile signature)
            # nodes list might have 'fullName' if it's from Joern
            node = next((n for n in nodes if n["name"] == node_name or n.get("id") == node_name), None)
            if node and node.get("file"): # Simple heuristic: if it's in a file, it might be an entry point
                return node["file"]
            
            for parent in incoming[node_name]:
                res = find_entry_point(parent, visited)
                if res: return res
            return None

        for sink in sinks:
            entry_point = find_entry_point(sink["name"], set())
            if entry_point:
                reachable.append({
                    "name": sink["name"],
                    "entry_point": entry_point,
                    "location": f"{sink.get('file')}:{sink.get('line')}"
                })
                
        return reachable

    def _is_trivial(self, location: str) -> bool:
        """Skip non-code or static assets"""
        ignored_exts = ['.css', '.js.map', '.png', '.jpg', '.svg', '.md', '.txt']
        return any(location.endswith(ext) for ext in ignored_exts)

    def _fallback_heuristic(self, ep, hypotheses_list):
        """Legacy keyword-based fallback"""
        priority = "LOW"
        KEYWORDS = ["admin", "auth", "login", "payment", "upload", "token"]
        content = (ep.code_location + " " + (ep.description or "")).lower()
        
        if ep.category == EntryPointType.HTTP:
            priority = "HIGH"
        if any(k in content for k in KEYWORDS):
            priority = "CRITICAL"
            
        h = Hypothesis(
            id=str(uuid.uuid4()),
            description=f"Fallback Security Check for {ep.category}",
            target_code=ep.code_location,
            verification_plan="Standard Static Scan",
            metadata={"priority": priority, "note": "Generated via Fallback"}
        )
        hypotheses_list.append(h)
